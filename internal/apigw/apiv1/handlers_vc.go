package apiv1

import (
	"context"
	"encoding/json"
	"time"
	"vc/internal/apigw/db"
	"vc/pkg/helpers"
	"vc/pkg/model"
	"vc/pkg/topicnames"

	"github.com/segmentio/kafka-go/protocol"
	"go.opentelemetry.io/otel/codes"
)

// UploadRequest is the request for Upload
type UploadRequest struct {
	Meta         *model.MetaData    `json:"meta" validate:"required"`
	Identity     *model.Identity    `json:"identity,omitempty" validate:"required"`
	Attestation  *model.Attestation `json:"attestation,omitempty" validate:"required"`
	DocumentData map[string]any     `json:"document_data" validate:"required"`
}

// Upload uploads a document with a set of attributes
//
//	@Summary		Upload
//	@ID				generic-upload
//	@Description	Upload endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		UploadRequest			true	" "
//	@Router			/upload [post]
func (c *Client) Upload(ctx context.Context, req *UploadRequest) error {
	if err := helpers.Check(ctx, c.cfg, req, c.log); err != nil {
		c.log.Debug("Validation failed", "error", err)
		return err
	}

	ctx, span := c.tp.Start(ctx, "apiv1:Upload")
	defer span.End()

	qr, err := req.Meta.QRGenerator(ctx, c.cfg.Common.QR.BaseURL, c.cfg.Common.QR.RecoveryLevel, c.cfg.Common.QR.Size)
	if err != nil {
		c.log.Debug("QR code generation failed", "error", err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	if req.Meta.CollectID == "" {
		req.Meta.CollectID = req.Meta.DocumentID
	}

	if req.Meta.Revocation == nil {
		req.Meta.Revocation = &model.Revocation{
			ID: req.Meta.DocumentID,
		}
	} else {
		if req.Meta.Revocation.ID == "" {
			req.Meta.Revocation.ID = req.Meta.DocumentID
		}
	}

	req.Meta.CreatedAt = time.Now().Unix()

	upload := &model.Upload{
		Meta:         req.Meta,
		Identity:     req.Identity,
		Attestation:  req.Attestation,
		DocumentData: req.DocumentData,
		QR:           qr,
	}

	_, err = c.simpleQueue.VCPersistentSave.Enqueue(ctx, upload)
	if err != nil {
		c.log.Debug("Failed to enqueue upload document", "error", err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	c.log.Debug("Document enqueued for saving", "document_id", req.Meta.DocumentID)

	data, err := json.Marshal(req)
	if err != nil {
		c.log.Error(err, "failed to marshal request")
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	if err := c.queue.Enqueue(ctx, topicnames.QueuingVCSaveDocumentV0, req.Meta.DocumentID, data, []protocol.Header{}); err != nil {
		c.log.Error(err, "failed to write message to kafka")
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// NotificationRequest is the request for Notification
type NotificationRequest struct {
	AuthenticSource string `json:"authentic_source" required:"true"`
	DocumentType    string `json:"document_type" required:"true"`
	DocumentID      string `json:"document_id" required:"true"`
}

// NotificationReply is the reply for a Notification
type NotificationReply struct {
	Data *model.QR `json:"data"`
}

// Notification return QR code and DeepLink for a document
//
//	@Summary		Notification
//	@ID				generic-notification
//	@Description	notification endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	NotificationReply		"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		NotificationRequest		true	" "
//	@Router			/notification [post]
func (c *Client) Notification(ctx context.Context, req *NotificationRequest) (*NotificationReply, error) {
	ctx, span := c.tp.Start(ctx, "apiv1:Notification")
	defer span.End()

	qrCode, err := c.db.VCDatastoreColl.GetQR(ctx, &model.MetaData{
		AuthenticSource: req.AuthenticSource,
		DocumentType:    req.DocumentType,
		DocumentID:      req.DocumentID,
	})
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	reply := &NotificationReply{
		Data: qrCode,
	}
	return reply, nil
}

// IDMappingRequest is the request for IDMapping
type IDMappingRequest struct {
	AuthenticSource string          `json:"authentic_source" validate:"required"`
	Identity        *model.Identity `json:"identity" validate:"required"`
}

// IDMappingReply is the reply for a IDMapping
type IDMappingReply struct {
	Data struct {
		AuthenticSourcePersonID string `json:"authentic_source_person_id"`
	} `json:"data"`
}

// IDMapping return a mapping between PID and AuthenticSource
//
//	@Summary		IDMapping
//	@ID				id-mapping
//	@Description	ID mapping endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	IDMappingReply			"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		model.MetaData			true	" "
//	@Router			/id_mapping [post]
func (c *Client) IDMapping(ctx context.Context, reg *IDMappingRequest) (*IDMappingReply, error) {
	ctx, span := c.tp.Start(ctx, "apiv1:IDMapping")
	defer span.End()

	if err := helpers.Check(ctx, c.cfg, reg, c.log); err != nil {
		return nil, err
	}
	authenticSourcePersonID, err := c.db.VCDatastoreColl.IDMapping(ctx, &db.IDMappingQuery{
		AuthenticSource: reg.AuthenticSource,
		Identity:        reg.Identity,
	})
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply := &IDMappingReply{
		Data: struct {
			AuthenticSourcePersonID string `json:"authentic_source_person_id"`
		}{
			AuthenticSourcePersonID: authenticSourcePersonID,
		},
	}
	return reply, nil

}

// GetDocumentRequest is the request for GetDocument
type GetDocumentRequest struct {
	AuthenticSource string `json:"authentic_source" validate:"required"`
	DocumentType    string `json:"document_type" validate:"required"`
	DocumentID      string `json:"document_id" validate:"required"`
}

// GetDocumentReply is the reply for a generic document
type GetDocumentReply struct {
	Data struct {
		Meta         *model.MetaData `json:"meta"`
		DocumentData any             `json:"document_data"`
	} `json:"data"`
}

// GetDocument return a specific document
//
//	@Summary		GetDocument
//	@ID				get-document
//	@Description	Get document endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	GetDocumentReply		"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		GetDocumentRequest		true	" "
//	@Router			/document [post]
func (c *Client) GetDocument(ctx context.Context, req *GetDocumentRequest) (*GetDocumentReply, error) {
	if err := helpers.Check(ctx, c.cfg, req, c.log); err != nil {
		return nil, err
	}

	ctx, span := c.tp.Start(ctx, "apiv1:GetDocument")
	defer span.End()

	query := &model.MetaData{
		DocumentID:      req.DocumentID,
		DocumentType:    req.DocumentType,
		AuthenticSource: req.AuthenticSource,
	}
	doc, err := c.db.VCDatastoreColl.GetDocument(ctx, query)
	if err != nil {
		return nil, err
	}
	reply := &GetDocumentReply{
		Data: struct {
			Meta         *model.MetaData `json:"meta"`
			DocumentData any             `json:"document_data"`
		}{
			Meta:         doc.Meta,
			DocumentData: doc.DocumentData,
		},
	}

	return reply, nil
}

// DeleteDocumentRequest is the request for DeleteDocument
type DeleteDocumentRequest struct {
	// required: true
	// example: skatteverket
	AuthenticSource string `json:"authentic_source" required:"true"`

	// required: true
	// example: 5e7a981c-c03f-11ee-b116-9b12c59362b9
	DocumentID string `json:"document_id" required:"true"`
}

// DeleteDocument deletes a specific document
//
//	@Summary		DeleteDocument
//	@ID				delete-document
//	@Description	delete one document endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		DeleteDocumentRequest	true	" "
//	@Router			/document [delete]
func (c *Client) DeleteDocument(ctx context.Context, req *DeleteDocumentRequest) error {
	ctx, span := c.tp.Start(ctx, "apiv1:DeleteDocument")
	defer span.End()

	if err := helpers.Check(ctx, c.cfg, req, c.log); err != nil {
		return err
	}

	_, err := c.simpleQueue.VCPersistentDelete.Enqueue(ctx, req)
	if err != nil {
		return err
	}

	return nil
}

// GetDocumentCollectIDRequest is the request for GetDocumentAttestation
type GetDocumentCollectIDRequest struct {
	AuthenticSource string          `json:"authentic_source" validate:"required"`
	DocumentType    string          `json:"document_type" validate:"required"`
	CollectID       string          `json:"collect_id" validate:"required"`
	Identity        *model.Identity `json:"identity" validate:"required"`
}

// GetDocumentCollectIDReply is the reply for a generic document
type GetDocumentCollectIDReply struct {
	Data *model.Upload `json:"data"`
}

// GetDocumentCollectID return a specific document ??
//
//	@Summary		GetDocumentByCollectID
//	@ID				get-document-collect-id
//	@Description	Get document by collect code endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	GetDocumentCollectIDReply	"Success"
//	@Failure		400	{object}	helpers.ErrorResponse		"Bad Request"
//	@Param			req	body		GetDocumentCollectIDRequest	true	" "
//	@Router			/document/collect_id [post]
func (c *Client) GetDocumentCollectID(ctx context.Context, req *GetDocumentCollectIDRequest) (*GetDocumentCollectIDReply, error) {
	if err := helpers.Check(ctx, c.cfg, req, c.log); err != nil {
		return nil, err
	}

	query := &db.GetDocumentCollectIDQuery{
		AuthenticSource: req.AuthenticSource,
		DocumentType:    req.DocumentType,
		CollectID:       req.CollectID,
		Identity:        req.Identity,
	}

	doc, err := c.db.VCDatastoreColl.GetDocumentCollectID(ctx, query)
	if err != nil {
		return nil, err
	}

	reply := &GetDocumentCollectIDReply{
		Data: doc,
	}
	return reply, nil
}

// RevokeDocumentRequest is the request for RevokeDocument
type RevokeDocumentRequest struct {
	AuthenticSource string            `json:"authentic_source" validate:"required"`
	DocumentType    string            `json:"document_type" validate:"required"`
	Revocation      *model.Revocation `json:"revocation" validate:"required"`
}

// RevokeDocument revokes a specific document
//
//	@Summary		RevokeDocument
//	@ID				revoke-document
//	@Description	Revoke one document
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		RevokeDocumentRequest	true	" "
//	@Router			/document/revoke [post]
func (c *Client) RevokeDocument(ctx context.Context, req *RevokeDocumentRequest) error {
	c.log.Debug("Revoke request", "request", req)
	if err := helpers.Check(ctx, c.cfg, req, c.log); err != nil {
		return err
	}

	if req.Revocation.ID == "" {
		return helpers.NewError("missing meta.revocation.id")
	}

	doc, err := c.db.VCDatastoreColl.GetByRevocationID(ctx, &model.MetaData{
		AuthenticSource: req.AuthenticSource,
		DocumentType:    req.DocumentType,
		Revocation:      &model.Revocation{ID: req.Revocation.ID},
	})
	if err != nil {
		return err
	}
	c.log.Debug("Document found", "document_id", doc.Meta.DocumentID)

	doc.Meta.Revocation = req.Revocation

	if req.Revocation.RevokedAt == 0 {
		doc.Meta.Revocation.RevokedAt = time.Now().Unix()
		doc.Meta.Revocation.Revoked = true
	}

	c.log.Debug("Add revocation to document", "document_id", doc.Meta.DocumentID)

	_, err = c.simpleQueue.VCPersistentReplace.Enqueue(ctx, doc)
	if err != nil {
		return err
	}
	c.log.Debug("Document enqueued for update", "document_id", doc.Meta.DocumentID)

	return nil
}

// PortalRequest is the request for PortalData
type PortalRequest struct {
	AuthenticSource         string `json:"authentic_source" validate:"required"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id" validate:"required"`
	DocumentType            string `json:"document_type"`
	ValidFrom               int64  `json:"valid_from"`
	ValidTo                 int64  `json:"valid_to"`
}

// PortalReply is the reply for PortalData
type PortalReply struct {
	Data []model.Upload `json:"data"`
}

// Portal return a list of metadata for a specific person
//
//	@Summary		Portal
//	@ID				portal
//	@Description	Get portal data endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	PortalReply				"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		PortalRequest			true	" "
//	@Router			/portal [post]
func (c *Client) Portal(ctx context.Context, req *PortalRequest) (*PortalReply, error) {
	ctx, span := c.tp.Start(ctx, "apiv1:Portal")
	defer span.End()

	if err := helpers.Check(ctx, c.cfg, req, c.log); err != nil {
		return nil, err
	}

	query := &db.PortalQuery{
		AuthenticSource:         req.AuthenticSource,
		AuthenticSourcePersonID: req.AuthenticSourcePersonID,
		DocumentType:            req.DocumentType,
		ValidTo:                 req.ValidTo,
		ValidFrom:               req.ValidFrom,
	}
	portalData, err := c.db.VCDatastoreColl.PortalData(ctx, query)
	if err != nil {
		return nil, err
	}

	reply := &PortalReply{
		Data: portalData,
	}
	return reply, nil
}
