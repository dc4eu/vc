package apiv1

import (
	"context"
	"time"
	"vc/internal/apigw/db"
	"vc/pkg/helpers"
	"vc/pkg/model"
)

// UploadRequest is the request for Upload
type UploadRequest struct {
	Meta                *model.MetaData        `json:"meta" validate:"required"`
	Identities          []*model.Identity      `json:"identities,omitempty" validate:"required"`
	DocumentDisplay     *model.DocumentDisplay `json:"document_display,omitempty" validate:"required"`
	DocumentData        map[string]any         `json:"document_data" validate:"required"`
	DocumentDataVersion string                 `json:"document_data_version,omitempty" validate:"required,semver"`
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

	qr, err := req.Meta.QRGenerator(ctx, c.cfg.Common.QR.BaseURL, c.cfg.Common.QR.RecoveryLevel, c.cfg.Common.QR.Size)
	if err != nil {
		c.log.Debug("QR code generation failed", "error", err)
		return err
	}

	if req.Meta.Collect.ID == "" {
		req.Meta.Collect.ID = req.Meta.DocumentID
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

	upload := &model.CompleteDocument{
		Meta:                req.Meta,
		DocumentDisplay:     req.DocumentDisplay,
		DocumentData:        req.DocumentData,
		DocumentDataVersion: req.DocumentDataVersion,
		Identities:          req.Identities,
		QR:                  qr,
	}

	_, err = c.simpleQueue.VCPersistentSave.Enqueue(ctx, upload)
	if err != nil {
		c.log.Debug("Failed to enqueue upload document", "error", err)
		return err
	}
	c.log.Debug("Document enqueued for saving", "document_id", req.Meta.DocumentID)
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
	qrCode, err := c.db.VCDatastoreColl.GetQR(ctx, &model.MetaData{
		AuthenticSource: req.AuthenticSource,
		DocumentType:    req.DocumentType,
		DocumentID:      req.DocumentID,
	})
	if err != nil {
		return nil, err
	}

	reply := &NotificationReply{
		Data: qrCode,
	}
	return reply, nil
}

// IDMappingRequest is the request for IDMapping
type IDMappingRequest struct {
	// required: true
	// example: SUNET
	AuthenticSource string          `json:"authentic_source" required:"true"`
	Identity        *model.Identity `json:"identity" validate:"required"`
}

// IDMappingReply is the reply for a IDMapping
type IDMappingReply struct {
	Data *model.IDMapping `json:"data"`
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
	if err := helpers.Check(ctx, c.cfg, reg, c.log); err != nil {
		return nil, err
	}
	authenticSourcePersonID, err := c.db.VCDatastoreColl.IDMapping(ctx, &db.IDMappingQuery{
		AuthenticSource: reg.AuthenticSource,
		Identity:        reg.Identity,
	})
	if err != nil {
		return nil, err
	}

	reply := &IDMappingReply{
		Data: &model.IDMapping{
			AuthenticSourcePersonID: authenticSourcePersonID,
		},
	}

	return reply, nil
}

// AddDocumentIdentityRequest is the request for DocumentIdentity
type AddDocumentIdentityRequest struct {
	// required: true
	// example: SUNET
	AuthenticSource string `json:"authentic_source" required:"true"`

	// required: true
	// example: PDA1
	DocumentType string `json:"document_type" required:"true"`

	// required: true
	// example: 7a00fe1a-3e1a-11ef-9272-fb906803d1b8
	DocumentID string `json:"document_id" required:"true"`

	Identities []*model.Identity `json:"identities" required:"true"`
}

// AddDocumentIdentity adds an identity to a document
//
//	@Summary		AddDocumentIdentity
//	@ID				add-document-identity
//	@Description	Adding identity to document endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200
//	@Failure		400	{object}	helpers.ErrorResponse		"Bad Request"
//	@Param			req	body		AddDocumentIdentityRequest	true	" "
//	@Router			/document/identity [put]
func (c *Client) AddDocumentIdentity(ctx context.Context, req *AddDocumentIdentityRequest) error {
	err := c.db.VCDatastoreColl.AddDocumentIdentity(ctx, &db.AddDocumentIdentityQuery{
		AuthenticSource: req.AuthenticSource,
		DocumentType:    req.DocumentType,
		DocumentID:      req.DocumentID,
		Identities:      req.Identities,
	})
	if err != nil {
		return err
	}

	return nil
}

// DeleteDocumentIdentityRequest is the request for DeleteDocumentIdentity
type DeleteDocumentIdentityRequest struct {
	// required: true
	// example: SUNET
	AuthenticSource string `json:"authentic_source" required:"true"`

	// required: true
	// example: PDA1
	DocumentType string `json:"document_type" required:"true"`

	// required: true
	// example: 7a00fe1a-3e1a-11ef-9272-fb906803d1b8
	DocumentID string `json:"document_id" required:"true"`

	// required: true
	// example: 83c1a3c8-3e1a-11ef-9c01-6b6642c8d638
	AuthenticSourcePersonID string `json:"authentic_source_person_id" required:"true"`
}

// DeleteDocumentIdentity deletes an identity from a document
//
//	@Summary		DeleteDocumentIdentity
//	@ID				delete-document-identity
//	@Description	Delete identity to document endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200
//	@Failure		400	{object}	helpers.ErrorResponse			"Bad Request"
//	@Param			req	body		DeleteDocumentIdentityRequest	true	" "
//	@Router			/document/identity [delete]
func (c *Client) DeleteDocumentIdentity(ctx context.Context, req *DeleteDocumentIdentityRequest) error {
	err := c.db.VCDatastoreColl.DeleteDocumentIdentity(ctx, &db.DeleteDocumentIdentityQuery{
		AuthenticSource:         req.AuthenticSource,
		DocumentType:            req.DocumentType,
		DocumentID:              req.DocumentID,
		AuthenticSourcePersonID: req.AuthenticSourcePersonID,
	})
	if err != nil {
		return err
	}

	return nil
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
	if err := helpers.Check(ctx, c.cfg, req, c.log); err != nil {
		return err
	}

	_, err := c.simpleQueue.VCPersistentDelete.Enqueue(ctx, req)
	if err != nil {
		return err
	}

	return nil
}

// GetDocumentRequest is the request for GetDocument
type GetDocumentRequest struct {
	AuthenticSource string `json:"authentic_source" validate:"required"`
	DocumentType    string `json:"document_type" validate:"required"`
	DocumentID      string `json:"document_id" validate:"required"`
}

// GetDocumentReply is the reply for a generic document
type GetDocumentReply struct {
	Data *model.Document `json:"data"`
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

	query := &db.GetDocumentQuery{
		Meta: &model.MetaData{
			AuthenticSource: req.AuthenticSource,
			DocumentType:    req.DocumentType,
			DocumentID:      req.DocumentID,
		},
	}
	doc, err := c.db.VCDatastoreColl.GetDocument(ctx, query)
	if err != nil {
		return nil, err
	}
	reply := &GetDocumentReply{
		Data: &model.Document{
			Meta:         &model.MetaData{},
			DocumentData: doc,
		},
	}

	return reply, nil
}

// DocumentListRequest is the request for DocumentList
type DocumentListRequest struct {
	AuthenticSource string          `json:"authentic_source" validate:"required"`
	Identity        *model.Identity `json:"identity" validate:"required"`
	DocumentType    string          `json:"document_type" validate:"required"`
	ValidFrom       int64           `json:"valid_from"`
	ValidTo         int64           `json:"valid_to"`
}

// DocumentListReply is the reply for a list of documents
type DocumentListReply struct {
	Data []model.DocumentList `json:"data"`
}

// DocumentList return a list of metadata for a specific identity
func (c *Client) DocumentList(ctx context.Context, req *DocumentListRequest) (*DocumentListReply, error) {
	return nil, nil
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
	Data *model.Document `json:"data"`
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
		Identity: req.Identity,
		Meta: &model.MetaData{
			AuthenticSource: req.AuthenticSource,
			DocumentType:    req.DocumentType,
			Collect: &model.Collect{
				ID: req.CollectID,
			},
		},
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
	Data []model.CompleteDocument `json:"data"`
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

// AddConsentRequest is the request for AddConsent
type AddConsentRequest struct {
	AuthenticSource         string `json:"authentic_source" validate:"required"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id" validate:"required"`
	ConsentTo               string `json:"consent_to"`
	SessionID               string `json:"session_id"`
}

// AddConsent adds a consent to a document
func (c *Client) AddConsent(ctx context.Context, req *AddConsentRequest) error {
	err := c.db.VCConsentColl.Add(ctx, &db.AddConsentQuery{
		AuthenticSource:         req.AuthenticSource,
		AuthenticSourcePersonID: req.AuthenticSourcePersonID,
		Consent: &model.Consent{
			ConsentTo: req.ConsentTo,
			SessionID: req.SessionID,
			CreatedAt: time.Now().Unix(),
		},
	})
	if err != nil {
		return err
	}

	return nil
}

// GetConsentRequest is the request for GetConsent
type GetConsentRequest struct {
	AuthenticSource         string `json:"authentic_source" validate:"required"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id" validate:"required"`
}

// GetConsent gets a consent for a document
func (c *Client) GetConsent(ctx context.Context, req *GetConsentRequest) (*model.Consent, error) {
	res, err := c.db.VCConsentColl.Get(ctx, &db.GetConsentQuery{
		AuthenticSource:         req.AuthenticSource,
		AuthenticSourcePersonID: req.AuthenticSourcePersonID,
	})
	if err != nil {
		return nil, err
	}

	return res, nil
}
