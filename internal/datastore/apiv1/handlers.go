package apiv1

import (
	"context"
	"vc/pkg/helpers"
	_ "vc/pkg/helpers"
	"vc/pkg/model"
)

// UploadReply is the reply for a generic upload
type UploadReply struct {
	Data struct {
		Status string `json:"status"`
	} `json:"data"`
}

// Upload uploads a document with a set of attributes
//
//	@Summary		Upload
//	@ID				generic-upload
//	@Description	Upload endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	UploadReply				"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		model.Upload			true	" "
//	@Router			/upload [post]
func (c *Client) Upload(ctx context.Context, req *model.Upload) (*UploadReply, error) {
	if err := helpers.Check(ctx, req, c.log); err != nil {
		return nil, err
	}
	if err := c.db.Coll.Save(ctx, req); err != nil {
		return nil, err
	}
	reply := &UploadReply{
		Data: struct {
			Status string `json:"status"`
		}{
			Status: "OK",
		},
	}
	return reply, nil
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
func (c *Client) IDMapping(ctx context.Context, reg *model.MetaData) (*IDMappingReply, error) {
	mapping, err := c.db.Coll.IDMapping(ctx, reg)
	if err != nil {
		return nil, err
	}
	reply := &IDMappingReply{
		Data: struct {
			AuthenticSourcePersonID string `json:"authentic_source_person_id"`
		}{
			AuthenticSourcePersonID: mapping,
		},
	}
	return reply, nil

}

// ListMetadataRequest is the request for ListMetadata
type ListMetadataRequest struct {
	AuthenticSource         string `json:"authentic_source"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id"`
}

// ListMetadataReply is the reply for a document query
type ListMetadataReply struct {
	Data []model.MetaData `json:"data"`
}

// ListMetadata return a list of metadata for a person
//
//	@Summary		ListMetadata
//	@ID				list-metadata
//	@Description	List metadata endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	ListMetadataReply		"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		ListMetadataRequest		true	" "
//	@Router			/metadata [post]
func (c *Client) ListMetadata(ctx context.Context, req *ListMetadataRequest) (*ListMetadataReply, error) {
	query := &model.MetaData{
		AuthenticSource:         req.AuthenticSource,
		AuthenticSourcePersonID: req.AuthenticSourcePersonID,
	}
	docs, err := c.db.Coll.ListMetadata(ctx, query)
	if err != nil {
		return nil, err
	}
	reply := &ListMetadataReply{
		Data: docs,
	}

	return reply, nil
}

// GetDocumentRequest is the request for GetDocument
type GetDocumentRequest struct {
	DocumentID      string `json:"document_id"`
	AuthenticSource string `json:"authentic_source"`
	DocumentType    string `json:"document_type"`
}

// GetDocumentReply is the reply for a generic document
type GetDocumentReply struct {
	Data *model.Upload `json:"data"`
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
	query := &model.MetaData{
		DocumentID:      req.DocumentID,
		DocumentType:    req.DocumentType,
		AuthenticSource: req.AuthenticSource,
	}
	doc, err := c.db.Coll.GetDocument(ctx, query)
	if err != nil {
		return nil, err
	}
	reply := &GetDocumentReply{
		Data: doc,
	}
	return reply, nil
}

// GetDocumentByCollectCode return a specific document by collect code
//
//	@Summary		GetDocumentByCollectCode
//	@ID				get-document-collect-code
//	@Description	Get document by collect code endpoint
//	@Tags			dc4eu
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	GetDocumentReply		"Success"
//	@Failure		400	{object}	helpers.ErrorResponse	"Bad Request"
//	@Param			req	body		model.MetaData			true	" "
//	@Router			/document/collection_code [post]
func (c *Client) GetDocumentByCollectCode(ctx context.Context, req *model.MetaData) (*GetDocumentReply, error) {
	doc, err := c.db.Coll.GetDocumentByCollectCode(ctx, req)
	if err != nil {
		return nil, err
	}

	reply := &GetDocumentReply{
		Data: doc,
	}
	return reply, nil
}

// PortalRequest is the request for PortalData
type PortalRequest struct {
	AuthenticSource         string `json:"authentic_source"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id"`
}

// PortalReply is the reply for PortalData
type PortalReply struct {
	Data []*model.MetaData `json:"data"`
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
	query := &model.MetaData{
		AuthenticSource:         req.AuthenticSource,
		AuthenticSourcePersonID: req.AuthenticSourcePersonID,
	}
	portalData, err := c.db.Coll.PortalData(ctx, query)
	if err != nil {
		return nil, err
	}

	reply := &PortalReply{
		Data: portalData,
	}
	return reply, nil
}
