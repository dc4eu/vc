package httpserver

import (
	"context"
	"vc/internal/datastore/apiv1"
	apiv1_status "vc/internal/gen/status/apiv1.status"
	"vc/pkg/model"

	"github.com/gin-gonic/gin"
)

func (s *Service) endpointUpload(ctx context.Context, c *gin.Context) (any, error) {
	request := &model.Upload{}
	if err := s.bindRequest(c, request); err != nil {
		s.logger.Info("endpointGenericUpload", "error", err)
		return nil, err
	}
	reply, err := s.apiv1.Upload(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointIDMapping(ctx context.Context, c *gin.Context) (any, error) {
	request := &model.MetaData{}
	if err := s.bindRequest(c, request); err != nil {
		s.logger.Info("endpointGenericUpload", "error", err)
		return nil, err
	}
	reply, err := s.apiv1.IDMapping(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointGetDocument(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1.GetDocumentRequest{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.GetDocument(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointGetDocumentByCollectionCode(ctx context.Context, c *gin.Context) (any, error) {
	request := &model.MetaData{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.GetDocumentByCollectionCode(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointListMetadata(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1.ListMetadataRequest{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.ListMetadata(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}
func (s *Service) endpointPortal(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1.PortalRequest{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.Portal(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointStatus(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1_status.StatusRequest{}
	reply, err := s.apiv1.Status(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}
