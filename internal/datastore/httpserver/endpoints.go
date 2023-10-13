package httpserver

import (
	"context"
	"vc/internal/datastore/apiv1"
	apiv1_status "vc/internal/gen/status/apiv1.status"
	"vc/pkg/model"

	"github.com/gin-gonic/gin"
)

func (s *Service) endpointEHICUpload(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1.EHICUploadRequest{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.EHICUpload(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointPDA1Upload(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1.PDA1UploadRequest{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.PDA1Upload(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}
func (s *Service) endpointPDA1Search(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1.PDA1SearchRequest{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.PDA1Search(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointEHICID(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1.EHICIDRequest{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.EHICID(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}
func (s *Service) endpointPDA1ID(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1.PDA1IDRequest{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.PDA1ID(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}
func (s *Service) endpointLadokUpload(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1.LadokUploadRequest{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.LadokUpload(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointLadokID(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1.LadokIDRequest{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.LadokID(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointGenericUpload(ctx context.Context, c *gin.Context) (any, error) {
	request := &model.GenericUpload{}
	if err := s.bindRequest(c, request); err != nil {
		s.logger.Info("endpointGenericUpload", "error", err)
		return nil, err
	}
	reply, err := s.apiv1.GenericUpload(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointGenericList(ctx context.Context, c *gin.Context) (any, error) {
	request := &model.GenericAttributes{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.GenericList(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointGenericDocument(ctx context.Context, c *gin.Context) (any, error) {
	request := &model.GenericAttributes{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.GenericDocument(ctx, request)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *Service) endpointGenericQR(ctx context.Context, c *gin.Context) (any, error) {
	request := &model.GenericAttributes{}
	if err := s.bindRequest(c, request); err != nil {
		return nil, err
	}
	reply, err := s.apiv1.GenericQR(ctx, request)
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
