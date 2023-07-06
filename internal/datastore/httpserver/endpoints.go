package httpserver

import (
	"context"
	"vc/internal/datastore/apiv1"

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

func (s *Service) endpointStatus(ctx context.Context, c *gin.Context) (interface{}, error) {
	reply, err := s.apiv1.Status(ctx)
	if err != nil {
		return nil, err
	}
	return reply, nil
}
