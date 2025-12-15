package grpcserver

import (
	"context"

	"vc/internal/gen/registry/apiv1_registry"
	"vc/internal/registry/apiv1"
)

// TSLAddStatus adds a new status entry to the Token Status List
func (s *Service) TSLAddStatus(ctx context.Context, req *apiv1_registry.TSLAddStatusRequest) (*apiv1_registry.TSLAddStatusReply, error) {
	section, index, err := s.tslIssuer.AddStatus(ctx, uint8(req.Status))
	if err != nil {
		return nil, err
	}

	reply := &apiv1_registry.TSLAddStatusReply{
		Section: section,
		Index:   index,
	}

	return reply, nil
}

// TSLUpdateStatus updates an existing status entry in the Token Status List
func (s *Service) TSLUpdateStatus(ctx context.Context, req *apiv1_registry.TSLUpdateStatusRequest) (*apiv1_registry.TSLUpdateStatusReply, error) {
	err := s.tslIssuer.UpdateStatus(ctx, req.Section, req.Index, uint8(req.Status))
	if err != nil {
		return nil, err
	}

	return &apiv1_registry.TSLUpdateStatusReply{}, nil
}

// SaveCredentialSubject saves credential subject info linked to a TSL entry
func (s *Service) SaveCredentialSubject(ctx context.Context, req *apiv1_registry.SaveCredentialSubjectRequest) (*apiv1_registry.SaveCredentialSubjectReply, error) {
	err := s.apiv1.SaveCredentialSubject(ctx, &apiv1.SaveCredentialSubjectRequest{
		FirstName:   req.FirstName,
		LastName:    req.LastName,
		DateOfBirth: req.DateOfBirth,
		Section:     req.Section,
		Index:       req.Index,
	})
	if err != nil {
		return nil, err
	}

	return &apiv1_registry.SaveCredentialSubjectReply{}, nil
}