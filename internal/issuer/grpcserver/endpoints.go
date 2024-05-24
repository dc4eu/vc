package grpcserver

import (
	"context"
	apiv1_issuer "vc/internal/gen/issuer/apiv1.issuer"
	"vc/internal/issuer/apiv1"
)

// MakeSDJWT creates an sd-jwt and return it, else error
func (s *Service) MakeSDJWT(ctx context.Context, in *apiv1_issuer.MakeSDJWTRequest) (*apiv1_issuer.MakeSDJWTReply, error) {
	reply, err := s.apiv1.MakeSDJWT(ctx, &apiv1.CreateCredentialRequest{
		AuthenticSource:         in.AuthenticSource,
		AuthenticSourcePersonID: in.AuthenticSourcePersonID,
		DocumentID:              in.DocumentID,
		DocumentType:            in.DocumentType,
		DocumentVersion:         in.DocumentVersion,
		CollectID:               in.CollectID,
		DateOfBirth:             in.DateOfBirth,
		LastName:                in.LastName,
		FirstName:               in.FirstName,
		DocumentData:            in.DocumentData,
	})
	if err != nil {
		return nil, err
	}
	return &apiv1_issuer.MakeSDJWTReply{
		JWT:         reply.Data.JWT,
		Disclosures: reply.Data.Disclosures,
	}, nil
}
