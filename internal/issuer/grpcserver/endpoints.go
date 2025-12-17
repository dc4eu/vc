package grpcserver

import (
	"context"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/internal/issuer/apiv1"
)

// MakeSDJWT creates an sd-jwt and return it, else error
func (s *Service) MakeSDJWT(ctx context.Context, in *apiv1_issuer.MakeSDJWTRequest) (*apiv1_issuer.MakeSDJWTReply, error) {
	reply, err := s.apiv1.MakeSDJWT(ctx, &apiv1.CreateCredentialRequest{
		Scope:        in.Scope,
		DocumentData: in.DocumentData,
		JWK:          in.Jwk,
	})
	if err != nil {
		return nil, err
	}

	return &apiv1_issuer.MakeSDJWTReply{
		Credentials:       reply.Data,
		TokenStatusListSection: reply.TokenStatusListSection,
		TokenStatusListIndex:   reply.TokenStatusListIndex,
	}, nil
}

// JWKS returns the JWKS
func (s *Service) JWKS(ctx context.Context, in *apiv1_issuer.Empty) (*apiv1_issuer.JwksReply, error) {
	reply, err := s.apiv1.JWKS(ctx, in)
	if err != nil {
		return nil, err
	}

	return &apiv1_issuer.JwksReply{
		Issuer: reply.Issuer,
		Jwks:   reply.Jwks,
	}, nil
}
