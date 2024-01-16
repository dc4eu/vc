package pda1

import (
	"context"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/pda1"

	"github.com/masv3971/gosdjwt"
)

// Service holds PDA1 service object
type Service struct {
	cfg         *model.Cfg
	log         *logger.Log
	sdJWTClient *gosdjwt.Client
}

// New creates a new instance of the service, or error
func New(ctx context.Context, cfg *model.Cfg, log *logger.Log) (*Service, error) {
	s := &Service{
		log: log,
		cfg: cfg,
	}

	var err error
	s.sdJWTClient, err = gosdjwt.New(ctx, gosdjwt.Config{
		JWTType: "sd-jwt",
	})
	if err != nil {
		return nil, err
	}

	s.log.Info("Started")

	return s, nil
}

// Close closes the service
func (s *Service) Close(ctx context.Context) error {
	ctx.Done()
	return nil
}

// Build builds a PDA1 document
func (s *Service) Build(document *pda1.Document, signingKey string) (string, error) {
	instructions := gosdjwt.Instructions{
		{
			Name:  "eidas_type",
			Value: "QEAA",
		},
		{
			Name:  "iss",
			Value: "http://example.social-security/QTSP/12345",
		},
		{
			Name:  "authentic_source",
			Value: "http://example.social-security/issuers/565049",
		},
		{
			Name:  "given_name",
			Value: "x",
		},
		{
			Name:  "family_name",
			Value: "x",
		},
		{
			Name:  "date_of_birth",
			Value: "x",
		},
		{
			Name:  "uid_pid",
			Value: "x",
		},
		{
			Name: "credentialSchema",
			Children: gosdjwt.Instructions{
				{
					Name:  "id",
					Value: "http://example.social-security/schema/PDA1.json",
				},
				{
					Name:  "type",
					Value: "JsonSchema2023",
				},
			},
		},
		{
			Name:  "iat",
			Value: "x",
		},
		{
			Name:  "exp",
			Value: "x",
		},
		{
			Name:  "nbf",
			Value: "x",
		},
		{
			Name:  "sub",
			Value: "did:example:subjectDID",
		},
		{
			Name:  "proofValue",
			Value: "x",
		},
		{
			Name:  "verificationMethod",
			Value: "http://example.social-security/QTSP/12345#keys-1",
		},
		{
			Name: "credentialStatus",
			Children: gosdjwt.Instructions{
				{
					Name:  "id",
					Value: "https://example.social-security/credentials/statuslists/3#94567",
				},
				{
					Name:  "type",
					Value: "StatusList2021Entry",
				},
				{
					Name:  "statusPurpose",
					Value: "statusPurpose",
				},
				{
					Name:  "statusListIndex",
					Value: "94567",
				},
				{
					Name:  "statusListCredential",
					Value: "https://example.social-security/credentials/statuslists/3",
				},
			},
		},
		{
			Name:  "document",
			Value: document,
			SD:    true,
		},
	}

	s.log.Info("Building PDA1 document", "instructions", instructions)

	//return s.sdJWTClient.SDJWT(instructions, signingKey)
	return "", nil
}
