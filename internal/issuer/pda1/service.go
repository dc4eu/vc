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
	cfg *model.Cfg
	log *logger.Log
	//sdJWTClient *gosdjwt.Client
}

// New creates a new instance of the service, or error
func New(ctx context.Context, cfg *model.Cfg, log *logger.Log) (*Service, error) {
	s := &Service{
		log: log,
		cfg: cfg,
	}

	//var err error
	//s.sdJWTClient, err = gosdjwt.New(ctx, gosdjwt.Config{
	//	JWTType: "sd-jwt",
	//})
	//if err != nil {
	//	return nil, err
	//}

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
	ins := gosdjwt.InstructionsV2{
		&gosdjwt.ParentInstructionV2{
			Name: "eidas_type",
			Children: gosdjwt.InstructionsV2{
				&gosdjwt.ChildInstructionV2{
					Name:  "eidas_type",
					Value: "QEAA",
				},
			},
		},
	}

	s.log.Info("Building PDA1 document", "instructions", ins)

	//return s.sdJWTClient.SDJWT(instructions, signingKey)
	return "", nil
}
