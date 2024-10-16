package apiv1

import (
	"context"
	"vc/pkg/ehic"
	"vc/pkg/logger"
	"vc/pkg/sdjwt"
	"vc/pkg/trace"
)

type ehicClient struct {
	log    *logger.Log
	tracer *trace.Tracer
}

func newEHICClient(tracer *trace.Tracer, log *logger.Log) (*ehicClient, error) {
	client := &ehicClient{
		log:    log,
		tracer: tracer,
	}

	return client, nil
}

func (c *ehicClient) sdjwt(ctx context.Context, doc *ehic.Document) sdjwt.InstructionsV2 {
	ctx, span := c.tracer.Start(ctx, "apiv1:ehic:sdjwt")
	defer span.End()

	instruction := sdjwt.InstructionsV2{
		&sdjwt.ParentInstructionV2{
			Name: "cardHolder",
			Children: []any{
				&sdjwt.ChildInstructionV2{
					Name:                "birthDate",
					Value:               doc.CardHolder.BirthDate,
					SelectiveDisclosure: true,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "cardholderStatus",
					Value: doc.CardHolder.CardholderStatus,
				},
				&sdjwt.ChildInstructionV2{
					Name:                "familyName",
					Value:               doc.CardHolder.FamilyName,
					SelectiveDisclosure: true,
				},
				&sdjwt.ChildInstructionV2{
					Name:                "givenName",
					Value:               doc.CardHolder.GivenName,
					SelectiveDisclosure: true,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "id",
					Value: doc.CardHolder.ID,
				},
			},
		},
		&sdjwt.ParentInstructionV2{
			Name: "cardInformation",
			Children: []any{
				&sdjwt.ChildInstructionV2{
					Name:  "expiryDate",
					Value: doc.CardInformation.ExpiryDate,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "id",
					Value: doc.CardInformation.ID,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "invalidSince",
					Value: doc.CardInformation.InvalidSince,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "issuanceDate",
					Value: doc.CardInformation.IssuanceDate,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "validSince",
					Value: doc.CardInformation.ValidSince,
				},
				&sdjwt.ParentInstructionV2{
					Name: "signature",
					Children: []any{
						&sdjwt.ChildInstructionV2{
							Name:  "issuer",
							Value: doc.CardInformation.Signature.Issuer,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "seal",
							Value: doc.CardInformation.Signature.Seal,
						},
					},
				},
			},
		},

		&sdjwt.ParentInstructionV2{
			Name: "competentInstitution",
			Children: []any{
				&sdjwt.ChildInstructionV2{
					Name:  "id",
					Value: doc.CompetentInstitution.ID,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "institutionName",
					Value: doc.CompetentInstitution.InstitutionName,
				},
			},
		},

		&sdjwt.ParentInstructionV2{
			Name: "pid",
			Children: []any{
				&sdjwt.ChildInstructionV2{
					Name:  "exhibitorID",
					Value: doc.PID.ExhibitorID,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "firstName",
					Value: doc.PID.FirstName,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "gender",
					Value: doc.PID.Gender,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "lastName",
					Value: doc.PID.LastName,
				},
				&sdjwt.ChildArrayInstructionV2{
					Name: "pins",
					//Value: []string(doc.PID.PINS),
				},
			},
		},

		&sdjwt.ParentInstructionV2{
			Name: "signature",
			Children: []any{
				&sdjwt.ChildInstructionV2{
					Name:  "issuer",
					Value: doc.Signature.Issuer,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "seal",
					Value: doc.Signature.Seal,
				},
			},
		},
	}

	return instruction
}
