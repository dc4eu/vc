package apiv1

import (
	"context"
	"vc/pkg/ehic"

	"github.com/golang-jwt/jwt/v5"
	"github.com/masv3971/gosdjwt"
)

type ehicClient struct {
}

func newEHICClient() (*ehicClient, error) {
	return &ehicClient{}, nil
}

func (c *ehicClient) sdjwt(ctx context.Context, doc *ehic.Document) (*gosdjwt.SDJWT, error) {
	ins := gosdjwt.InstructionsV2{
		&gosdjwt.ParentInstructionV2{
			Name: "cardHolder",
			Children: []any{
				&gosdjwt.ChildInstructionV2{
					Name:                "birthDate",
					Value:               doc.CardHolder.BirthDate,
					SelectiveDisclosure: true,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "cardholderStatus",
					Value: doc.CardHolder.CardholderStatus,
				},
				&gosdjwt.ChildInstructionV2{
					Name:                "familyName",
					Value:               doc.CardHolder.FamilyName,
					SelectiveDisclosure: true,
				},
				&gosdjwt.ChildInstructionV2{
					Name:                "givenName",
					Value:               doc.CardHolder.GivenName,
					SelectiveDisclosure: true,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "id",
					Value: doc.CardHolder.ID,
				},
			},
		},
		&gosdjwt.ParentInstructionV2{
			Name: "cardInformation",
			Children: []any{
				&gosdjwt.ChildInstructionV2{
					Name:  "expiryDate",
					Value: doc.CardInformation.ExpiryDate,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "id",
					Value: doc.CardInformation.ID,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "invalidSince",
					Value: doc.CardInformation.InvalidSince,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "issuanceDate",
					Value: doc.CardInformation.IssuanceDate,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "validSince",
					Value: doc.CardInformation.ValidSince,
				},
				&gosdjwt.ParentInstructionV2{
					Name: "signature",
					Children: []any{
						&gosdjwt.ChildInstructionV2{
							Name:  "issuer",
							Value: doc.CardInformation.Signature.Issuer,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "seal",
							Value: doc.CardInformation.Signature.Seal,
						},
					},
				},
			},
		},

		&gosdjwt.ParentInstructionV2{
			Name: "competentInstitution",
			Children: []any{
				&gosdjwt.ChildInstructionV2{
					Name:  "id",
					Value: doc.CompetentInstitution.ID,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "institutionName",
					Value: doc.CompetentInstitution.InstitutionName,
				},
			},
		},

		&gosdjwt.ParentInstructionV2{
			Name: "pid",
			Children: []any{
				&gosdjwt.ChildInstructionV2{
					Name:  "exhibitorID",
					Value: doc.PID.ExhibitorID,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "firstName",
					Value: doc.PID.FirstName,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "gender",
					Value: doc.PID.Gender,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "lastName",
					Value: doc.PID.LastName,
				},
				&gosdjwt.ChildArrayInstructionV2{
					Name: "pins",
					//Value: []string(doc.PID.PINS),
				},
			},
		},

		&gosdjwt.ParentInstructionV2{
			Name: "signature",
			Children: []any{
				&gosdjwt.ChildInstructionV2{
					Name:  "issuer",
					Value: doc.Signature.Issuer,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "seal",
					Value: doc.Signature.Seal,
				},
			},
		},
	}

	cred, err := ins.SDJWT(jwt.SigningMethodHS256, "key")
	if err != nil {
		return nil, err
	}

	return cred, nil
}
