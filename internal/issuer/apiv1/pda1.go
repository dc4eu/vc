package apiv1

import (
	"context"
	"vc/pkg/logger"
	"vc/pkg/pda1"

	"github.com/golang-jwt/jwt/v5"
	"github.com/masv3971/gosdjwt"
)

type pda1Client struct {
	log *logger.Log
}

func newPDA1Client(log *logger.Log) (*pda1Client, error) {
	client := &pda1Client{
		log: log,
	}

	return client, nil
}

func (c *pda1Client) sdjwt(ctx context.Context, doc *pda1.Document) (*gosdjwt.SDJWT, error) {
	ins := gosdjwt.InstructionsV2{
		&gosdjwt.ParentInstructionV2{
			Name: "activityEmploymentDetails",
			Children: []any{
				&gosdjwt.ChildInstructionV2{
					Name:  "noFixedAddress",
					Value: doc.ActivityEmploymentDetails.NoFixedAddress,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "noFixedAddressDescription",
					Value: doc.ActivityEmploymentDetails.NoFixedAddressDescription,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "workPlaceAddresses",
					Value: doc.ActivityEmploymentDetails.WorkPlaceAddresses,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "workPlaceAddressesBlob",
					Value: doc.ActivityEmploymentDetails.WorkPlaceAddressesBlob,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "workPlaceNames",
					Value: doc.ActivityEmploymentDetails.WorkPlaceNames,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "workPlaceNamesBlob",
					Value: doc.ActivityEmploymentDetails.WorkPlaceNamesBlob,
				},
			},
		},
		&gosdjwt.ParentInstructionV2{
			Name: "completingInstitution",
			Children: []any{
				&gosdjwt.ChildInstructionV2{
					Name:  "date",
					Value: doc.CompletingInstitution.Date,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "email",
					Value: doc.CompletingInstitution.Email,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "institutionID",
					Value: doc.CompletingInstitution.InstitutionID,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "name",
					Value: doc.CompletingInstitution.Name,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "officeFaxNo",
					Value: doc.CompletingInstitution.OfficeFaxNo,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "signature",
					Value: doc.CompletingInstitution.Signature,
				},
				&gosdjwt.ParentInstructionV2{
					Name:                "address",
					SelectiveDisclosure: true,
					Children: []any{
						&gosdjwt.ChildInstructionV2{
							Name:  "buildingName",
							Value: doc.CompletingInstitution.Address.BuildingName,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "countryCode",
							Value: doc.CompletingInstitution.Address.CountryCode,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "postCode",
							Value: doc.CompletingInstitution.Address.PostCode,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "region",
							Value: doc.CompletingInstitution.Address.Region,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "streetNo",
							Value: doc.CompletingInstitution.Address.StreetNo,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "town",
							Value: doc.CompletingInstitution.Address.Town,
						},
					},
				},
			},
		},
		&gosdjwt.ParentInstructionV2{
			Name: "employmentDetails",
			Children: []any{
				&gosdjwt.ChildInstructionV2{
					Name:  "employee",
					Value: doc.EmploymentDetails.Employee,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "employerSelfEmployedActivityCodes",
					Value: doc.EmploymentDetails.EmployerSelfEmployedActivityCodes,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "nameBusinessName",
					Value: doc.EmploymentDetails.NameBusinessName,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "registeredAddress",
					Value: doc.EmploymentDetails.RegisteredAddress,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "selfEmployedActivity",
					Value: doc.EmploymentDetails.SelfEmployedActivity,
				},
				&gosdjwt.ParentInstructionV2{
					Name: "registeredAddress",
					Children: []any{
						&gosdjwt.ChildInstructionV2{
							Name:  "buildingName",
							Value: doc.EmploymentDetails.RegisteredAddress.BuildingName,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "countryCode",
							Value: doc.EmploymentDetails.RegisteredAddress.CountryCode,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "postCode",
							Value: doc.EmploymentDetails.RegisteredAddress.PostCode,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "region",
							Value: doc.EmploymentDetails.RegisteredAddress.Region,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "streetNo",
							Value: doc.EmploymentDetails.RegisteredAddress.StreetNo,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "town",
							Value: doc.EmploymentDetails.RegisteredAddress.Town,
						},
					},
				},
			},
		},
		&gosdjwt.ParentInstructionV2{
			Name: "memberStateLegislation",
			Children: []any{
				&gosdjwt.ChildInstructionV2{
					Name:  "certificateForDurationActivity",
					Value: doc.MemberStateLegislation.CertificateForDurationActivity,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "determinationProvisional",
					Value: doc.MemberStateLegislation.DeterminationProvisional,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "endingDate",
					Value: doc.MemberStateLegislation.EndingDate,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "memberStateWhichLegislationApplies",
					Value: doc.MemberStateLegislation.MemberStateWhichLegislationApplies,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "startingDate",
					Value: doc.MemberStateLegislation.StartingDate,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "transitionRulesApplyAsEC8832004",
					Value: doc.MemberStateLegislation.TransitionRulesApplyAsEC8832004,
				},
			},
		},
		&gosdjwt.ParentInstructionV2{
			Name: "personalDetails",
			Children: []any{
				&gosdjwt.ChildInstructionV2{
					Name:                "dateBirth",
					SelectiveDisclosure: true,
					Value:               doc.PersonalDetails.DateBirth,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "forenames",
					Value: doc.PersonalDetails.Forenames,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "nationality",
					Value: doc.PersonalDetails.Nationality,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "personalIdentificationNumber",
					Value: doc.PersonalDetails.PersonalIdentificationNumber,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "sex",
					Value: doc.PersonalDetails.Sex,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "surname",
					Value: doc.PersonalDetails.Surname,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "surnameAtBirth",
					Value: doc.PersonalDetails.SurnameAtBirth,
				},
				&gosdjwt.ParentInstructionV2{
					Name: "placeBirth",
					Children: []any{
						&gosdjwt.ChildInstructionV2{
							Name:  "countryCode",
							Value: doc.PersonalDetails.PlaceBirth.CountryCode,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "region",
							Value: doc.PersonalDetails.PlaceBirth.Region,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "town",
							Value: doc.PersonalDetails.PlaceBirth.Town,
						},
					},
				},
				&gosdjwt.ParentInstructionV2{
					Name: "stateOfResidenceAddress",
					Children: []any{
						&gosdjwt.ChildInstructionV2{
							Name:  "buildingName",
							Value: doc.PersonalDetails.StateOfResidenceAddress.BuildingName,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "countryCode",
							Value: doc.PersonalDetails.StateOfResidenceAddress.CountryCode,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "postCode",
							Value: doc.PersonalDetails.StateOfResidenceAddress.PostCode,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "region",
							Value: doc.PersonalDetails.StateOfResidenceAddress.Region,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "streetNo",
							Value: doc.PersonalDetails.StateOfResidenceAddress.StreetNo,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "town",
							Value: doc.PersonalDetails.StateOfResidenceAddress.Town,
						},
					},
				},
				&gosdjwt.ParentInstructionV2{
					Name: "stateOfStayAddress",
					Children: []any{
						&gosdjwt.ChildInstructionV2{
							Name:  "buildingName",
							Value: doc.PersonalDetails.StateOfStayAddress.BuildingName,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "countryCode",
							Value: doc.PersonalDetails.StateOfStayAddress.CountryCode,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "postCode",
							Value: doc.PersonalDetails.StateOfStayAddress.PostCode,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "region",
							Value: doc.PersonalDetails.StateOfStayAddress.Region,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "streetNo",
							Value: doc.PersonalDetails.StateOfStayAddress.StreetNo,
						},
						&gosdjwt.ChildInstructionV2{
							Name:  "town",
							Value: doc.PersonalDetails.StateOfStayAddress.Town,
						},
					},
				},
			},
		},
		&gosdjwt.ParentInstructionV2{
			Name: "statusConfirmation",
			Children: []any{
				&gosdjwt.ChildInstructionV2{
					Name:  "civilAndEmployedSelfEmployed",
					Value: doc.StatusConfirmation.CivilAndEmployedSelfEmployed,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "civilServant",
					Value: doc.StatusConfirmation.CivilServant,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "contractStaff",
					Value: doc.StatusConfirmation.ContractStaff,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "employedAndSelfEmployed",
					Value: doc.StatusConfirmation.EmployedAndSelfEmployed,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "civilAndEmployedSelfEmployed",
					Value: doc.StatusConfirmation.CivilAndEmployedSelfEmployed,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "employedTwoOrMoreStates",
					Value: doc.StatusConfirmation.EmployedTwoOrMoreStates,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "exception",
					Value: doc.StatusConfirmation.Exception,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "exceptionDescription",
					Value: doc.StatusConfirmation.ExceptionDescription,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "flightCrewMember",
					Value: doc.StatusConfirmation.FlightCrewMember,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "mariner",
					Value: doc.StatusConfirmation.Mariner,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "postedEmployedPerson",
					Value: doc.StatusConfirmation.PostedEmployedPerson,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "postedSelfEmployedPerson",
					Value: doc.StatusConfirmation.PostedSelfEmployedPerson,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "selfEmployedTwoOrMoreStates",
					Value: doc.StatusConfirmation.SelfEmployedTwoOrMoreStates,
				},
				&gosdjwt.ChildInstructionV2{
					Name:  "workingInStateUnder21",
					Value: doc.StatusConfirmation.WorkingInStateUnder21,
				},
			},
		},
	}

	cred, err := ins.SDJWT(jwt.SigningMethodHS256, "key")
	c.log.Debug("SDJWT", "cred", cred, "err", err)
	if err != nil {
		return nil, err
	}

	return cred, nil
}
