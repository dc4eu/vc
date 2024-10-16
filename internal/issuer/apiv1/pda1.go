package apiv1

import (
	"context"
	"vc/pkg/logger"
	"vc/pkg/pda1"
	"vc/pkg/sdjwt"
	"vc/pkg/trace"
)

type pda1Client struct {
	log    *logger.Log
	tracer *trace.Tracer
}

func newPDA1Client(tracer *trace.Tracer, log *logger.Log) (*pda1Client, error) {
	c := &pda1Client{
		log:    log,
		tracer: tracer,
	}

	return c, nil
}

func (c *pda1Client) sdjwt(ctx context.Context, doc *pda1.Document) sdjwt.InstructionsV2 {
	ctx, span := c.tracer.Start(ctx, "apiv1:pda1:sdjwt")
	defer span.End()

	instruction := sdjwt.InstructionsV2{
		&sdjwt.ParentInstructionV2{
			Name: "activityEmploymentDetails",
			Children: []any{
				&sdjwt.ChildInstructionV2{
					Name:  "noFixedAddress",
					Value: doc.ActivityEmploymentDetails.NoFixedAddress,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "noFixedAddressDescription",
					Value: doc.ActivityEmploymentDetails.NoFixedAddressDescription,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "workPlaceAddresses",
					Value: doc.ActivityEmploymentDetails.WorkPlaceAddresses,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "workPlaceAddressesBlob",
					Value: doc.ActivityEmploymentDetails.WorkPlaceAddressesBlob,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "workPlaceNames",
					Value: doc.ActivityEmploymentDetails.WorkPlaceNames,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "workPlaceNamesBlob",
					Value: doc.ActivityEmploymentDetails.WorkPlaceNamesBlob,
				},
			},
		},
		&sdjwt.ParentInstructionV2{
			Name: "completingInstitution",
			Children: []any{
				&sdjwt.ChildInstructionV2{
					Name:  "date",
					Value: doc.CompletingInstitution.Date,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "email",
					Value: doc.CompletingInstitution.Email,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "institutionID",
					Value: doc.CompletingInstitution.InstitutionID,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "name",
					Value: doc.CompletingInstitution.Name,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "officeFaxNo",
					Value: doc.CompletingInstitution.OfficeFaxNo,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "signature",
					Value: doc.CompletingInstitution.Signature,
				},
				&sdjwt.ParentInstructionV2{
					Name:                "address",
					SelectiveDisclosure: true,
					Children: []any{
						&sdjwt.ChildInstructionV2{
							Name:  "buildingName",
							Value: doc.CompletingInstitution.Address.BuildingName,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "countryCode",
							Value: doc.CompletingInstitution.Address.CountryCode,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "postCode",
							Value: doc.CompletingInstitution.Address.PostCode,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "region",
							Value: doc.CompletingInstitution.Address.Region,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "streetNo",
							Value: doc.CompletingInstitution.Address.StreetNo,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "town",
							Value: doc.CompletingInstitution.Address.Town,
						},
					},
				},
			},
		},
		&sdjwt.ParentInstructionV2{
			Name: "employmentDetails",
			Children: []any{
				&sdjwt.ChildInstructionV2{
					Name:  "employee",
					Value: doc.EmploymentDetails.Employee,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "employerSelfEmployedActivityCodes",
					Value: doc.EmploymentDetails.EmployerSelfEmployedActivityCodes,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "nameBusinessName",
					Value: doc.EmploymentDetails.NameBusinessName,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "registeredAddress",
					Value: doc.EmploymentDetails.RegisteredAddress,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "selfEmployedActivity",
					Value: doc.EmploymentDetails.SelfEmployedActivity,
				},
				&sdjwt.ParentInstructionV2{
					Name: "registeredAddress",
					Children: []any{
						&sdjwt.ChildInstructionV2{
							Name:  "buildingName",
							Value: doc.EmploymentDetails.RegisteredAddress.BuildingName,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "countryCode",
							Value: doc.EmploymentDetails.RegisteredAddress.CountryCode,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "postCode",
							Value: doc.EmploymentDetails.RegisteredAddress.PostCode,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "region",
							Value: doc.EmploymentDetails.RegisteredAddress.Region,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "streetNo",
							Value: doc.EmploymentDetails.RegisteredAddress.StreetNo,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "town",
							Value: doc.EmploymentDetails.RegisteredAddress.Town,
						},
					},
				},
			},
		},
		&sdjwt.ParentInstructionV2{
			Name: "memberStateLegislation",
			Children: []any{
				&sdjwt.ChildInstructionV2{
					Name:  "certificateForDurationActivity",
					Value: doc.MemberStateLegislation.CertificateForDurationActivity,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "determinationProvisional",
					Value: doc.MemberStateLegislation.DeterminationProvisional,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "endingDate",
					Value: doc.MemberStateLegislation.EndingDate,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "memberStateWhichLegislationApplies",
					Value: doc.MemberStateLegislation.MemberStateWhichLegislationApplies,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "startingDate",
					Value: doc.MemberStateLegislation.StartingDate,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "transitionRulesApplyAsEC8832004",
					Value: doc.MemberStateLegislation.TransitionRulesApplyAsEC8832004,
				},
			},
		},
		&sdjwt.ParentInstructionV2{
			Name: "personalDetails",
			Children: []any{
				&sdjwt.ChildInstructionV2{
					Name:                "dateBirth",
					SelectiveDisclosure: true,
					Value:               doc.PersonalDetails.DateBirth,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "forenames",
					Value: doc.PersonalDetails.Forenames,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "nationality",
					Value: doc.PersonalDetails.Nationality,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "personalIdentificationNumber",
					Value: doc.PersonalDetails.PersonalIdentificationNumber,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "sex",
					Value: doc.PersonalDetails.Sex,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "surname",
					Value: doc.PersonalDetails.Surname,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "surnameAtBirth",
					Value: doc.PersonalDetails.SurnameAtBirth,
				},
				&sdjwt.ParentInstructionV2{
					Name: "placeBirth",
					Children: []any{
						&sdjwt.ChildInstructionV2{
							Name:  "countryCode",
							Value: doc.PersonalDetails.PlaceBirth.CountryCode,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "region",
							Value: doc.PersonalDetails.PlaceBirth.Region,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "town",
							Value: doc.PersonalDetails.PlaceBirth.Town,
						},
					},
				},
				&sdjwt.ParentInstructionV2{
					Name: "stateOfResidenceAddress",
					Children: []any{
						&sdjwt.ChildInstructionV2{
							Name:  "buildingName",
							Value: doc.PersonalDetails.StateOfResidenceAddress.BuildingName,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "countryCode",
							Value: doc.PersonalDetails.StateOfResidenceAddress.CountryCode,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "postCode",
							Value: doc.PersonalDetails.StateOfResidenceAddress.PostCode,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "region",
							Value: doc.PersonalDetails.StateOfResidenceAddress.Region,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "streetNo",
							Value: doc.PersonalDetails.StateOfResidenceAddress.StreetNo,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "town",
							Value: doc.PersonalDetails.StateOfResidenceAddress.Town,
						},
					},
				},
				&sdjwt.ParentInstructionV2{
					Name: "stateOfStayAddress",
					Children: []any{
						&sdjwt.ChildInstructionV2{
							Name:  "buildingName",
							Value: doc.PersonalDetails.StateOfStayAddress.BuildingName,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "countryCode",
							Value: doc.PersonalDetails.StateOfStayAddress.CountryCode,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "postCode",
							Value: doc.PersonalDetails.StateOfStayAddress.PostCode,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "region",
							Value: doc.PersonalDetails.StateOfStayAddress.Region,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "streetNo",
							Value: doc.PersonalDetails.StateOfStayAddress.StreetNo,
						},
						&sdjwt.ChildInstructionV2{
							Name:  "town",
							Value: doc.PersonalDetails.StateOfStayAddress.Town,
						},
					},
				},
			},
		},
		&sdjwt.ParentInstructionV2{
			Name: "statusConfirmation",
			Children: []any{
				&sdjwt.ChildInstructionV2{
					Name:  "civilAndEmployedSelfEmployed",
					Value: doc.StatusConfirmation.CivilAndEmployedSelfEmployed,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "civilServant",
					Value: doc.StatusConfirmation.CivilServant,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "contractStaff",
					Value: doc.StatusConfirmation.ContractStaff,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "employedAndSelfEmployed",
					Value: doc.StatusConfirmation.EmployedAndSelfEmployed,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "civilAndEmployedSelfEmployed",
					Value: doc.StatusConfirmation.CivilAndEmployedSelfEmployed,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "employedTwoOrMoreStates",
					Value: doc.StatusConfirmation.EmployedTwoOrMoreStates,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "exception",
					Value: doc.StatusConfirmation.Exception,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "exceptionDescription",
					Value: doc.StatusConfirmation.ExceptionDescription,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "flightCrewMember",
					Value: doc.StatusConfirmation.FlightCrewMember,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "mariner",
					Value: doc.StatusConfirmation.Mariner,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "postedEmployedPerson",
					Value: doc.StatusConfirmation.PostedEmployedPerson,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "postedSelfEmployedPerson",
					Value: doc.StatusConfirmation.PostedSelfEmployedPerson,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "selfEmployedTwoOrMoreStates",
					Value: doc.StatusConfirmation.SelfEmployedTwoOrMoreStates,
				},
				&sdjwt.ChildInstructionV2{
					Name:  "workingInStateUnder21",
					Value: doc.StatusConfirmation.WorkingInStateUnder21,
				},
			},
		},
	}

	return instruction
}
