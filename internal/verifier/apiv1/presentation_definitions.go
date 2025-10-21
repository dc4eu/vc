package apiv1

import (
	"fmt"
	"vc/pkg/model"
	"vc/pkg/openid4vp"
)

//var format = map[string]openid4vp.Format{
//	"vc+sd-jwt": {Alg: []string{"ES256"}},
//}

var presentationRequestTypes = map[string]*openid4vp.PresentationRequestType{
	"VCELM": {
		ID:          "VCELM",
		Title:       "VC European Learning Model for EMREX",
		Description: "Required Fields: VC type, ELM",
	},
	"VCEHIC": {
		ID:          "VCEHIC",
		Title:       "VC European Health Insurance Card",
		Description: "Request a VC European Health Insurance Card",
	},
	"VCPID": {
		ID:          "VCPID",
		Title:       "VC PID",
		Description: "Request a VC PID",
	},

	"EuropeanHealthInsuranceCard": {
		ID:          "EuropeanHealthInsuranceCard",
		Title:       "European Health Insurance Card - based on wwWallet issuer",
		Description: "Request a European Health Insurance Card",
	},
	//"CustomVerifiableId": {
	//	ID:          "CustomVerifiableId",
	//	Title:       "PID  (ARF v1.8) - based on wwWallet issuer",
	//	Description: "Request a PID (ARF v1.8)",
	//},
	"MinimalPIDAndEuropeanHealthInsuranceCard": {
		ID:          "MinimalPIDAndEuropeanHealthInsuranceCard",
		Title:       "PID (ARF v1.8) + EHIC - both based on wwWallet issuer",
		Description: "Request a PID (ARF v1.8) along with an EHIC",
	},
}

func lookupPresentationRequestTypeFrom(ID string) (*openid4vp.PresentationRequestType, bool) {
	prt, ok := presentationRequestTypes[ID]
	return prt, ok
}

func buildPresentationDefinition(presentationRequestType *openid4vp.PresentationRequestType) (*openid4vp.PresentationDefinition, error) {
	switch presentationRequestType.ID {
	case "VCELM":
		return vcELMForEMREX(presentationRequestType), nil
	case "VCEHIC":
		return vcEHIC(presentationRequestType), nil
	case "VCPID":
		return vcPID(presentationRequestType), nil
	case "EuropeanHealthInsuranceCard":
		return wwwEHIC(presentationRequestType), nil
	//case "CustomVerifiableId":
	//	return wwwPID18(presentationRequestType), nil
	case "MinimalPIDAndEuropeanHealthInsuranceCard":
		return wwwMinimalPIDAndEuropeanHealthInsuranceCard(presentationRequestType), nil
	default:
		return nil, fmt.Errorf("presentationRequestType.ID %s is currently not supported", presentationRequestType.ID)
	}
}

func vcELMForEMREX(requestType *openid4vp.PresentationRequestType) *openid4vp.PresentationDefinition {
	vctList := []string{model.CredentialTypeUrnEudiElm1}

	return &openid4vp.PresentationDefinition{
		ID:          requestType.ID,
		Title:       requestType.Title,
		Description: requestType.Description,
		InputDescriptors: []openid4vp.InputDescriptor{
			{
				ID:     requestType.ID,
				Format: nil, //todo(masv): fix
				Constraints: openid4vp.Constraints{
					Fields: []openid4vp.Field{
						{Name: "VC type", Path: []string{"$.vct"}, Filter: &openid4vp.Filter{Type: "string", Enum: vctList}},
						{Name: "ELM", Path: []string{"$.elm"}},
					},
				},
			},
		},
	}
}

func vcEHIC(requestType *openid4vp.PresentationRequestType) *openid4vp.PresentationDefinition {
	vctList := []string{model.CredentialTypeUrnEudiEhic1}

	return &openid4vp.PresentationDefinition{
		ID:          requestType.ID,
		Title:       requestType.Title,
		Description: requestType.Description,
		InputDescriptors: []openid4vp.InputDescriptor{
			{
				ID:     requestType.ID,
				Format: nil, //todo(masv): fix
				Constraints: openid4vp.Constraints{
					Fields: []openid4vp.Field{
						{Name: "VC type", Path: []string{"$.vct"}, Filter: &openid4vp.Filter{Type: "string", Enum: vctList}},
						{Name: "Personal ID", Path: []string{"$.personal_administrative_number"}},
						{Name: "Document number", Path: []string{"$.document_number"}},
						{Name: "Issuing country", Path: []string{"$.issuing_country"}},
						{Name: "Issuing authority id", Path: []string{"$.issuing_authority.id"}},
						{Name: "Issuing authority name", Path: []string{"$.issuing_authority.name"}},
						{Name: "Expiry date", Path: []string{"$.date_of_expiry"}},
						{Name: "Issue date", Path: []string{"$.date_of_issuance"}},
					},
				},
			},
		},
	}
}

func vcPID(requestType *openid4vp.PresentationRequestType) *openid4vp.PresentationDefinition {
	vctList := []string{model.CredentialTypeUrnEudiPid1}

	return &openid4vp.PresentationDefinition{
		ID:          requestType.ID,
		Title:       requestType.Title,
		Description: requestType.Description,
		Selectable:  true, // special field found i db4eu verifier
		InputDescriptors: []openid4vp.InputDescriptor{
			{
				ID:     requestType.ID,
				Format: nil, //todo(masv): fix
				Constraints: openid4vp.Constraints{
					Fields: []openid4vp.Field{
						{Name: "VC type", Path: []string{"$.vct"}, Filter: &openid4vp.Filter{Type: "string", Enum: vctList}},
						{Name: "Family name", Path: []string{"$.family_name"}},
						{Name: "Given name", Path: []string{"$.given_name"}},
						{Name: "Date of birth", Path: []string{"$.birthdate"}},
						{Name: "Place of birth", Path: []string{"$.birth_place"}},
						{Name: "Nationality", Path: []string{"$.nationality"}},
						{Name: "Issuing authority", Path: []string{"$.issuing_authority"}},
						{Name: "Issuing country", Path: []string{"$.issuing_country"}},
						{Name: "Expiry date", Path: []string{"$.expiry_date"}},
						//TODO add more optional attributes for vcPID?
					},
				},
			},
		},
	}
}

func wwwEHIC(requestType *openid4vp.PresentationRequestType) *openid4vp.PresentationDefinition {
	vctList := []string{"urn:eudi:ehic:1"}

	return &openid4vp.PresentationDefinition{
		ID:          requestType.ID,
		Title:       requestType.Title,
		Description: requestType.Description,
		InputDescriptors: []openid4vp.InputDescriptor{
			{
				ID:     requestType.ID,
				Format: nil, //todo(masv): fix
				Constraints: openid4vp.Constraints{
					Fields: []openid4vp.Field{
						{Name: "VC type", Path: []string{"$.vct"}, Filter: &openid4vp.Filter{Type: "string", Enum: vctList}},
						{Name: "Personal ID", Path: []string{"$.personal_administrative_number"}},
						{Name: "Document number", Path: []string{"$.document_number"}},
						{Name: "Issuing country", Path: []string{"$.issuing_country"}},
						{Name: "Issuing authority id", Path: []string{"$.issuing_authority.id"}},
						{Name: "Issuing authority name", Path: []string{"$.issuing_authority.name"}},
						{Name: "Expiry Date", Path: []string{"$.date_of_expiry"}},
						{Name: "Issue Date", Path: []string{"$.date_of_issuance"}},
					},
				},
			},
		},
	}
}

func wwwMinimalPIDAndEuropeanHealthInsuranceCard(requestType *openid4vp.PresentationRequestType) *openid4vp.PresentationDefinition {
	pidVctList := []string{"urn:eudi:pid:1"}
	ehicVctList := []string{"urn:eudi:ehic:1"}

	return &openid4vp.PresentationDefinition{
		ID:          requestType.ID,
		Title:       requestType.Title,
		Description: requestType.Description,
		InputDescriptors: []openid4vp.InputDescriptor{
			{
				ID:     "minimalSdJwtPID",
				Format: nil, //todo(masv): fix
				Constraints: openid4vp.Constraints{
					Fields: []openid4vp.Field{
						{Name: "VC type", Path: []string{"$.vct"}, Filter: &openid4vp.Filter{Type: "string", Enum: pidVctList}},
						{Name: "Family name", Path: []string{"$.family_name"}},
						{Name: "Given name", Path: []string{"$.given_name"}},
						{Name: "Date of birth", Path: []string{"$.birthdate"}},
						//{Name: "Place of birth", Path: []string{"$.birth_place"}},
						//{Name: "Nationality", Path: []string{"$.nationalities"}},
						//{Name: "Issuing authority", Path: []string{"$.issuing_authority"}},
						//{Name: "Issuing country", Path: []string{"$.issuing_country"}},
						//{Name: "Expiry date", Path: []string{"$.date_of_expiry"}},
					},
				},
			},
			{
				ID:     "EuropeanHealthInsuranceCard",
				Format: nil, //todo(masv): fix
				Constraints: openid4vp.Constraints{
					Fields: []openid4vp.Field{
						{Name: "VC type", Path: []string{"$.vct"}, Filter: &openid4vp.Filter{Type: "string", Enum: ehicVctList}},
						{Name: "Personal ID", Path: []string{"$.personal_administrative_number"}},
						{Name: "Document Number", Path: []string{"$.document_number"}},
					},
				},
			},
		},
	}
}
