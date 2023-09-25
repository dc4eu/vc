package pda1

import "time"

// Document model for PDA1
type Document struct {
	PersonalDetails           Section1 `json:"personalDetails" bson:"personalDetails" validate:"required"`
	MemberStateLegislation    Section2 `json:"memberStateLegislation" bson:"memberStateLegislation"`
	StatusConfirmation        Section3 `json:"statusConfirmation" bson:"statusConfirmation"`
	EmploymentDetails         Section4 `json:"employmentDetails" bson:"employmentDetails"`
	ActivityEmploymentDetails Section5 `json:"activityEmploymentDetails" bson:"activityEmploymentDetails"`
	CompletingInstitution     Section6 `json:"completingInstitution" bson:"completingInstitution"`
}

// AddressType is the model for the PDA1 address type
type AddressType struct {
	BuildingName string `json:"buildingName" bson:"buildingName"`
	StreetNo     string `json:"streetNo" bson:"streetNo"`
	PostCode     string `json:"postCode" bson:"postCode"`
	Town         string `json:"town" bson:"town"`
	Region       string `json:"region" bson:"region"`
	CountryCode  string `json:"countryCode" bson:"country_code" validate:"oneof=AT BE BG CY CZ DE DK EE EL ES FI FR HR HU IE IT LT LU LV MT NL PL PT RO SE SI SK UK"`
}

// WorkPlaceNameType is the model for the PDA1 work place name type
type WorkPlaceNameType struct {
	Seqno                 int    `json:"seqno" bson:"seqno"`
	FlagStateHomeBase     string `json:"flagStatehomeBase" bson:"flag_state_home_base"`
	CompanyNameVesselName string `json:"companyNameVesselName" bson:"company_name_vessel_name"`
}

// WorkPlaceAddressType is the model for the PDA1 work place address type
type WorkPlaceAddressType struct {
	Address    string `json:"addresses" bson:"addresses"`
	NameOfShip string `json:"nameOfShips" bson:"name_of_ships"`
	HomeBase   string `json:"homeBases" bson:"home_bases"`
	HostState  string `json:"hostStates" bson:"host_states"`
}

// BirthPlaceType is the model for the PDA1 birth place type
type BirthPlaceType struct {
	Town        string `json:"town" bson:"town"`
	Region      string `json:"region" bson:"region"`
	CountryCode string `json:"countryCode" bson:"countryCode" validate:"oneof=AT BE BG CY CZ DE DK EE EL ES FI FR HR HU IE IT LT LU LV MT NL PL PT RO SE SI SK UK"`
}

// Section1 is the model for the PDA1 section 1
type Section1 struct {
	PersonalIdentificationNumber string         `json:"personalIdentificationNumber" bson:"personalIdentificationNumber"`
	Sex                          string         `json:"sex" bson:"sex" validate:"oneof=01 02 98 99"`
	Surname                      string         `json:"surname" bson:"surname"`
	Forenames                    string         `json:"forenames" bson:"forenames"`
	SurnameAtBirth               string         `json:"surnameAtBirth" bson:"surnameAtBirth"`
	DateBirth                    string         `json:"dateBirth" bson:"dateBirth"`
	Nationality                  string         `json:"nationality" bson:"nationality" validate:"oneof=AT BE BG HR CY CZ DK EE FI FR DE EL HU IS IE IT LV LI LT LU MT NL NO PL PT RO SK SI ES SE CH UK XR XS XU AF AL DZ AD AO AG AR AM AU AZ BS BH BD BB BY BZ BJ BT BO BA BW BR BN BF BI KH CM CA CV CF TD CL CN CO KM CG CD CR CI CU DJ DM DO EC EG SV GQ ER ET FJ GA GM GE GH GD GT GN GW GY HT VA HN IN ID IR IQ IL JM JP JO KZ KE KI KP KR KW KG LA LB LS LR LY MK MG MW MY MV ML MH MR MU MX FM MD MC MN ME MA MZ MM NA NR NP NZ NI NE NG OM PK PW PS PA PG PY PE PH QA RU RW KN LC VC WS SM ST SA SN RS SC SL SG SB SO ZA SS LK SD SR SZ SY TJ TZ TH TL TG TO TT TN TR TM TV UG UA AE US UY UZ VU VE VN YE ZM ZW BQAQ BUMM BYAA CTKI CSHH DYBJ NQAQ TPTL FXFR AIDJ FQHH DDDE GEHH JTUM MIUM ANHH NTHH NHVU PCHH PZPA CSXX SKIN RHZW HVBF PUUM SUHH VDVN WKUM YDYE YUCS ZRCD"`
	PlaceBirth                   BirthPlaceType `json:"placeBirth" bson:"placeBirth"`
	StateOfResidenceAddress      AddressType    `json:"stateOfResidenceAddress" bson:"stateOfResidenceAddress"`
	StateOfStayAddress           AddressType    `json:"stateOfStayAddress" bson:"stateOfStayAddress"`
}

// Section2 is the model for the PDA1 section 2
type Section2 struct {
	MemberStateWhichLegislationApplies string    `json:"memberStateWhichLegislationApplies" bson:"member_state_which_legislation_applies" validate:"oneof=AT BE BG CY CZ DE DK EE EL ES FI FR HR HU IE IT LT LU LV MT NL PL PT RO SE SI SK UK"`
	StartingDate                       time.Time `json:"startingDate" bson:"starting_date"`
	EndingDate                         time.Time `json:"endingDate" bson:"ending_date"`
	CertificateForDurationActivity     bool      `json:"certificateForDurationActivity" bson:"certificate_for_duration_activity"`
	DeterminationProvisional           bool      `json:"determinationProvisional" bson:"determination_provisional"`
	TransitionRulesApplyAsEC8832004    bool      `json:"transitionRulesApplyAsEC8832004" bson:"transition_rules_apply_as_ec8832004"`
}

// Section3 is the model for the PDA1 section 3
type Section3 struct {
	PostedEmployedPerson         bool   `json:"postedEmployedPerson" bson:"posted_employed_person"`
	EmployedTwoOrMoreStates      bool   `json:"employedTwoOrMoreStates" bson:"employed_two_or_more_states"`
	PostedSelfEmployedPerson     bool   `json:"postedSelfEmployedPerson" bson:"posted_self_employed_person"`
	SelfEmployedTwoOrMoreStates  bool   `json:"selfEmployedTwoOrMoreStates" bson:"self_employed_two_or_more_states"`
	CivilServant                 bool   `json:"civilServant" bson:"civil_servant"`
	ContractStaff                bool   `json:"contractStaff" bson:"contract_staff"`
	Mariner                      bool   `json:"mariner" bson:"mariner"`
	EmployedAndSelfEmployed      bool   `json:"employedAndSelfEmployed" bson:"employed_and_self_employed"`
	CivilAndEmployedSelfEmployed bool   `json:"civilAndEmployedSelfEmployed" bson:"civil_and_employed_self_employed"`
	FlightCrewMember             bool   `json:"flightCrewMember" bson:"flight_crew_member"`
	Exception                    bool   `json:"exception" bson:"exception"`
	ExceptionDescription         string `json:"exceptionDescription" bson:"exception_description"`
	WorkingInStateUnder21        bool   `json:"workingInStateUnder21" bson:"working_in_state_under_21"`
}

// Section4 is the model for the PDA1 section 4
type Section4 struct {
	Employee                          bool        `json:"employee" bson:"employee"`
	SelfEmployedActivity              bool        `json:"selfEmployedActivity" bson:"self_employed_activity"`
	EmployerSelfEmployedActivityCodes []string    `json:"employerSelfEmployedActivityCodes" bson:"employer_self_employed_activity_codes"`
	NameBusinessName                  string      `json:"nameBusinessName" bson:"name_business_name"`
	RegisteredAddress                 AddressType `json:"registeredAddress" bson:"registered_address"`
}

// Section5 is the model for the PDA1 section 5
type Section5 struct {
	WorkPlaceNames            []WorkPlaceNameType    `json:"workPlaceNames" bson:"work_place_names"`
	WorkPlaceNamesBlob        string                 `json:"workPlaceNamesBlob" bson:"work_place_names_blob"`
	WorkPlaceAddresses        []WorkPlaceAddressType `json:"workPlaceAddresses" bson:"work_place_addresses"`
	WorkPlaceAddressesBlob    string                 `json:"workPlaceAddressesBlob" bson:"work_place_addresses_blob"`
	NoFixedAddress            bool                   `json:"noFixedAddress" bson:"no_fixed_address"`
	NoFixedAddressDescription string                 `json:"noFixedAddressDescription" bson:"no_fixed_address_description"`
}

// Section6 is the model for the PDA1 section 6
type Section6 struct {
	Name          string      `json:"name" bson:"name"`
	Address       AddressType `json:"address" bson:"address"`
	InstitutionID string      `json:"institutionID" bson:"institution_id"`
	OfficeFaxNo   string      `json:"officeFaxNo" bson:"office_fax_no"`
	OfficePhoneNo string      `json:"officePhoneNo" bson:"office_phone_no"`
	Email         string      `json:"email" bson:"email"`
	Date          time.Time   `json:"date" bson:"date"`
	Signature     string      `json:"signature" bson:"signature"`
}
