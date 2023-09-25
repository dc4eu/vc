package pda1

// Credential model for the PDA1
type Credential struct {
	EIDASType          string           `json:"eidas_type"`
	ISS                string           `json:"iss"`
	AuthenticSource    string           `json:"authentic_source"`
	GivenName          string           `json:"given_name"`
	FamilyName         string           `json:"family_name"`
	DateOfBirth        string           `json:"date_of_birth"`
	UIDPID             string           `json:"uid_pid"`
	CredentialSchema   CredentialSchema `json:"credentialSchema"`
	IAT                int64            `json:"iat"`
	EXP                int64            `json:"exp"`
	NBF                int64            `json:"nbf"`
	Sub                string           `json:"sub"`
	ProofValue         string           `json:"proofValue"`
	VerificationMethod string           `json:"verificationMethod"`
	CredentialStatus   CredentialStatus `json:"credentialStatus"`
}

type CredentialSchema struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type CredentialStatus struct {
	ID                   string `json:"id"`
	Type                 string `json:"type"`
	StatusPurpose        string `json:"statusPurpose"`
	StatusListIndex      string `json:"statusListIndex"`
	StatusListCredential string `json:"statusListCredential"`
}
