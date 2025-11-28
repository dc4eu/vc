//go:build vc20

package credential

import (
	"testing"
	"time"
)

func TestVerifiableCredential_Validate(t *testing.T) {
	tests := []struct {
		name    string
		vc      *VerifiableCredential
		wantErr error
	}{
		{
			name: "valid credential",
			vc: &VerifiableCredential{
				Context:           []string{VC20ContextURL},
				Type:              []string{TypeVerifiableCredential},
				Issuer:            "did:example:issuer",
				ValidFrom:         time.Now().Format(time.RFC3339),
				CredentialSubject: map[string]interface{}{"id": "did:example:subject"},
			},
			wantErr: nil,
		},
		{
			name: "missing context",
			vc: &VerifiableCredential{
				Type:              []string{TypeVerifiableCredential},
				Issuer:            "did:example:issuer",
				ValidFrom:         time.Now().Format(time.RFC3339),
				CredentialSubject: map[string]interface{}{"id": "did:example:subject"},
			},
			wantErr: ErrMissingContext,
		},
		{
			name: "invalid base context",
			vc: &VerifiableCredential{
				Context:           []string{"https://example.com/context"},
				Type:              []string{TypeVerifiableCredential},
				Issuer:            "did:example:issuer",
				ValidFrom:         time.Now().Format(time.RFC3339),
				CredentialSubject: map[string]interface{}{"id": "did:example:subject"},
			},
			wantErr: ErrInvalidBaseContext,
		},
		{
			name: "missing type",
			vc: &VerifiableCredential{
				Context:           []string{VC20ContextURL},
				Issuer:            "did:example:issuer",
				ValidFrom:         time.Now().Format(time.RFC3339),
				CredentialSubject: map[string]interface{}{"id": "did:example:subject"},
			},
			wantErr: ErrMissingType,
		},
		{
			name: "missing VerifiableCredential type",
			vc: &VerifiableCredential{
				Context:           []string{VC20ContextURL},
				Type:              []string{"CustomCredential"},
				Issuer:            "did:example:issuer",
				ValidFrom:         time.Now().Format(time.RFC3339),
				CredentialSubject: map[string]interface{}{"id": "did:example:subject"},
			},
			wantErr: ErrMissingVCType,
		},
		{
			name: "missing issuer",
			vc: &VerifiableCredential{
				Context:           []string{VC20ContextURL},
				Type:              []string{TypeVerifiableCredential},
				ValidFrom:         time.Now().Format(time.RFC3339),
				CredentialSubject: map[string]interface{}{"id": "did:example:subject"},
			},
			wantErr: ErrMissingIssuer,
		},
		{
			name: "missing validFrom",
			vc: &VerifiableCredential{
				Context:           []string{VC20ContextURL},
				Type:              []string{TypeVerifiableCredential},
				Issuer:            "did:example:issuer",
				CredentialSubject: map[string]interface{}{"id": "did:example:subject"},
			},
			wantErr: ErrMissingValidFrom,
		},
		{
			name: "missing credentialSubject",
			vc: &VerifiableCredential{
				Context:   []string{VC20ContextURL},
				Type:      []string{TypeVerifiableCredential},
				Issuer:    "did:example:issuer",
				ValidFrom: time.Now().Format(time.RFC3339),
			},
			wantErr: ErrMissingCredentialSubject,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.vc.Validate()
			if err != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifiableCredential_GetIssuerID(t *testing.T) {
	tests := []struct {
		name    string
		issuer  interface{}
		want    string
		wantErr bool
	}{
		{
			name:    "string issuer",
			issuer:  "did:example:issuer",
			want:    "did:example:issuer",
			wantErr: false,
		},
		{
			name: "object issuer",
			issuer: map[string]interface{}{
				"id":   "did:example:issuer",
				"name": "Example Issuer",
			},
			want:    "did:example:issuer",
			wantErr: false,
		},
		{
			name:    "invalid issuer type",
			issuer:  123,
			want:    "",
			wantErr: true,
		},
		{
			name:    "object issuer without id",
			issuer:  map[string]interface{}{"name": "Example Issuer"},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vc := &VerifiableCredential{Issuer: tt.issuer}
			got, err := vc.GetIssuerID()
			if (err != nil) != tt.wantErr {
				t.Errorf("GetIssuerID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetIssuerID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifiableCredential_IsValidNow(t *testing.T) {
	now := time.Now()
	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)

	tests := []struct {
		name       string
		validFrom  string
		validUntil string
		want       bool
	}{
		{
			name:       "valid credential",
			validFrom:  past.Format(time.RFC3339),
			validUntil: future.Format(time.RFC3339),
			want:       true,
		},
		{
			name:       "not yet valid",
			validFrom:  future.Format(time.RFC3339),
			validUntil: future.Add(1 * time.Hour).Format(time.RFC3339),
			want:       false,
		},
		{
			name:       "expired credential",
			validFrom:  past.Add(-1 * time.Hour).Format(time.RFC3339),
			validUntil: past.Format(time.RFC3339),
			want:       false,
		},
		{
			name:       "no expiration",
			validFrom:  past.Format(time.RFC3339),
			validUntil: "",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vc := &VerifiableCredential{
				ValidFrom:  tt.validFrom,
				ValidUntil: tt.validUntil,
			}
			if got := vc.IsValidNow(); got != tt.want {
				t.Errorf("IsValidNow() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifiableCredential_JSON(t *testing.T) {
	vc := &VerifiableCredential{
		Context:   []string{VC20ContextURL},
		Type:      []string{TypeVerifiableCredential},
		Issuer:    "did:example:issuer",
		ValidFrom: time.Now().Format(time.RFC3339),
		CredentialSubject: map[string]interface{}{
			"id":   "did:example:subject",
			"name": "John Doe",
		},
	}

	// Test ToJSON
	data, err := vc.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	// Test FromJSON
	decoded, err := FromJSON(data)
	if err != nil {
		t.Fatalf("FromJSON() error = %v", err)
	}

	if decoded.ValidFrom != vc.ValidFrom {
		t.Errorf("FromJSON() validFrom = %v, want %v", decoded.ValidFrom, vc.ValidFrom)
	}
}
