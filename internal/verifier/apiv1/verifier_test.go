package apiv1

import "testing"

func TestVPToken_validateHolderSignature(t *testing.T) {
	type fields struct {
		RawToken           string
		Header             map[string]interface{}
		Payload            map[string]interface{}
		Signature          string
		DecodedCredentials []map[string]interface{}
		DisclosedClaims    []string
		ValidationResults  map[string]bool
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Valid Holder Signature",
			fields: fields{
				RawToken: `eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiaG9sZGVyIiwgImF1ZCI6ICJ2ZXJpZmllciIsICJpYXQiOiAxNjgwODk3ODU1fQ.VALID_SIGNATURE`,
				Header: map[string]interface{}{
					"alg": "ES256",
					"typ": "JWT",
				},
				Payload: map[string]interface{}{
					"sub": "holder",
					"aud": "verifier",
					"iat": 1680897855,
				},
				Signature: "VALID_SIGNATURE",
				ValidationResults: map[string]bool{
					"HolderSignature": false,
				},
			},
			wantErr: false,
		},
		{
			name: "Invalid Holder Signature",
			fields: fields{
				RawToken: `eyJhbGciOiAiRVMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiaG9sZGVyIiwgImF1ZCI6ICJ2ZXJpZmllciIsICJpYXQiOiAxNjgwODk3ODU1fQ.INVALID_SIGNATURE`,
				Header: map[string]interface{}{
					"alg": "ES256",
					"typ": "JWT",
				},
				Payload: map[string]interface{}{
					"sub": "holder",
					"aud": "verifier",
					"iat": 1680897855,
				},
				Signature: "INVALID_SIGNATURE",
				ValidationResults: map[string]bool{
					"HolderSignature": false,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vp := &VPToken{
				RawToken:           tt.fields.RawToken,
				Header:             tt.fields.Header,
				Payload:            tt.fields.Payload,
				Signature:          tt.fields.Signature,
				DecodedCredentials: tt.fields.DecodedCredentials,
				DisclosedClaims:    tt.fields.DisclosedClaims,
				ValidationResults:  tt.fields.ValidationResults,
			}
			if err := vp.validateHolderSignature(); (err != nil) != tt.wantErr {
				t.Errorf("validateHolderSignature() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
