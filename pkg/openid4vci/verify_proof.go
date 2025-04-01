package openid4vci

import (
	"crypto"
	"errors"
	"fmt"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// * all required claims for that proof type are contained as defined in Section 8.2.1,
// * the key proof is explicitly typed using header parameters as defined for that proof type,
// * the header parameter indicates a registered asymmetric digital signature algorithm, alg parameter
// value is not none, is supported by the application, and is acceptable per local policy,
//
// * the signature on the key proof verifies with the public key contained in the header parameter,
// * the header parameter does not contain a private key,
// * if the server had previously provided a c_nonce, the nonce in the key proof matches the server-provided
// 	c_nonce value,
// * the creation time of the JWT, as determined by either the issuance time, or a server managed timestamp via the
// 	nonce claim, is within an acceptable window (see Section 12.5).

func verifyJWT(jwt string, publicKey crypto.PublicKey) error {
	claims := jwtv5.MapClaims{}

	token, err := jwtv5.ParseWithClaims(jwt, claims, func(token *jwtv5.Token) (any, error) {
		if _, ok := token.Header["alg"]; !ok {
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "alg parameter not found"}
		}

		if _, ok := token.Header["typ"]; !ok {
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "typ parameter not found"}
		}
		if token.Header["typ"] != "openid4vci-proof+jwt" {
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "typ parameter value is not openid4vci-proof+jwt"}
		}

		if _, ok := token.Header["jwk"]; ok {
			if _, ok := token.Header["kid"]; ok {
				return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "kid parameter can not be present when jwk parameter is present"}
			}
		}

		if _, ok := claims["iat"]; !ok {
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "iat parameter not found"}
		}
		t, err := claims.GetIssuedAt()
		if err != nil {
			return nil, err
		}
		if t.After(time.Now()) {
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "iat parameter value is in the future"}
		}

		if _, ok := token.Header["aud"]; !ok {
			return nil, &Error{Err: ErrInvalidCredentialRequest, ErrorDescription: "aud parameter not found"}
		}
		// check that aud is https URI, https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-identifie

		if _, ok := token.Method.(*jwtv5.SigningMethodECDSA); !ok {
			if _, ok := token.Method.(*jwtv5.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
		}
		return publicKey, nil

	})
	if err != nil {
		return err
	}

	if !token.Valid {
		return errors.New("token invalid")
	}
	fmt.Println("token", token)
	return nil
}

// VerifyProof https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-verifying-proof
func (c *CredentialRequest) VerifyProof(publicKey crypto.PublicKey) error {
	fmt.Println("privateKey", publicKey)
	switch c.Proof.ProofType {
	case "jwt":
		if err := verifyJWT(c.Proof.JWT, publicKey); err != nil {
			return err
		}

		return nil
	case "ldp_vp":
		return nil
	case "attestation":
		return nil
	default:
		return errors.New("invalid proof type")
	}

	// TODO
}
