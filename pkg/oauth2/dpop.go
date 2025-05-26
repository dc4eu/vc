package oauth2

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type DPoP struct {
	// JTI Unique identifier for the DPoP proof JWT. The value MUST be assigned such that there is a negligible probability that the same value will be assigned to any other DPoP proof used in the same context during the time window of validity. Such uniqueness can be accomplished by encoding (base64url or any other suitable encoding) at least 96 bits of pseudorandom data or by using a version 4 Universally Unique Identifier (UUID) string according to [RFC4122]. The jti can be used by the server for replay detection and prevention; see Section 11.1.
	JTI string `json:"jti" validate:"required"`

	//HTM The value of the HTTP method (Section 9.1 of [RFC9110]) of the request to which the JWT is attached.¶
	HTM string `json:"htm" validate:"required,oneof=POST GET PUT DELETE PATCH OPTIONS HEAD"`

	// HTU The HTTP target URI (Section 7.1 of [RFC9110]) of the request to which the JWT is attached, without query and fragment parts.¶
	HTU string `json:"htu" validate:"required,url"`

	// IAT Creation timestamp of the JWT (Section 4.1.6 of [RFC7519]).¶
	//IAT int64 `json:"iat" validate:"required"` // TODO: use time.Time

	// ATH Hash of the access token. The value MUST be the result of a base64url encoding (as defined in Section 2 of [RFC7515]) the SHA-256 [SHS] hash of the ASCII encoding of the associated access token's value.¶
	ATH string `json:"ath"`
	//jwt.RegisteredClaims
}

func parseJWK(dpopJWT string) (jwk.Set, error) {
	token, err := jwt.ParseString(dpopJWT, jwt.WithVerify(false))
	if err != nil {
		return nil, err
	}

	fmt.Println("token", token)

	keySet := jwk.NewSet()
	//
	//	k, err := jwk.ParseKey([]byte(key))
	//	if err != nil {
	//		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	//	}
	//	keySet.AddKey(k)

	return keySet, err
}

func Validate(dPopJWT string, set jwk.Set) (bool, error) {
	jwt.WithKeySet(set)
	token, err := jwt.ParseString(dPopJWT, jwt.WithKeySet(set))
	if err != nil {
		return false, err
	}

	fmt.Println("token", token)

	return false, nil

}

// Validate validates a signed sdjwt
//func ParseDPoPJWT(dpopJWT string, pubkey crypto.PublicKey) (bool, error) {
//	claims := jwt.MapClaims{}
//
//	token, err := jwt.ParseWithClaims(dpopJWT, claims, func(token *jwt.Token) (any, error) {
//		return pubkey.(*ecdsa.PublicKey), nil
//	})
//	if err != nil {
//		return false, err
//	}
//
//	return token.Valid, nil
//}
//
//func (d *DPoP) SignJWT(signingMethod jwt.SigningMethod, privateKey crypto.PrivateKey, certs []string) (string, error) {
//	token := jwt.NewWithClaims(signingMethod, d)
//
//	// Sign the token with the private key
//	signedToken, err := token.SignedString(privateKey)
//	if err != nil {
//		return "", err
//	}
//
//	return signedToken, nil
//}

//func (d *DPoP) SignJWT2(signingMethod jwt., privateKey crypto.PrivateKey, certs []string) (string, error) {
//	//token := jwt.NewWithClaims(signingMethod, d)
//
//	pubkey, err := jwk.PublicKeyOf(privateKey)
//	if err != nil {
//		fmt.Printf("failed to get public key: %s\n", err)
//		return "", err
//	}
//	b, err := json.Marshal(pubkey)
//	if err != nil {
//		return "", err
//	}
//
//	fmt.Println("pubkey", string(b))
//
//	// Sign the token with the private key
//	signedToken, err := token.SignedString(privateKey)
//	if err != nil {
//		return "", err
//	}
//
//	return signedToken, nil
//}

//func mura() {
//
//}
