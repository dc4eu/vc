package oauth2

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
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
	jwt.RegisteredClaims
}

func ParseAndValidateDPoPJWT(signedJWT string) (*DPoP, error) {
	//claims := DPoP{}
	//	token, err := jwt.ParseWithClaims(signedJWT, &claims, func(token *jwt.Token) (any, error) {
	//		return []byte{}, nil
	//	}, jwt.WithLeeway(2*time.Second))
	//	if err != nil {
	//		return nil, err
	//	}
	//

	token, err := jwt.ParseWithClaims(signedJWT, &DPoP{}, func(token *jwt.Token) (any, error) {
		alg := token.Method.Alg()
		fmt.Println("alg", alg)
		//return pubkey.(token.Method.Alg()), nil
		return nil, nil
	})
	if err != nil {
		return nil, err
	}

	fmt.Println("token", token)

	return nil, nil
}
