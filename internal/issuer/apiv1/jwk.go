package apiv1

import (
	"context"
	"encoding/json"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
)

//type jwkClaims struct {
//	CRV string `json:"crv"`
//	KID string `json:"kid"`
//	KTY string `json:"kty"`
//	X   string `json:"x"`
//	Y   string `json:"y"`
//	D   string `json:"d"`
//}

func (c *Client) createJWK(ctx context.Context) error {
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(2*time.Second))
	defer cancel()

	key, err := jwk.New(c.privateKey)
	if err != nil {
		return err
	}

	key.Set("kid", "singing_")

	c.jwkBytes, err = json.MarshalIndent(key, "", "  ")
	if err != nil {
		return err
	}

	if err := json.Unmarshal(c.jwkBytes, c.jwkProto); err != nil {
		return err
	}

	jwkClaim := jwt.MapClaims{
		"crv": c.jwkProto.Crv,
		"kid": c.jwkProto.Kid,
		"kty": c.jwkProto.Kty,
		"x":   c.jwkProto.X,
		"y":   c.jwkProto.Y,
		"d":   c.jwkProto.D,
	}
	c.jwkClaim["jwk"] = jwkClaim

	return nil
}
