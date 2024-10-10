package apiv1

import (
	"context"
	"encoding/json"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
)

type jwkClaims struct {
	CRV string `json:"crv"`
	KID string `json:"kid"`
	KTY string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
}

func (c *Client) createJWK(ctx context.Context) error {
	ctx, cancel := context.WithDeadline(ctx, time.Now().Add(2*time.Second))
	defer cancel()

	key, err := jwk.New(c.privateKey)
	if err != nil {
		return err
	}

	key.Set("kid", "singing_")

	buf, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		return err
	}

	j := &jwkClaims{}
	if err := json.Unmarshal(buf, j); err != nil {
		return err
	}

	c.jwkClaim = jwt.MapClaims{}

	jwkClaim := jwt.MapClaims{
		"crv": j.CRV,
		"kid": j.KID,
		"kty": j.KTY,
		"x":   j.X,
		"y":   j.Y,
		"d":   j.D,
	}
	c.jwkClaim["jwk"] = jwkClaim

	return nil
}
