package apiv1

import (
	"context"
	"vc/pkg/model"

	"github.com/golang-jwt/jwt/v5"
)

type VerificationRequestObjectRequest struct {
	ID string `form:"id" uri:"id"`
	//SessionID string `json:"-"`
}

func (c *Client) VerificationRequestObject(ctx context.Context, req *VerificationRequestObjectRequest) (string, error) {
	c.log.Debug("Verification request object", "req", req)

	// TODO(masv): should request-object-id be associated with a particular session?
	authorizationContext, err := c.db.AuthorizationContextColl.Get(ctx, &model.AuthorizationContext{
		RequestObjectID: req.ID,
	})
	if err != nil {
		c.log.Error(err, "failed to get authorization context")
		return "", err
	}

	res := c.requestObjectCache.Get(authorizationContext.RequestObjectID)

	signedJWT, err := res.Value().Sign(jwt.SigningMethodRS256, c.issuerMetadataSigningKey, c.issuerMetadataSigningChain)
	if err != nil {
		c.log.Error(err, "failed to sign authorization request")
		return "", err
	}

	c.log.Debug("Signed JWT", "jwt", signedJWT)

	return signedJWT, nil
}

func (c *Client) VerificationDirectPost(ctx context.Context) (string, error) {
	c.log.Debug("Verification direct post")

	return "", nil
}
