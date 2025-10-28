package openid4vp

import (
	"context"
	"net/url"
	"time"
)

type Context struct {
	Nonce                string         `json:"nonce" bson:"nonce" validate:"required"`
	ID                   string         `json:"id" bson:"id" validate:"required"`
	AuthorizationRequest *RequestObject `json:"authorization" bson:"authorization" validate:"required"`
}

func (r *RequestObject) CreateAuthorizationRequestURI(ctx context.Context, verifierHost, id string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	u, err := url.JoinPath("openid4vp", "cb")
	if err != nil {
		return "", err
	}

	uu, err := url.Parse(u)
	if err != nil {
		return "", err
	}

	q := uu.Query()
	q.Set("client_id", r.ClientID)

	requestObjectURL, err := r.createRequestURI(ctx, verifierHost, id)
	if err != nil {
		return "", err
	}

	q.Set("requestURI", requestObjectURL)
	uu.RawQuery = q.Encode()

	return uu.String(), nil
}

func (r *RequestObject) createRequestURI(ctx context.Context, verifierHost, id string) (string, error) {
	_, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	requestObjectURL, err := url.JoinPath(verifierHost, "verification", "request-object")
	if err != nil {
		return "", err
	}
	requestObjectURLQuery, err := url.Parse(requestObjectURL)
	if err != nil {
		return "", err
	}

	q := requestObjectURLQuery.Query()
	q.Set("id", id)
	requestObjectURLQuery.RawQuery = q.Encode()

	return requestObjectURLQuery.String(), nil
}
