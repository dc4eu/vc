package openid4vp

import (
	"context"
	"net/url"
	"time"
)

func (r *RequestObject) CreateAuthorizationRequestURI(ctx context.Context, verifierHost, id string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	u := url.URL{
		Scheme: "openid4vp",
		Path:   "cb",
	}

	q := u.Query()
	q.Set("client_id", r.ClientID)

	requestObjectURL, err := r.createRequestURI(ctx, verifierHost, id)
	if err != nil {
		return "", err
	}

	q.Set("requestURI", requestObjectURL)
	u.RawQuery = q.Encode()

	return u.String(), nil
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
