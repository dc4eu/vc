package datastoreclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
	"vc/pkg/helpers"
)

// Client is the client
type Client struct {
	httpClient *http.Client
	url        string

	DocumentService *documentService
	IdentityService *identityService
}

// Config is the configuration for the client
type Config struct {
	URL string `validate:"required"`
}

// New creates a new client
func New(config *Config) (*Client, error) {
	if err := helpers.CheckSimple(config); err != nil {
		return nil, err
	}
	c := &Client{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		url: config.URL,
	}

	c.DocumentService = &documentService{client: c, service: "api/v1/document"}
	c.IdentityService = &identityService{client: c, service: "api/v1/identity"}

	return c, nil
}

// NewRequest make a new request
func (c *Client) newRequest(ctx context.Context, method, path string, body any) (*http.Request, error) {
	rel, err := url.Parse(path)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(c.url)
	if err != nil {
		return nil, err
	}
	url := u.ResolveReference(rel)

	fmt.Println("url", url.String())

	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		err = json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url.String(), buf)
	if err != nil {
		return nil, err
	}

	fmt.Println("req", req)

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// Do does the new request
func (c *Client) do(ctx context.Context, req *http.Request, reply any) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if err := checkResponse(resp); err != nil {
		buf := &bytes.Buffer{}
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(buf.Bytes(), err); err != nil {
			return nil, err
		}
		return nil, err
	}

	r := struct {
		Data any `json:"data"`
	}{
		Data: reply,
	}

	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		fmt.Println("err", err)
		return nil, err
	}

	return resp, nil
}

func checkResponse(r *http.Response) error {
	switch r.StatusCode {
	case 200, 201, 202, 204, 304:
		return nil
	case 500:
		return ErrInvalidRequest
	case 401:
		return ErrNotAllowedRequest
	}

	return ErrInvalidRequest
}

func (c *Client) call(ctx context.Context, method, url string, body, reply any) (*http.Response, error) {
	request, err := c.newRequest(
		ctx,
		method,
		url,
		body,
	)
	if err != nil {
		return nil, err
	}

	resp, err := c.do(ctx, request, reply)
	if err != nil {
		return resp, err
	}

	fmt.Println("reply", reply)

	return resp, nil
}
