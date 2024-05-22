package apiv1

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"
	"vc/pkg/logger"
	"vc/pkg/trace"
)

// VCBaseClient Defines a base http(s) client for a service in the vc (verifiable credential) domain (for example: apigw, datastore, etc.)
//
//	request: json
//	response: json
type VCBaseClient struct {
	serviceName string
	baseUrl     string
	logger      *logger.Log
	httpClient  *http.Client
	tp          *trace.Tracer
}

func NewClient(serviceName string, baseUrl string, tracer *trace.Tracer, logger *logger.Log) *VCBaseClient {
	client := &VCBaseClient{
		serviceName: serviceName,
		baseUrl:     baseUrl,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: logger,
		tp:     tracer,
	}
	return client
}

func (c *VCBaseClient) DoPostJSON(endpoint string, reqBody any) (*map[string]any, error) {
	url := c.url(endpoint)

	reqBodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBodyJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer c.closeBody(resp)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jsonResp map[string]any
	if err := json.Unmarshal(body, &jsonResp); err != nil {
		return nil, err
	}

	return &jsonResp, nil
}

func (c *VCBaseClient) DoGetJSON(endpoint string) (*map[string]any, error) {
	url := c.url(endpoint)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer c.closeBody(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jsonResp map[string]any
	if err := json.Unmarshal(body, &jsonResp); err != nil {
		return nil, err
	}

	return &jsonResp, nil
}

func (c *VCBaseClient) url(path string) string {
	return c.baseUrl + path
}

func (c *VCBaseClient) closeBody(resp *http.Response) {
	func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			c.logger.Error(err, "could not close response body")
		}
	}(resp.Body)
}
