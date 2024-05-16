package vcclient

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"
	"vc/pkg/logger"
	"vc/pkg/trace"
)

const (
	CONTENT_TYPE = "application/json"
	ACCEPT       = "application/json"
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

func New(serviceName string, baseUrl string, tracer *trace.Tracer, logger *logger.Log) *VCBaseClient {
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

func (vcbc *VCBaseClient) DoPostJSON(endpoint string, reqBody any) (*map[string]interface{}, error) {
	url := vcbc.url(endpoint)

	reqBodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBodyJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", CONTENT_TYPE)
	req.Header.Set("Accept", ACCEPT)

	resp, err := vcbc.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer closeBody(resp)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jsonResp map[string]interface{}
	if err := json.Unmarshal(body, &jsonResp); err != nil {
		return nil, err
	}

	return &jsonResp, nil
}

//func (vcbc *VCBaseClient) DoPostJSON[T any](endpoint string, reqBody any) (*T, error) {
//	url := vcbc.url(endpoint)
//
//	reqBodyJSON, err := json.Marshal(reqBody)
//	if err != nil {
//		return nil, err
//	}
//
//	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBodyJSON))
//	if err != nil {
//		return nil, err
//	}
//	req.Header.Set("Content-Type", CONTENT_TYPE)
//	req.Header.Set("Accept", ACCEPT)
//
//	resp, err := vcbc.httpClient.Do(req)
//	if err != nil {
//		return nil, err
//	}
//	defer resp.Body.Close()
//
//	// Check HTTP status code
//	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
//		return nil, fmt.Errorf("unexpected HTTP status: %s", resp.Status)
//	}
//
//	// Unmarshal into the generic type T
//	var jsonResp T
//	if err := json.NewDecoder(resp.Body).Decode(&jsonResp); err != nil {
//		return nil, err
//	}
//
//	return &jsonResp, nil
//}

func (vcbc *VCBaseClient) DoGetJSON(endpoint string) (*map[string]interface{}, error) {
	url := vcbc.url(endpoint)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", ACCEPT)

	resp, err := vcbc.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer closeBody(resp)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jsonResp map[string]interface{}
	if err := json.Unmarshal(body, &jsonResp); err != nil {
		return nil, err
	}

	return &jsonResp, nil
}

//func doGetJSON[T any](client *http.Client, url string) (*T, error) {
//	req, err := http.NewRequest("GET", url, nil)
//	if err != nil {
//		return nil, err
//	}
//	req.Header.Set("Accept", "application/json")
//
//	resp, err := client.Do(req)
//	if err != nil {
//		return nil, err
//	}
//	defer closeBody(resp)
//
//	body, err := io.ReadAll(resp.Body)
//	if err != nil {
//		return nil, err
//	}
//
//	var jsonResp T
//	if err := json.Unmarshal(body, &jsonResp); err != nil {
//		return nil, err
//	}
//
//	return &jsonResp, nil
//}
//
//func (vcbc *VCBaseClient) DoGetJSON[T any](endpoint string) (*T, error) {
//	url := vcbc.url(endpoint)
//	return doGetJSON[T](vcbc.httpClient, url)
//}

func (vcbc *VCBaseClient) url(path string) string {
	return vcbc.baseUrl + path
}

func closeBody(resp *http.Response) {
	func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			//TODO: what to do here, just log???
		}
	}(resp.Body)
}
