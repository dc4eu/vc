package vcclient

import (
	"bytes"
	"encoding/json"
	"github.com/gin-gonic/gin"
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

// Defines a base http(s) client for a service in the vc (verifiable credential) domain (for example: apigw, datastore, etc.)
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

	requestBodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBodyJSON))
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

func (vcbc *VCBaseClient) DoGetJSON(c *gin.Context, endpoint string) {
	url := vcbc.url(endpoint)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error creating new http(s) request": err.Error()})
	}
	req.Header.Set("Accept", ACCEPT)

	resp, err := vcbc.httpClient.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error request": err.Error()})
	}

	defer closeBody(resp)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error read response": err.Error()})
		return
	}

	var jsonResp map[string]interface{}
	if err := json.Unmarshal(body, &jsonResp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error Unmarshal response to json": err.Error()})
		return
	}

	c.JSON(resp.StatusCode, jsonResp)

}

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
