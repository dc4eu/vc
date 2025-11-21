package openid4vp

import (
	"encoding/json"
	"fmt"
	"net/url"
)

// DirectPostResponse is the response from the direct_post endpoint (Section 8.2)
type DirectPostResponse struct {
	RedirectURI string `json:"redirect_uri,omitempty"` // Optional per spec
}

// DirectPostJWTResponse represents response_mode=direct_post.jwt (Section 8.3.1)
type DirectPostJWTResponse struct {
	Response string `json:"response"` // Encrypted JWT containing the Authorization Response
}

// BuildDirectPostURL creates a URL-encoded form data string for direct_post
func BuildDirectPostURL(baseURL string, response *ResponseParameters) (string, error) {
	data := url.Values{}

	if response.VPToken != "" {
		data.Set("vp_token", response.VPToken)
	}
	if response.State != "" {
		data.Set("state", response.State)
	}
	if response.Code != "" {
		data.Set("code", response.Code)
	}
	if response.IDToken != "" {
		data.Set("id_token", response.IDToken)
	}
	if response.PresentationSubmission != nil {
		psJSON, err := json.Marshal(response.PresentationSubmission)
		if err != nil {
			return "", fmt.Errorf("failed to marshal presentation_submission: %w", err)
		}
		data.Set("presentation_submission", string(psJSON))
	}

	return baseURL + "?" + data.Encode(), nil
}
