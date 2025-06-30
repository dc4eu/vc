package apiv1

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"time"
	"vc/pkg/sdjwt3"
)

type GetVCTMFromScopeRequest struct {
	Scope string `validate:"required"`
}

func (c *Client) GetVCTMFromScope(ctx context.Context, req *GetVCTMFromScopeRequest) (*sdjwt3.VCTM, error) {
	credentialConstructor, ok := c.cfg.CredentialConstructor[req.Scope]
	if !ok {
		err := errors.New("scope is not valid credential")
		return nil, err
	}

	if err := credentialConstructor.LoadFile(ctx); err != nil {
		return nil, err
	}

	vctm := credentialConstructor.VCTM

	return vctm, nil
}

type SVGTemplateRequest struct {
	VCTM *sdjwt3.VCTM
}

type SVGTemplateReply struct {
	Template  string               `json:"template"`
	SVGClaims map[string][]*string `json:"svg_claims"`
}

func (c *Client) SVGTemplateReply(ctx context.Context, req *SVGTemplateRequest) (*SVGTemplateReply, error) {
	svgTemplateURI := req.VCTM.Display[0].Rendering.SVGTemplates[0].URI

	if c.svgTemplateCache.Has(svgTemplateURI) {
		cachedSvgTemplateReply := c.svgTemplateCache.Get(svgTemplateURI)

		cachedReply := cachedSvgTemplateReply.Value()

		return &cachedReply, nil
	}

	c.log.Debug("SVG template not available in cache, fetching from origin")

	response, err := http.Get(svgTemplateURI)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		err := errors.New("non ok response code from svg template origin")
		return nil, err
	}

	responseData, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	template := base64.StdEncoding.EncodeToString([]byte(responseData))

	svgClaims := make(map[string][]*string)

	for _, claim := range req.VCTM.Claims {
		if claim.SVGID != "" {
			svgClaims[claim.SVGID] = claim.Path
		}
	}

	reply := &SVGTemplateReply{
		Template:  template,
		SVGClaims: svgClaims,
	}

	c.svgTemplateCache.Set(svgTemplateURI, *reply, 2*time.Hour)

	return reply, nil
}
