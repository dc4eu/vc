package apiv1

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
	"vc/pkg/openid4vp"
	"vc/pkg/sdjwt3"

	"github.com/skip2/go-qrcode"
)

type CredentialOffer struct {
	Name string
	ID   string
	QRs  map[string]openid4vp.QRReply
}

type GetAllCredentialOffersReply map[string]CredentialOffer

func (c *Client) GetAllCredentialOffers(ctx context.Context) (*GetAllCredentialOffersReply, error) {
	reply := make(GetAllCredentialOffersReply)

	for credentialKey, credential := range c.cfg.CredentialConstructor {
		if err := credential.LoadFile(ctx); err != nil {
			continue
		}

		vctm := credential.VCTM

		data := map[string]any{
			"credential_issuer":            c.cfg.APIGW.CredentialOffers.IssuerURL,
			"credential_configuration_ids": []string{vctm.VCT},
			"grants": map[string]any{
				"authorization_code": map[string]any{},
			},
		}

		jsonBytes, err := json.Marshal(data)
		if err != nil {
			panic(err)
		}

		UrlQueryString := url.PathEscape(string(jsonBytes))

		qrs := make(map[string]openid4vp.QRReply)

		for walletLabel, walletURL := range c.cfg.APIGW.CredentialOffers.Wallets {
			url := walletURL + "?credential_offer=" + UrlQueryString

			qr, err := openid4vp.GenerateQR(url, qrcode.Medium, 256)
			if err != nil {
				return nil, err
			}

			qrs[walletLabel] = *qr
		}

		reply[credentialKey] = CredentialOffer{
			Name: vctm.Name,
			ID:   vctm.VCT,
			QRs:  qrs,
		}
	}

	return &reply, nil
}

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
