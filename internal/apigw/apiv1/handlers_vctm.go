package apiv1

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
	"vc/pkg/openid4vci"
	"vc/pkg/openid4vp"
	"vc/pkg/sdjwtvc"

	"github.com/skip2/go-qrcode"
)

// UICredentialOffers provides data for UI /offer endpoint
func (c *Client) UICredentialOffers(ctx context.Context) (*CredentialOfferLookupMetadata, error) {
	return c.CredentialOfferLookupMetadata, nil
}

type UICredentialOfferRequest struct {
	Scope    string `json:"scope" uri:"scope" binding:"required"`
	WalletID string `json:"wallet_id" uri:"wallet_id" binding:"required"`
}

type CredentialOfferReply struct {
	Name string            `json:"name" validate:"required"`
	ID   string            `json:"id" validate:"required"`
	QR   openid4vp.QRReply `json:"qr" validate:"required"`
}

func (c *Client) UICreateCredentialOffer(ctx context.Context, req *UICredentialOfferRequest) (*CredentialOfferReply, error) {
	vctmReq := &GetVCTMFromScopeRequest{
		Scope: req.Scope,
	}

	vctm, err := c.GetVCTMFromScope(ctx, vctmReq)
	if err != nil {
		return nil, err
	}

	offerParams := openid4vci.CredentialOfferParameters{
		CredentialIssuer:           c.cfg.APIGW.CredentialOffers.IssuerURL,
		CredentialConfigurationIDs: []string{req.Scope},
		Grants: map[string]any{
			"authorization_code": map[string]any{},
		},
	}

	credentialOffer, err := offerParams.CredentialOffer()
	if err != nil {
		return nil, err
	}

	wallet, ok := c.cfg.APIGW.CredentialOffers.Wallets[req.WalletID]
	if !ok {
		err := errors.New("invalid wallet id")
		return nil, err
	}

	credentialOfferURL := fmt.Sprintf("%s?%s", wallet.RedirectURI, credentialOffer)

	u, err := url.Parse(credentialOfferURL)
	if err != nil {
		c.log.Error(err, "failed to parse credential offer URL")
		return nil, err
	}

	qr, err := openid4vp.GenerateQR(u, qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}

	reply := &CredentialOfferReply{
		Name: vctm.Name,
		ID:   vctm.VCT,
		QR:   *qr,
	}

	return reply, nil
}

type GetVCTMFromScopeRequest struct {
	Scope string `validate:"required"`
}

func (c *Client) GetVCTMFromScope(ctx context.Context, req *GetVCTMFromScopeRequest) (*sdjwtvc.VCTM, error) {
	credentialConstructor, ok := c.cfg.CredentialConstructor[req.Scope]
	if !ok {
		err := errors.New("scope is not valid credential")
		return nil, err
	}

	if err := credentialConstructor.LoadVCTMetadata(ctx, req.Scope); err != nil {
		return nil, err
	}

	vctm := credentialConstructor.VCTM

	return vctm, nil
}

type SVGTemplateRequest struct {
	VCTM *sdjwtvc.VCTM `json:"-"`
}

type SVGTemplateReply struct {
	Template string `json:"template"`
}

func (c *Client) SVGTemplateReply(ctx context.Context, req *SVGTemplateRequest) (*SVGTemplateReply, error) {
	svgTemplateURI := req.VCTM.Display[0].Rendering.SVGTemplates[0].URI

	if c.svgTemplateCache.Has(svgTemplateURI) {
		cachedSvgTemplateReply := c.svgTemplateCache.Get(svgTemplateURI)

		cachedReply := cachedSvgTemplateReply.Value()

		return &cachedReply, nil
	}

	c.log.Debug("SVG template not available in cache, fetching from origin")

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, svgTemplateURI, nil)
	if err != nil {
		return nil, err
	}

	response, err := http.DefaultClient.Do(httpReq)
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

	reply := &SVGTemplateReply{
		Template: template,
	}

	c.svgTemplateCache.Set(svgTemplateURI, *reply, 2*time.Hour)

	return reply, nil
}
