package apiv1

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
	"vc/pkg/openid4vci"
	"vc/pkg/openid4vp"
	"vc/pkg/sdjwt3"

	"github.com/skip2/go-qrcode"
)

type GetAllCredentialOffersCredential struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type GetAllCredentialOffersReply struct {
	Credentials map[string]GetAllCredentialOffersCredential `json:"credentials"`
	Wallets     map[string]string                           `json:"wallets"`
}

func (c *Client) GetAllCredentialOffers(ctx context.Context) (*GetAllCredentialOffersReply, error) {
	credentials := make(map[string]GetAllCredentialOffersCredential)

	for key, credential := range c.cfg.CredentialConstructor {
		if err := credential.LoadFile(ctx); err != nil {
			continue
		}

		vctm := credential.VCTM

		credentials[key] = GetAllCredentialOffersCredential{
			Name:        vctm.Name,
			Description: vctm.Description,
		}

	}

	wallets := make(map[string]string)

	for key, wallet := range c.cfg.APIGW.CredentialOffers.Wallets {
		wallets[key] = wallet.Label
	}

	reply := &GetAllCredentialOffersReply{
		Credentials: credentials,
		Wallets:     wallets,
	}

	return reply, nil
}

type CredentialOfferRequest struct {
	Scope    string `json:"scope" uri:"scope" binding:"required"`
	WalletID string `json:"wallet_id" uri:"wallet_id" binding:"required"`
}

type CredentialOfferReply struct {
	Name string            `json:"name" validate:"required"`
	ID   string            `json:"id" validate:"required"`
	QR   openid4vp.QRReply `json:"qr" validate:"required"`
}

func (c *Client) CredentialOffer(ctx context.Context, req *CredentialOfferRequest) (*CredentialOfferReply, error) {
	vctmReq := &GetVCTMFromScopeRequest{
		Scope: req.Scope,
	}

	vctm, err := c.GetVCTMFromScope(ctx, vctmReq)
	if err != nil {
		return nil, err
	}

	offerParams := openid4vci.CredentialOfferParameters{
		CredentialIssuer:           c.cfg.APIGW.CredentialOffers.IssuerURL,
		CredentialConfigurationIDs: []string{vctm.VCT},
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

	baseURL, err := url.Parse(wallet.RedirectURI)
	if err != nil {
		return nil, err
	}

	url := baseURL.String() + "?" + credentialOffer.String()

	qr, err := openid4vp.GenerateQR(url, qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}

	// Since we're using the qr method in a place it wasn't really
	// intended for, blank any possible data we don't want sent to
	// the client.
	qr.RequestURI = ""
	qr.SessionID = ""
	qr.ClientID = ""

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
	VCTM *sdjwt3.VCTM `json:"-"`
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


	reply := &SVGTemplateReply{
		Template: template,
	}

	c.svgTemplateCache.Set(svgTemplateURI, *reply, 2*time.Hour)

	return reply, nil
}
