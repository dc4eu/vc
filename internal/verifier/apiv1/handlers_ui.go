package apiv1

import (
	"context"
	"vc/pkg/model"
	"vc/pkg/openid4vp"

	"github.com/google/uuid"
)

func (c *Client) UICredentialInfo(ctx context.Context) (map[string]*model.CredentialConstructor, error) {
	reply := c.cfg.CredentialConstructor

	for _, constructor := range reply {
		constructor.AuthMethod = ""
		constructor.VCTMFilePath = ""
		constructor.VCTM = nil
	}

	return reply, nil
}

type UIPresentationDefinitionRequest struct {
	DCQLQuery *openid4vp.DCQL `json:"dcql_query" validate:"required"`
}

type UIPresentationDefinitionReply struct {
	AuthorizationRequest string `json:"authorization_request"`
	QRCode               string `json:"qr_code"`
}

// UIPresentationDefinition handles the UI presentation definition request, reply Authorization Request that contains a Request URI and DCQL query, the latter for UI to show.
func (c *Client) UIPresentationDefinition(ctx context.Context, req *UIPresentationDefinitionRequest) (*UIPresentationDefinitionReply, error) {
	c.log.Debug("uIPresentationDefinition", "dcql_query", req.DCQLQuery)

	id := uuid.NewString()
	nonce := uuid.NewString()
	state := uuid.NewString()

	context := &openid4vp.Context{
		Nonce: nonce,
		ID:    id,
		AuthorizationRequest: &openid4vp.RequestObject{
			ISS:          "vc-interop-3.sunet.se",
			AUD:          "https://self-issued.me/v2",
			IAT:          0,
			ResponseType: "vp_token",
			ClientID:     "x509_san_dns:vc-interop-3.sunet.se",
			RedirectURI:  "",
			Scope:        "",
			State:        state,
			Nonce:        nonce,
			ResponseMode: "direct_post.jwt",
			DCQLQuery:    req.DCQLQuery,
			ClientMetadata: &openid4vp.ClientMetadata{
				JWKS:                                &openid4vp.Keys{},
				EncryptedResponseEncValuesSupported: []string{},
				VPFormatsSupported:                  map[string]map[string][]string{},
				VPFormats: map[string]map[string][]string{
					"vc+sd-jwt": {
						"sd-jwt_alg_values": {"ES256"},
						"kb-jwt_alg_values": {"ES256"}},
				},
				AuthorizationSignedResponseALG:    "",
				AuthorizationEncryptedResponseALG: "ECDH-ES",
				AuthorizationEncryptedResponseENC: "A256GCM",
			},
			RequestURIMethod: "",
			TransactionData:  []openid4vp.TransactionData{},
			VerifierInfo:     []openid4vp.VerifierInfo{},
			ResponseURI:      "https://vc-interop-3.sunet.se:444/verification/direct_post",
		},
	}

	if err := c.db.ContextColl.Save(ctx, context); err != nil {
		return nil, err
	}

	reply := &UIPresentationDefinitionReply{}

	var err error
	reply.AuthorizationRequest, err = context.AuthorizationRequest.CreateAuthorizationRequestURI(ctx, "https://vc-interop-3.sunet.se:444", id)
	if err != nil {
		return nil, err
	}

	reply.QRCode, err = openid4vp.GenerateQRV2(ctx, reply.AuthorizationRequest)
	if err != nil {
		return nil, err
	}

	return reply, nil
}

type GetRequestObjectRequest struct {
	ID string `form:"id" validate:"required"`
}

func (c *Client) GetRequestObject(ctx context.Context, req *GetRequestObjectRequest) (map[string]any, error) {
	c.log.Debug("getRequestObject", "id", req.ID)

	return nil, nil
}
