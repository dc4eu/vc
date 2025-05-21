package apiv1

import (
	"context"
	"errors"
	"net/http"
	"vc/internal/gen/status/apiv1_status"
	"vc/pkg/model"
	"vc/pkg/vcclient"
)

// Status return status for each ladok instance
func (c *Client) Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	probes := model.Probes{}

	status := probes.Check("portal")

	return status, nil
}

func (c *Client) GetUserCredentialOffers(ctx context.Context, req *vcclient.LoginPIDUserRequest) (*model.SearchDocumentsReply, error) {
	loginPIDUserReply, response, err := c.vcClient.User.LoginPIDUser(ctx, req)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK || loginPIDUserReply == nil || !loginPIDUserReply.Grant {
		return nil, errors.New("not authorized")
	}

	identity := loginPIDUserReply.Identity
	//TODO: komplettera searchRequest med birth_place + nationality när issuer och bootstrapdata anpassat. Komplettera även sökimpl för att kunna söka med dessa samt bestäm vad utfall av sök ska bli om man skickar in ex. bara en landskod som matchar men man har dubbla medborgarskap
	searchRequest := &model.SearchDocumentsRequest{
		Limit:      100,
		FamilyName: identity.FamilyName,
		GivenName:  identity.GivenName,
		BirthDate:  identity.BirthDate,
		Fields:     []string{"meta.document_id", "meta.authentic_source", "meta.document_type", "meta.collect.id", "identities", "qr"},
	}
	searchReply, httpResponse, err := c.apigwClient.Document.Search(ctx, searchRequest)
	if err != nil {
		return nil, err
	}
	if httpResponse.StatusCode != http.StatusOK {
		return nil, errors.New(httpResponse.Status)
	}
	return searchReply, nil
}

// SearchDocuments search for documents
func (c *Client) SearchDocuments(ctx context.Context, req *model.SearchDocumentsRequest) (*model.SearchDocumentsReply, error) {
	reply, httpResponse, err := c.apigwClient.Document.Search(ctx, req)
	if err != nil {
		return nil, err
	}
	if httpResponse.StatusCode != http.StatusOK {
		return nil, errors.New(httpResponse.Status)
	}
	return reply, nil
}
