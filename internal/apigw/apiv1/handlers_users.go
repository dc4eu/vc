package apiv1

import (
	"context"
	"fmt"
	"net/url"
	"vc/pkg/model"
	"vc/pkg/vcclient"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func (c *Client) AddPIDUser(ctx context.Context, req *vcclient.AddPIDRequest) error {
	documentData, err := req.Attributes.Marshal()
	if err != nil {
		c.log.Error(err, "failed to marshal document data")
		return err
	}

	// build a new document
	uploadRequest := &UploadRequest{
		Meta: &model.MetaData{
			AuthenticSource:           "Generic_PID_Issuer",
			DocumentVersion:           "1.0.0",
			DocumentType:              model.CredentialTypeUrnEudiPid1,
			DocumentID:                fmt.Sprintf("generic.pid.%s", uuid.NewString()),
			RealData:                  false,
			Collect:                   &model.Collect{},
			Revocation:                &model.Revocation{},
			CredentialValidFrom:       0,
			CredentialValidTo:         0,
			DocumentDataValidationRef: "",
		},
		Identities: []model.Identity{*req.Attributes},
		DocumentDisplay: &model.DocumentDisplay{
			Version: "1.0.0",
			Type:    "",
			DescriptionStructured: map[string]any{
				"en": "Generic PID Issuer",
			},
		},
		DocumentData:        documentData,
		DocumentDataVersion: "1.0.0",
	}

	// store user and password in the database before document is saved - to check constraints that the user not already exists
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	err = c.db.VCUsersColl.Save(ctx, &model.OAuthUsers{
		Username: req.Username,
		Password: string(passwordHash),
		Identity: req.Attributes,
	})
	if err != nil {
		c.log.Error(err, "failed to save user")
		return err
	}

	// store document
	if err := c.Upload(ctx, uploadRequest); err != nil {
		c.log.Error(err, "failed to upload document")
		return err
	}

	return nil
}

func (c *Client) LoginPIDUser(ctx context.Context, req *vcclient.LoginPIDUserRequest) (*vcclient.LoginPIDUserReply, error) {
	c.log.Debug("LoginPIDUser called", "username", req.Username)
	user, err := c.db.VCUsersColl.GetUser(ctx, req.Username)
	if err != nil {
		return nil, fmt.Errorf("username %s not found", req.Username)
	}

	reply := &vcclient.LoginPIDUserReply{}

	if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return reply, fmt.Errorf("password mismatch for username %s", req.Username)
	}

	if err := c.db.VCAuthorizationContextColl.Consent(ctx, &model.AuthorizationContext{RequestURI: req.RequestURI}); err != nil {
		c.log.Error(err, "failed to consent for user", "username", req.Username)
		return nil, fmt.Errorf("failed to consent for user %s: %w", req.Username, err)
	}

	authorizationContext, err := c.db.VCAuthorizationContextColl.Get(ctx, &model.AuthorizationContext{
		RequestURI: req.RequestURI,
	})
	if err != nil {
		c.log.Error(err, "failed to get authorization for user", "request_uri", req.RequestURI)
	}

	// Update the authorization with the user identity
	if err := c.db.VCAuthorizationContextColl.AddIdentity(ctx, req.RequestURI, user.Identity); err != nil {
		return nil, err
	}

	c.log.Debug("LoginPIDUser", "user", user, "auth", authorizationContext)

	redirectURL, err := url.Parse(authorizationContext.RedirectURI)
	if err != nil {
		c.log.Error(err, "failed to parse redirect URI", "redirect_uri", authorizationContext.RedirectURI)
		return nil, fmt.Errorf("failed to parse redirect URI %s: %w", authorizationContext.RedirectURI, err)
	}

	redirectURL.RawQuery = url.Values{"code": {authorizationContext.Code}, "state": {authorizationContext.State}}.Encode()

	reply.Grant = true
	reply.Identity = user.Identity
	reply.RedirectURL = redirectURL.String()

	return reply, nil
}
