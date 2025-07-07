package apiv1

import (
	"context"
	"fmt"
	"net/url"
	"vc/pkg/model"
	"vc/pkg/pid"
	"vc/pkg/sdjwt3"
	"vc/pkg/vcclient"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func (c *Client) AddPIDUser(ctx context.Context, req *vcclient.AddPIDRequest) error {
	pid := pid.Document{
		Identity: req.Identity,
	}

	documentData, err := pid.Marshal()
	if err != nil {
		c.log.Error(err, "failed to marshal document data")
		return err
	}

	// build a new document
	uploadRequest := &UploadRequest{
		Meta: &model.MetaData{
			AuthenticSource:           req.Meta.AuthenticSource,
			DocumentVersion:           "1.0.0",
			DocumentType:              req.Meta.DocumentType,
			DocumentID:                fmt.Sprintf("generic.pid.%s", uuid.NewString()),
			RealData:                  false,
			Collect:                   &model.Collect{},
			Revocation:                &model.Revocation{},
			CredentialValidFrom:       0,
			CredentialValidTo:         0,
			DocumentDataValidationRef: "",
		},
		Identities: []model.Identity{*req.Identity},
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
		Username:        req.Username,
		Password:        string(passwordHash),
		Identity:        req.Identity,
		DocumentType:    req.Meta.DocumentType,
		AuthenticSource: req.Meta.AuthenticSource,
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

func (c *Client) LoginPIDUser(ctx context.Context, req *vcclient.LoginPIDUserRequest) error {
	c.log.Debug("LoginPIDUser called", "username", req.Username)
	user, err := c.db.VCUsersColl.GetUser(ctx, req.Username)
	if err != nil {
		return fmt.Errorf("username %s not found", req.Username)
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return fmt.Errorf("password mismatch for username %s", req.Username)
	}

	update := &model.AuthorizationContext{
		Identity:        user.Identity,
		DocumentType:    user.DocumentType,
		AuthenticSource: user.AuthenticSource,
	}
	// Update the authorization with the user identity
	if err := c.db.VCAuthorizationContextColl.AddIdentity(ctx, &model.AuthorizationContext{RequestURI: req.RequestURI}, update); err != nil {
		c.log.Error(err, "failed to add identity to authorization context")
		return err
	}

	return nil

}

func (c *Client) UserAuthenticSourceLookup(ctx context.Context, req *vcclient.UserAuthenticSourceLookupRequest) (*vcclient.UserAuthenticSourceLookupReply, error) {
	c.log.Debug("UserAuthenticSource called")

	if req.AuthenticSource == "" && req.SessionID != "" {
		c.log.Debug("userAuthenticSourceLookup called without authentic source, looking up by session ID", "session_id", req.SessionID)
		authorizationContext, err := c.db.VCAuthorizationContextColl.Get(ctx, &model.AuthorizationContext{
			SessionID: req.SessionID,
		})
		if err != nil {
			c.log.Error(err, "failed to get authorization context for authentic source lookup")
			return nil, err
		}

		docs := c.documentCache.Get(authorizationContext.SessionID).Value()
		if docs == nil {
			c.log.Error(nil, "no documents found in cache for session", "session_id", req.SessionID)
			return nil, fmt.Errorf("no documents found for session %s", req.SessionID)
		}

		authenticSources := []string{}

		for _, doc := range docs {
			authenticSources = append(authenticSources, doc.Meta.AuthenticSource)
		}

		reply := &vcclient.UserAuthenticSourceLookupReply{
			AuthenticSources: authenticSources,
		}

		return reply, nil

	} else if req.AuthenticSource != "" {
		c.log.Debug("userAuthenticSourceLookup called with authentic source", "authentic_source", req.AuthenticSource)
		if err := c.db.VCAuthorizationContextColl.SetAuthenticSource(ctx, &model.AuthorizationContext{SessionID: req.SessionID}, req.AuthenticSource); err != nil {
			c.log.Error(err, "failed to set authentic source")
			return nil, fmt.Errorf("failed to set authentic source %s: %w", req.AuthenticSource, err)
		}
	}

	return nil, nil
}

func (c *Client) UserLookup(ctx context.Context, req *vcclient.UserLookupRequest) (*vcclient.UserLookupReply, error) {
	c.log.Debug("UserLookup called")

	authorizationContext, err := c.db.VCAuthorizationContextColl.Get(ctx, &model.AuthorizationContext{
		RequestURI: req.RequestURI,
	})
	if err != nil {
		c.log.Error(err, "failed to get authorization for user", "request_uri", req.RequestURI)
	}

	c.log.Debug("LoginPIDUser", "auth", authorizationContext)

	redirectURL, err := url.Parse(authorizationContext.WalletURI)
	if err != nil {
		c.log.Error(err, "failed to parse redirect URI", "redirect_uri", authorizationContext.WalletURI)
		return nil, fmt.Errorf("failed to parse redirect URI %s: %w", authorizationContext.WalletURI, err)
	}

	redirectURL.RawQuery = url.Values{"code": {authorizationContext.Code}, "state": {authorizationContext.State}}.Encode()

	svgTemplateClaims := map[string]any{}

	switch req.AuthMethod {
	case model.AuthMethodBasic:
		user, err := c.db.VCUsersColl.GetUser(ctx, req.Username)
		if err != nil {
			c.log.Error(err, "failed to get user", "username", req.Username)
			return nil, fmt.Errorf("user %s not found: %w", req.Username, err)
		}

		svgTemplateClaims = map[string]any{
			"given_name":  user.Identity.GivenName,
			"family_name": user.Identity.FamilyName,
			"birth_date":  user.Identity.BirthDate,
			"expiry_date": user.Identity.ExpiryDate,
		}
	case model.AuthMethodPID:
		authorizationContext, err := c.db.VCAuthorizationContextColl.Get(ctx, &model.AuthorizationContext{VerifierResponseCode: req.ResponseCode})
		if err != nil {
			c.log.Error(err, "failed to get authorization context")
			return nil, err
		}

		docs := c.documentCache.Get(authorizationContext.SessionID).Value()
		if docs == nil {
			c.log.Error(nil, "no documents found in cache for session")
			return nil, fmt.Errorf("no documents found for session %s", authorizationContext.SessionID)
		}

		// TODO(masv): fix this monstrosity
		authenticSource := ""
		for _, doc := range docs {
			authenticSource = doc.Meta.AuthenticSource
			break
		}

		doc, ok := docs[authenticSource]
		if !ok {
			c.log.Error(nil, "no document found for authentic source")
			return nil, fmt.Errorf("no document found for authentic source %s", authorizationContext.AuthenticSource)
		}

		jsonPaths, err := req.VCTM.ClaimJSONPath()
		if err != nil {
			c.log.Error(err, "failed to get JSON paths from VCTM claims")
			return nil, err
		}

		svgTemplateClaims, err = sdjwt3.Filter(doc.DocumentData, jsonPaths.Displayable)
		if err != nil {
			c.log.Error(err, "failed to filter document data for SVG template claims")
			return nil, fmt.Errorf("failed to filter document data for SVG template claims")
		}

	default:
		return nil, fmt.Errorf("unsupported auth method for user lookup: %s", req.AuthMethod)
	}

	if err := c.db.VCAuthorizationContextColl.Consent(ctx, &model.AuthorizationContext{RequestURI: req.RequestURI}); err != nil {
		c.log.Error(err, "failed to consent for user", "username", req.Username)
		return nil, fmt.Errorf("failed to consent for user %s: %w", req.Username, err)
	}

	reply := &vcclient.UserLookupReply{
		SVGTemplateClaims: svgTemplateClaims,
		RedirectURL:       redirectURL.String(),
	}

	return reply, nil
}
