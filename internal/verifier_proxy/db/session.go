package db

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// SessionStatus represents the status of an OIDC session
type SessionStatus string

const (
	SessionStatusPending              SessionStatus = "pending"
	SessionStatusAwaitingPresentation SessionStatus = "awaiting_presentation"
	SessionStatusCodeIssued           SessionStatus = "code_issued"
	SessionStatusTokenIssued          SessionStatus = "token_issued"
	SessionStatusCompleted            SessionStatus = "completed"
	SessionStatusExpired              SessionStatus = "expired"
	SessionStatusError                SessionStatus = "error"
)

// Session represents an OIDC/OpenID4VP session
type Session struct {
	ID        string        `bson:"_id" json:"id"`
	CreatedAt time.Time     `bson:"created_at" json:"created_at"`
	ExpiresAt time.Time     `bson:"expires_at" json:"expires_at"`
	Status    SessionStatus `bson:"status" json:"status"`

	// OIDC request from RP
	OIDCRequest OIDCRequest `bson:"oidc_request" json:"oidc_request"`

	// OpenID4VP interaction with wallet
	OpenID4VP OpenID4VPSession `bson:"openid4vp" json:"openid4vp"`

	// Verified claims from wallet
	VerifiedClaims map[string]any `bson:"verified_claims" json:"verified_claims"`

	// Tokens
	Tokens TokenSet `bson:"tokens" json:"tokens"`
}

// OIDCRequest represents the initial OIDC request from the RP
type OIDCRequest struct {
	ClientID            string   `bson:"client_id" json:"client_id"`
	RedirectURI         string   `bson:"redirect_uri" json:"redirect_uri"`
	Scope               string   `bson:"scope" json:"scope"`
	State               string   `bson:"state" json:"state"`
	Nonce               string   `bson:"nonce" json:"nonce"`
	CodeChallenge       string   `bson:"code_challenge,omitempty" json:"code_challenge,omitempty"`
	CodeChallengeMethod string   `bson:"code_challenge_method,omitempty" json:"code_challenge_method,omitempty"`
	ResponseType        string   `bson:"response_type" json:"response_type"`
	ResponseMode        string   `bson:"response_mode,omitempty" json:"response_mode,omitempty"`
	Display             string   `bson:"display,omitempty" json:"display,omitempty"`
	Prompt              string   `bson:"prompt,omitempty" json:"prompt,omitempty"`
	MaxAge              int      `bson:"max_age,omitempty" json:"max_age,omitempty"`
	UILocales           []string `bson:"ui_locales,omitempty" json:"ui_locales,omitempty"`
	IDTokenHint         string   `bson:"id_token_hint,omitempty" json:"id_token_hint,omitempty"`
	LoginHint           string   `bson:"login_hint,omitempty" json:"login_hint,omitempty"`
	ACRValues           []string `bson:"acr_values,omitempty" json:"acr_values,omitempty"`
	ShowCredentialDetails bool   `bson:"show_credential_details,omitempty" json:"show_credential_details,omitempty"` // User requested to view credential before authorization
}

// OpenID4VPSession represents the OpenID4VP interaction
type OpenID4VPSession struct {
	PresentationDefinition any    `bson:"presentation_definition,omitempty" json:"presentation_definition,omitempty"`
	RequestObjectNonce     string `bson:"request_object_nonce,omitempty" json:"request_object_nonce,omitempty"`
	VPToken                string `bson:"vp_token,omitempty" json:"vp_token,omitempty"`
	PresentationSubmission any    `bson:"presentation_submission,omitempty" json:"presentation_submission,omitempty"`
	WalletID               string `bson:"wallet_id,omitempty" json:"wallet_id,omitempty"`
}

// TokenSet represents the OAuth2/OIDC tokens
type TokenSet struct {
	AuthorizationCode     string    `bson:"authorization_code,omitempty" json:"authorization_code,omitempty"`
	AuthorizationCodeUsed bool      `bson:"authorization_code_used" json:"authorization_code_used"`
	CodeExpiresAt         time.Time `bson:"code_expires_at,omitempty" json:"code_expires_at,omitempty"`
	AccessToken           string    `bson:"access_token,omitempty" json:"access_token,omitempty"`
	AccessTokenExpiresAt  time.Time `bson:"access_token_expires_at,omitempty" json:"access_token_expires_at,omitempty"`
	IDToken               string    `bson:"id_token,omitempty" json:"id_token,omitempty"`
	RefreshToken          string    `bson:"refresh_token,omitempty" json:"refresh_token,omitempty"`
	RefreshTokenExpiresAt time.Time `bson:"refresh_token_expires_at,omitempty" json:"refresh_token_expires_at,omitempty"`
	TokenType             string    `bson:"token_type,omitempty" json:"token_type,omitempty"`
}

// SessionCollection provides database operations for sessions
type SessionCollection struct {
	Service    *Service
	collection *mongo.Collection
}

// Create creates a new session
func (c *SessionCollection) Create(ctx context.Context, session *Session) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:sessions:create")
	defer span.End()

	_, err := c.collection.InsertOne(ctx, session)
	if err != nil {
		c.Service.log.Error(err, "Failed to create session")
		return err
	}

	return nil
}

// GetByID retrieves a session by ID
func (c *SessionCollection) GetByID(ctx context.Context, id string) (*Session, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:sessions:get_by_id")
	defer span.End()

	var session Session
	err := c.collection.FindOne(ctx, bson.M{"_id": id}).Decode(&session)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		c.Service.log.Error(err, "Failed to get session")
		return nil, err
	}

	return &session, nil
}

// GetByAuthorizationCode retrieves a session by authorization code
func (c *SessionCollection) GetByAuthorizationCode(ctx context.Context, code string) (*Session, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:sessions:get_by_code")
	defer span.End()

	var session Session
	err := c.collection.FindOne(ctx, bson.M{"tokens.authorization_code": code}).Decode(&session)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		c.Service.log.Error(err, "Failed to get session by code")
		return nil, err
	}

	return &session, nil
}

// GetByAccessToken retrieves a session by access token
func (c *SessionCollection) GetByAccessToken(ctx context.Context, token string) (*Session, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:sessions:get_by_access_token")
	defer span.End()

	var session Session
	err := c.collection.FindOne(ctx, bson.M{"tokens.access_token": token}).Decode(&session)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		c.Service.log.Error(err, "Failed to get session by access token")
		return nil, err
	}

	return &session, nil
}

// Update updates a session
func (c *SessionCollection) Update(ctx context.Context, session *Session) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:sessions:update")
	defer span.End()

	_, err := c.collection.ReplaceOne(ctx, bson.M{"_id": session.ID}, session)
	if err != nil {
		c.Service.log.Error(err, "Failed to update session")
		return err
	}

	return nil
}

// Delete deletes a session
func (c *SessionCollection) Delete(ctx context.Context, id string) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:sessions:delete")
	defer span.End()

	_, err := c.collection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		c.Service.log.Error(err, "Failed to delete session")
		return err
	}

	return nil
}

// MarkCodeAsUsed marks an authorization code as used
func (c *SessionCollection) MarkCodeAsUsed(ctx context.Context, id string) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:sessions:mark_code_used")
	defer span.End()

	_, err := c.collection.UpdateOne(
		ctx,
		bson.M{"_id": id},
		bson.M{"$set": bson.M{"tokens.authorization_code_used": true}},
	)
	if err != nil {
		c.Service.log.Error(err, "Failed to mark code as used")
		return err
	}

	return nil
}
