package db

import (
	"context"
	"vc/pkg/model"
)

// AuthorizationContextStore defines the interface for authorization context operations
type AuthorizationContextStore interface {
	Save(ctx context.Context, doc *model.AuthorizationContext) error
	Get(ctx context.Context, query *model.AuthorizationContext) (*model.AuthorizationContext, error)
	GetWithAccessToken(ctx context.Context, token string) (*model.AuthorizationContext, error)
	ForfeitAuthorizationCode(ctx context.Context, query *model.AuthorizationContext) (*model.AuthorizationContext, error)
	Consent(ctx context.Context, query *model.AuthorizationContext) error
	AddToken(ctx context.Context, code string, token *model.Token) error
	SetAuthenticSource(ctx context.Context, query *model.AuthorizationContext, authenticSource string) error
	AddIdentity(ctx context.Context, query *model.AuthorizationContext, input *model.AuthorizationContext) error
}

// SessionStore defines the interface for OIDC session operations
type SessionStore interface {
	Create(ctx context.Context, session *Session) error
	GetByID(ctx context.Context, id string) (*Session, error)
	GetByAuthorizationCode(ctx context.Context, code string) (*Session, error)
	GetByAccessToken(ctx context.Context, token string) (*Session, error)
	Update(ctx context.Context, session *Session) error
	Delete(ctx context.Context, id string) error
	MarkCodeAsUsed(ctx context.Context, id string) error
}

// ClientStore defines the interface for OIDC client operations
type ClientStore interface {
	GetByClientID(ctx context.Context, clientID string) (*Client, error)
	Create(ctx context.Context, client *Client) error
	Update(ctx context.Context, client *Client) error
	Delete(ctx context.Context, clientID string) error
}

// Ensure concrete types implement the interfaces
var _ AuthorizationContextStore = (*AuthorizationContextColl)(nil)
var _ SessionStore = (*SessionCollection)(nil)
var _ ClientStore = (*ClientCollection)(nil)
