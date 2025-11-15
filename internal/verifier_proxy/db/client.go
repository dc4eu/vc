package db

import (
	"context"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// Client represents an OIDC client (Relying Party)
type Client struct {
	ClientID                string   `bson:"client_id" json:"client_id"`
	ClientSecretHash        string   `bson:"client_secret_hash,omitempty" json:"-"`
	RedirectURIs            []string `bson:"redirect_uris" json:"redirect_uris"`
	GrantTypes              []string `bson:"grant_types" json:"grant_types"`
	ResponseTypes           []string `bson:"response_types" json:"response_types"`
	TokenEndpointAuthMethod string   `bson:"token_endpoint_auth_method" json:"token_endpoint_auth_method"`
	AllowedScopes           []string `bson:"allowed_scopes" json:"allowed_scopes"`
	DefaultScopes           []string `bson:"default_scopes,omitempty" json:"default_scopes,omitempty"`
	SubjectType             string   `bson:"subject_type" json:"subject_type"` // "public" or "pairwise"
	JWKSUri                 string   `bson:"jwks_uri,omitempty" json:"jwks_uri,omitempty"`
	JWKS                    any      `bson:"jwks,omitempty" json:"jwks,omitempty"`
	RequirePKCE             bool     `bson:"require_pkce" json:"require_pkce"`
	RequireCodeChallenge    bool     `bson:"require_code_challenge" json:"require_code_challenge"`
}

// ClientCollection provides database operations for clients
type ClientCollection struct {
	Service    *Service
	collection *mongo.Collection
}

// GetByClientID retrieves a client by client ID
func (c *ClientCollection) GetByClientID(ctx context.Context, clientID string) (*Client, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:clients:get_by_client_id")
	defer span.End()

	var client Client
	err := c.collection.FindOne(ctx, bson.M{"client_id": clientID}).Decode(&client)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, nil
		}
		c.Service.log.Error(err, "Failed to get client")
		return nil, err
	}

	return &client, nil
}

// Create creates a new client
func (c *ClientCollection) Create(ctx context.Context, client *Client) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:clients:create")
	defer span.End()

	_, err := c.collection.InsertOne(ctx, client)
	if err != nil {
		c.Service.log.Error(err, "Failed to create client")
		return err
	}

	return nil
}

// Update updates a client
func (c *ClientCollection) Update(ctx context.Context, client *Client) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:clients:update")
	defer span.End()

	_, err := c.collection.ReplaceOne(ctx, bson.M{"client_id": client.ClientID}, client)
	if err != nil {
		c.Service.log.Error(err, "Failed to update client")
		return err
	}

	return nil
}

// Delete deletes a client
func (c *ClientCollection) Delete(ctx context.Context, clientID string) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:clients:delete")
	defer span.End()

	_, err := c.collection.DeleteOne(ctx, bson.M{"client_id": clientID})
	if err != nil {
		c.Service.log.Error(err, "Failed to delete client")
		return err
	}

	return nil
}
