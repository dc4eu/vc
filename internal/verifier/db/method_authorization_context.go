package db

import (
	"context"
	"errors"
	"time"
	"vc/pkg/logger"
	"vc/pkg/model"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.opentelemetry.io/otel/codes"
)

// AuthorizationContextColl is the collection of vc authorization contexts
type AuthorizationContextColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

// NewAuthorizationContextColl creates a new VCAuthColl
func NewAuthorizationContextColl(ctx context.Context, collName string, service *Service, log *logger.Log) (*AuthorizationContextColl, error) {
	c := &AuthorizationContextColl{
		log:     log,
		Service: service,
	}

	c.Coll = c.Service.dbClient.Database("vc").Collection(collName)

	if err := c.createIndex(ctx); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *AuthorizationContextColl) createIndex(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:authorization_context:create_index")
	defer span.End()

	indexRequestURIUniq := mongo.IndexModel{
		Keys: bson.D{
			bson.E{Key: "session_id", Value: 1},
		},
		Options: options.Index().SetName("session_iduniq").SetUnique(true),
	}
	//indexCodeUniq := mongo.IndexModel{
	//	Keys: bson.D{
	//		bson.E{Key: "code", Value: 1},
	//	},
	//	Options: options.Index().SetName("oauth_code_uniq").SetUnique(true),
	//}

	_, err := c.Coll.Indexes().CreateMany(ctx, []mongo.IndexModel{
		indexRequestURIUniq,
		//indexCodeUniq,
	})
	if err != nil {
		return err
	}
	return nil
}

// Save saves one document to the generic collection
func (c *AuthorizationContextColl) Save(ctx context.Context, doc *model.AuthorizationContext) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:authorization_context:save")
	defer span.End()

	doc.SavedAt = time.Now().Unix()

	_, err := c.Coll.InsertOne(ctx, doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())

		return err
	}

	return nil
}

func (c *AuthorizationContextColl) Consent(ctx context.Context, query *model.AuthorizationContext) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:authorization_context:consent")
	defer span.End()

	filter := bson.M{}

	if query.RequestURI == "" {
		return errors.New("request_uri cannot be empty")
	}

	filter["request_uri"] = bson.M{"$eq": query.RequestURI}

	update := bson.M{
		"$set": bson.M{
			"consent":   true,
			"last_used": time.Now().Unix(),
		},
	}

	_, err := c.Coll.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	return nil
}

// ForfeitAuthorizationCode gets one authorization document and at the same time forfeits it by setting is_used to true
func (c *AuthorizationContextColl) ForfeitAuthorizationCode(ctx context.Context, query *model.AuthorizationContext) (*model.AuthorizationContext, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:authorization_context:forfeit_authorization_code")
	defer span.End()

	if query == nil {
		span.SetStatus(codes.Error, "query cannot be nil")
		return nil, errors.New("query cannot be nil")
	}

	filter := bson.M{}

	if query.RequestURI != "" {
		filter["request_uri"] = bson.M{"$eq": query.RequestURI}
	}

	if query.ClientID != "" {
		filter["client_id"] = bson.M{"$eq": query.ClientID}
	}

	if query.Code != "" {
		filter["code"] = bson.M{"$eq": query.Code}
	}

	if len(filter) == 0 {
		span.SetStatus(codes.Error, "query cannot be empty")
		return nil, errors.New("query cannot be empty")
	}

	update := bson.M{
		"$set": bson.M{
			"is_used":   true,
			"last_used": time.Now().Unix(),
		},
	}

	var doc model.AuthorizationContext
	if err := c.Coll.FindOneAndUpdate(ctx, filter, update).Decode(&doc); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return &doc, nil
}

// Get gets one authorization document
func (c *AuthorizationContextColl) Get(ctx context.Context, query *model.AuthorizationContext) (*model.AuthorizationContext, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:authorization_context:get")
	defer span.End()

	if query == nil {
		span.SetStatus(codes.Error, "query cannot be nil")
		return nil, errors.New("query cannot be nil")
	}

	filter := bson.M{}

	if query.SessionID != "" {
		filter["session_id"] = bson.M{"$eq": query.SessionID}
	}

	if query.RequestURI != "" {
		filter["request_uri"] = bson.M{"$eq": query.RequestURI}
	}

	if query.ClientID != "" {
		filter["client_id"] = bson.M{"$eq": query.ClientID}
	}

	if query.Code != "" {
		filter["code"] = bson.M{"$eq": query.Code}
	}

	if query.VerifierResponseCode != "" {
		filter["verifier_response_code"] = bson.M{"$eq": query.VerifierResponseCode}
	}

	if query.EphemeralEncryptionKeyID != "" {
		filter["ephemeral_encryption_key_id"] = bson.M{"$eq": query.EphemeralEncryptionKeyID}
	}

	if len(filter) == 0 {
		span.SetStatus(codes.Error, "query cannot be empty")
		return nil, errors.New("query cannot be empty")
	}

	var doc model.AuthorizationContext
	err := c.Coll.FindOne(ctx, filter).Decode(&doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return &doc, nil
}

func (c *AuthorizationContextColl) AddToken(ctx context.Context, code string, token *model.Token) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:authorization_context:add_token")
	defer span.End()

	if code == "" {
		span.SetStatus(codes.Error, "query cannot be empty")
		return errors.New("query cannot be empty")
	}

	filter := bson.M{
		"code": bson.M{"$eq": code},
	}

	update := bson.M{
		"$set": bson.M{
			"token": token,
		},
	}

	_, err := c.Coll.UpdateOne(ctx, filter, update)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}

func (c *AuthorizationContextColl) SetAuthenticSource(ctx context.Context, query *model.AuthorizationContext, authenticSource string) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:authorization_context:set_authentic_source")
	defer span.End()

	if authenticSource == "" {
		span.SetStatus(codes.Error, "authentic source cannot be empty")
		return errors.New("authentic source cannot be empty")
	}

	filter := bson.M{}

	if query.SessionID != "" {
		filter["session_id"] = bson.M{"$eq": query.SessionID}
	}

	if len(filter) == 0 {
		span.SetStatus(codes.Error, "query cannot be empty")
		return errors.New("query cannot be empty")
	}

	update := bson.M{
		"$set": bson.M{
			"authentic_source": authenticSource,
		},
	}

	_, err := c.Coll.UpdateOne(ctx, filter, update)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}

// GetWithAccessToken retrieves an authorization context by its access token
func (c AuthorizationContextColl) GetWithAccessToken(ctx context.Context, token string) (*model.AuthorizationContext, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:authorization_context:get_with_token")
	defer span.End()

	if token == "" {
		span.SetStatus(codes.Error, "token cannot be empty")
		return nil, errors.New("token cannot be empty")
	}

	filter := bson.M{
		"token.access_token": bson.M{"$eq": token},
	}

	var doc model.AuthorizationContext
	err := c.Coll.FindOne(ctx, filter).Decode(&doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return &doc, nil
}

func (c *AuthorizationContextColl) AddIdentity(ctx context.Context, query *model.AuthorizationContext, input *model.AuthorizationContext) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:authorization_context:add_identity_kid")
	defer span.End()

	if query == nil {
		span.SetStatus(codes.Error, "query cannot be nil")
		return errors.New("query cannot be nil")
	}

	if input.Identity == nil {
		span.SetStatus(codes.Error, "identity cannot be nil")
		return errors.New("identity cannot be nil")
	}

	filter := bson.M{}

	if query.SessionID != "" {
		filter["session_id"] = bson.M{"$eq": query.SessionID}
	}

	if query.RequestURI != "" {
		filter["request_uri"] = bson.M{"$eq": query.RequestURI}
	}

	if query.EphemeralEncryptionKeyID != "" {
		filter["ephemeral_encryption_key_id"] = bson.M{"$eq": query.EphemeralEncryptionKeyID}
	}

	update := bson.M{
		"$set": bson.M{
			"identity":         input.Identity,
			"document_type":    input.DocumentType,
			"authentic_source": input.AuthenticSource,
		},
	}

	_, err := c.Coll.UpdateOne(ctx, filter, update)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}
