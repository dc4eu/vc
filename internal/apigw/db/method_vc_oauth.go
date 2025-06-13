package db

import (
	"context"
	"errors"
	"time"
	"vc/pkg/logger"
	"vc/pkg/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.opentelemetry.io/otel/codes"
)

// VCOauthColl is the collection of the VC Auth
type VCOauthColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

// NewOauthColl creates a new VCAuthColl
func NewOauthColl(ctx context.Context, collName string, service *Service, log *logger.Log) (*VCOauthColl, error) {
	c := &VCOauthColl{
		log:     log,
		Service: service,
	}

	c.Coll = c.Service.dbClient.Database("vc").Collection(collName)

	if err := c.createIndex(ctx); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *VCOauthColl) createIndex(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:oauth:createIndex")
	defer span.End()

	indexRequestURIUniq := mongo.IndexModel{
		Keys: bson.D{
			primitive.E{Key: "request_uri", Value: 1},
		},
		Options: options.Index().SetName("oauth_request_uri_uniq").SetUnique(true),
	}
	indexCodeUniq := mongo.IndexModel{
		Keys: bson.D{
			primitive.E{Key: "code", Value: 1},
		},
		Options: options.Index().SetName("oauth_code_uniq").SetUnique(true),
	}

	_, err := c.Coll.Indexes().CreateMany(ctx, []mongo.IndexModel{indexRequestURIUniq, indexCodeUniq})
	if err != nil {
		return err
	}
	return nil
}

// Save saves one document to the generic collection
func (c *VCOauthColl) Save(ctx context.Context, doc *model.Authorization) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:auth:save")
	defer span.End()

	doc.SavedAt = time.Now().Unix()

	_, err := c.Coll.InsertOne(ctx, doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())

		return err
	}

	return nil
}

func (c *VCOauthColl) Consent(ctx context.Context, query *model.Authorization) error {
	filter := bson.M{}

	if query.RequestURI == "" {
		return errors.New("code cannot be empty")
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
func (c *VCOauthColl) ForfeitAuthorizationCode(ctx context.Context, query *model.Authorization) (*model.Authorization, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:auth:get")
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

	update := bson.M{
		"$set": bson.M{
			"is_used":   true,
			"last_used": time.Now().Unix(),
		},
	}

	var doc model.Authorization
	if err := c.Coll.FindOneAndUpdate(ctx, filter, update).Decode(&doc); err != nil {
		//err := c.Coll.FindOne(ctx, filter).Decode(&doc)
		//if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return &doc, nil
}

// Get gets one authorization document
func (c *VCOauthColl) Get(ctx context.Context, query *model.Authorization) (*model.Authorization, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:auth:get")
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

	var doc model.Authorization
	err := c.Coll.FindOne(ctx, filter).Decode(&doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return &doc, nil
}

func (c *VCOauthColl) AddToken(ctx context.Context, code string, token *model.Token) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:oauth:addToken")
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

func (c VCOauthColl) GetWithToken(ctx context.Context, token string) (*model.Authorization, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:oauth:getWithToken")
	defer span.End()

	if token == "" {
		span.SetStatus(codes.Error, "token cannot be empty")
		return nil, errors.New("token cannot be empty")
	}

	filter := bson.M{
		"token.access_token": bson.M{"$eq": token},
	}

	var doc model.Authorization
	err := c.Coll.FindOne(ctx, filter).Decode(&doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	return &doc, nil
}

func (c *VCOauthColl) AddIdentity(ctx context.Context, requestURI string, identity *model.Identity) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:oauth:addIdentity")
	defer span.End()

	if requestURI == "" {
		span.SetStatus(codes.Error, "requestURI cannot be empty")
		return errors.New("requestURI cannot be empty")
	}

	filter := bson.M{
		"request_uri": bson.M{"$eq": requestURI},
	}

	update := bson.M{
		"$set": bson.M{
			"identity": identity,
		},
	}

	_, err := c.Coll.UpdateOne(ctx, filter, update)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}

//func (c *VCOauthColl) Update(ctx context.Context, query *model.Authorization) error {
//	ctx, span := c.Service.tracer.Start(ctx, "db:vc:auth:update")
//	defer span.End()
//
//	if query == nil {
//		span.SetStatus(codes.Error, "query cannot be nil")
//		return errors.New("query cannot be nil")
//	}
//
//	filter := bson.M{
//		"request_uri": bson.M{"$eq": query.RequestURI},
//		"client_id":   bson.M{"$eq": query.ClientID},
//	}
//
//	update := bson.M{
//		"$set": query,
//	}
//
//	_, err := c.Coll.UpdateOne(ctx, filter, update)
//	if err != nil {
//		span.SetStatus(codes.Error, err.Error())
//		return err
//	}
//
//	return nil
//}
