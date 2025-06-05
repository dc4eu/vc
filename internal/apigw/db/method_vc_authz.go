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

// VCAuthzColl is the collection of the VC Auth
type VCAuthzColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

// NewAuthzColl creates a new VCAuthColl
func NewAuthzColl(ctx context.Context, collName string, service *Service, log *logger.Log) (*VCAuthzColl, error) {
	c := &VCAuthzColl{
		log:     log,
		Service: service,
	}

	c.Coll = c.Service.dbClient.Database("vc").Collection(collName)

	if err := c.createIndex(ctx); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *VCAuthzColl) createIndex(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:auth:createIndex")
	defer span.End()

	indexCodeUniq := mongo.IndexModel{
		Keys: bson.D{
			primitive.E{Key: "request_uri", Value: 1},
		},
		Options: options.Index().SetName("auth_code_uniq").SetUnique(true),
	}

	indexTTL := mongo.IndexModel{
		Keys: bson.D{
			primitive.E{Key: "saved_at", Value: 1},
		},
		Options: options.Index().SetName("auth_code_ttl").SetExpireAfterSeconds(60),
	}
	_, err := c.Coll.Indexes().CreateMany(ctx, []mongo.IndexModel{indexCodeUniq, indexTTL})
	if err != nil {
		return err
	}
	return nil
}

// Save saves one document to the generic collection
func (c *VCAuthzColl) Save(ctx context.Context, doc *model.Authorization) error {
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

// Get gets one user from auth collection
func (c *VCAuthzColl) Get(ctx context.Context, query *model.Authorization) (*model.Authorization, error) {
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
