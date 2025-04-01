package db

import (
	"context"
	"vc/pkg/logger"
	"vc/pkg/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.opentelemetry.io/otel/codes"
)

// VCTokenColl is the collection of the VC Auth
type VCTokenColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

// NewTokenColl creates a new VCTokenColl
func NewTokenColl(ctx context.Context, collName string, service *Service, log *logger.Log) (*VCTokenColl, error) {
	c := &VCTokenColl{
		log:     log,
		Service: service,
	}

	c.Coll = c.Service.dbClient.Database("vc").Collection(collName)

	if err := c.createIndex(ctx); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *VCTokenColl) createIndex(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:auth:createIndex")
	defer span.End()

	indexCodeUniq := mongo.IndexModel{
		Keys: bson.D{
			primitive.E{Key: "code", Value: 1},
		},
		Options: options.Index().SetName("auth_code_uniq").SetUnique(true),
	}
	_, err := c.Coll.Indexes().CreateMany(ctx, []mongo.IndexModel{indexCodeUniq})
	if err != nil {
		return err
	}
	return nil
}

// Save saves one document to the generic collection
func (c *VCTokenColl) Save(ctx context.Context, doc *model.Authorization) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:auth:save")
	defer span.End()

	_, err := c.Coll.InsertOne(ctx, doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())

		return err
	}

	return nil
}
