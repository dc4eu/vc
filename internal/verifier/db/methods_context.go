package db

import (
	"context"
	"vc/pkg/logger"
	"vc/pkg/openid4vp"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.opentelemetry.io/otel/codes"
)

type ContextColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

func NewContextColl(ctx context.Context, service *Service, collName string, log *logger.Log) (*ContextColl, error) {
	c := &ContextColl{
		log:     log,
		Service: service,
	}

	c.Coll = c.Service.dbClient.Database("vc").Collection(collName)

	if err := c.createIndex(ctx); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *ContextColl) createIndex(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:verifier:createIndex")
	defer span.End()

	indexVerifierUniq := mongo.IndexModel{
		Keys: bson.D{
			{Key: "id", Value: 1},
		},
		Options: options.Index().SetName("verifier_uniq").SetUnique(true),
	}
	_, err := c.Coll.Indexes().CreateMany(ctx, []mongo.IndexModel{indexVerifierUniq})
	if err != nil {
		return err
	}
	return nil
}

func (c *ContextColl) Save(ctx context.Context, doc *openid4vp.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:verifier:save")
	defer span.End()

	_, err := c.Coll.InsertOne(ctx, doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}
