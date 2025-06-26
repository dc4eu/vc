package db

import (
	"context"
	"vc/pkg/logger"
	"vc/pkg/openid4vp"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.opentelemetry.io/otel/codes"
)

type VCVerifierContextColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

func NewVCVerifierContextColl(ctx context.Context, service *Service, collName string, log *logger.Log) (*VCVerifierContextColl, error) {
	c := &VCVerifierContextColl{
		log:     log,
		Service: service,
	}

	c.Coll = c.Service.dbClient.Database("vc").Collection(collName)

	if err := c.createIndex(ctx); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *VCVerifierContextColl) createIndex(ctx context.Context) error {
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

func (c *VCVerifierContextColl) Save(ctx context.Context, doc *openid4vp.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:verifier:save")
	defer span.End()

	_, err := c.Coll.InsertOne(ctx, doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}
