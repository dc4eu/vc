package db

import (
	"context"
	"time"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/openid4vci"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.opentelemetry.io/otel/codes"
)

// VCCodeChallengeColl is the collection of the VC Auth
type VCCodeChallengeColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

// NewPkceColl creates a new VCAuthColl
func NewPkceColl(ctx context.Context, collName string, service *Service, log *logger.Log) (*VCCodeChallengeColl, error) {
	c := &VCCodeChallengeColl{
		log:     log,
		Service: service,
	}

	c.Coll = c.Service.dbClient.Database("vc").Collection(collName)

	if err := c.createIndex(ctx); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *VCCodeChallengeColl) createIndex(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:pkce:createIndex")
	defer span.End()

	indexCodeChallengeUniq := mongo.IndexModel{
		Keys: bson.D{
			primitive.E{Key: "code_challenge", Value: 1},
		},
		Options: options.Index().SetName("auth_code_uniq").SetUnique(true),
	}
	_, err := c.Coll.Indexes().CreateMany(ctx, []mongo.IndexModel{indexCodeChallengeUniq})
	if err != nil {
		return err
	}
	return nil
}

// Save saves one document to the generic collection
func (c *VCCodeChallengeColl) Save(ctx context.Context, doc *model.CodeChallenge) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:pkce:save")
	defer span.End()

	_, err := c.Coll.InsertOne(ctx, doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())

		return err
	}

	return nil
}

// Exists checks if the code challenge already exists
func (c *VCCodeChallengeColl) Exists(ctx context.Context, codeChallenge string) (bool, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:pkce:exists")
	defer span.End()

	filter := bson.M{
		"code_challenge": bson.M{"$eq": codeChallenge},
	}

	count, err := c.Coll.CountDocuments(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return false, err
	}

	return count > 0, nil
}

// Delete deletes one code_challenge
func (c *VCCodeChallengeColl) Delete(ctx context.Context, codeChallenge string) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:pkce:delete")
	defer span.End()

	filter := bson.M{
		"code_challenge": bson.M{"$eq": codeChallenge},
	}

	_, err := c.Coll.DeleteOne(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}

// Grant grants one code_challenge from code_challenge collection
func (c *VCCodeChallengeColl) Grant(ctx context.Context, codeVerifier, codeChallengeMethod string) (bool, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:pkce:grant")
	defer span.End()

	codeChallenge := openid4vci.CreateCodeChallenge(codeChallengeMethod, codeVerifier)

	filter := bson.M{
		"code_challenge": bson.M{"$eq": codeChallenge},
	}

	err := c.Coll.FindOneAndUpdate(ctx, filter, bson.M{
		"$set": bson.M{"last_used": primitive.NewDateTimeFromTime(time.Now())},
	}).Err()
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "Code Challenge not found", "code_challenge", codeChallenge)
		if err == mongo.ErrNoDocuments {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// DeleteNotUsed deletes all code_challenge that are not used in the last 24 hours
func (c *VCCodeChallengeColl) DeleteNotUsed(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:pkce:deleteNotUsed")
	defer span.End()

	filter := bson.M{
		"last_used": bson.M{"$lt": primitive.NewDateTimeFromTime(time.Now().Add(-24 * time.Hour))},
	}

	_, err := c.Coll.DeleteMany(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}
