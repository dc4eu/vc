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

// VCUsersColl is the collection of the VC Auth
type VCUsersColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

// NewUserColl creates a new VCUsersColl
func NewUserColl(ctx context.Context, collName string, service *Service, log *logger.Log) (*VCUsersColl, error) {
	c := &VCUsersColl{
		log:     log,
		Service: service,
	}

	c.Coll = c.Service.dbClient.Database("vc").Collection(collName)

	if err := c.createIndex(ctx); err != nil {
		return nil, err
	}

	if err := c.loadUsers(ctx); err != nil {
		return nil, err
	}

	c.log.Info("Started")

	return c, nil
}

func (c *VCUsersColl) createIndex(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:users:createIndex")
	defer span.End()

	clientIDUniq := mongo.IndexModel{
		Keys: bson.D{
			primitive.E{Key: "client_id", Value: 1},
		},
		Options: options.Index().SetName("client_id_uniq").SetUnique(true),
	}
	_, err := c.Coll.Indexes().CreateMany(ctx, []mongo.IndexModel{clientIDUniq})
	if err != nil {
		return err
	}

	return nil
}

// Save saves one document to the generic collection
func (c *VCUsersColl) Save(ctx context.Context, doc *model.OAuthUsers) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:users:save")
	defer span.End()

	_, err := c.Coll.InsertOne(ctx, doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}

// Grant grants one user from users collection
func (c *VCUsersColl) Grant(ctx context.Context, clientID string) (bool, error) {
	c.log.Debug("this is grant", "client_id", clientID)
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:users:grant")
	defer span.End()

	filter := bson.M{
		"client_id": bson.M{"$eq": clientID},
	}

	res := &model.OAuthUsers{}

	if err := c.Coll.FindOne(ctx, filter).Decode(&res); err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "User not found", "client_id", clientID)
		if err == mongo.ErrNoDocuments {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (c *VCUsersColl) loadUsers(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:users:loadUsers")
	defer span.End()

	for userName := range c.Service.cfg.APIGW.APIServer.BasicAuth.Users {
		c.log.Info("Creating user", "user", userName)
		user := &model.OAuthUsers{
			ClientID: userName,
		}
		if err := c.Save(ctx, user); err != nil {
			return err
		}
	}

	return nil
}
