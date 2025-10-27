package db

import (
	"context"
	"vc/pkg/logger"

	"math/rand/v2"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.opentelemetry.io/otel/codes"
)

// StatusListColl is the collection for status list
type StatusListColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

type StatusListDoc struct {
	Index   int64 `bson:"index"`
	Status  uint8 `bson:"status"`
	Decoy   bool  `bson:"decoy"`
	Section int64 `bson:"section"`
}

// NewStatusListColl creates a new StatusListColl
func NewStatusListColl(ctx context.Context, collName string, service *Service, log *logger.Log) (*StatusListColl, error) {
	c := &StatusListColl{
		log:     log,
		Service: service,
	}

	c.Coll = c.Service.dbClient.Database("vc").Collection(collName)

	if err := c.createIndex(ctx); err != nil {
		return nil, err
	}

	c.log.Info("Started")

	return c, nil
}

func (c *StatusListColl) createIndex(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:status_list:createIndex")
	defer span.End()

	// TODO(masv): make mongodb do the index

	indexUniq := mongo.IndexModel{
		Keys: bson.D{
			bson.E{Key: "index", Value: 1},
		},
		Options: options.Index().SetName("index_uniq").SetUnique(true),
	}
	_, err := c.Coll.Indexes().CreateMany(ctx, []mongo.IndexModel{indexUniq})
	if err != nil {
		return err
	}

	return nil
}

func (c *StatusListColl) nextIndexNumber() int64 {
	ctx, span := c.Service.tracer.Start(context.Background(), "db:status_list:nextIndex")
	defer span.End()

	count, err := c.Coll.CountDocuments(ctx, bson.M{})
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "cant get next index")
		return 0
	}

	if count == 0 {
		return 0
	}

	return count
}

// AddDecoy adds decoy statuses to the status list collection to obfuscate real statuses, herd immunity
func (c *StatusListColl) AddDecoy(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:status_list:createDecoyStatus")
	defer span.End()

	min := 10
	max := 1000
	amountOfRecords := rand.IntN(max-min) + min

	for range amountOfRecords {
		status := uint8(rand.IntN(3))

		index := c.nextIndexNumber()
		doc := &StatusListDoc{
			Index:  index,
			Status: status,
			Decoy:  true,
		}

		_, err := c.Coll.InsertOne(ctx, doc)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			c.log.Error(err, "cant add decoy status")
			return err
		}
	}

	return nil
}

// Add adds a new status to the status list collection, return index of the added status or an error
func (c *StatusListColl) Add(ctx context.Context, status uint8) (int64, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:status_list:add")
	defer span.End()

	index := c.nextIndexNumber()

	if index < 10000 {
		if err := c.AddDecoy(ctx); err != nil {
			return 0, err
		}
	}

	nonDecoyIndex := c.nextIndexNumber()

	doc := &StatusListDoc{
		Index:  nonDecoyIndex,
		Status: status,
		Decoy:  false,
	}

	_, err := c.Coll.InsertOne(ctx, doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "cant add status")
		return 0, err
	}

	return nonDecoyIndex, nil
}

func (c *StatusListColl) UpdateRandomDecoy(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:status_list:updateRandomDecoy")
	defer span.End()

	filter := bson.M{"decoy": true, "status": bson.M{"$eq": 0}}

	cursor, err := c.Coll.Find(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "cant find decoy statuses")
		return err
	}

	var result []StatusListDoc
	if err := cursor.All(ctx, &result); err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "cant read decoy statuses")
		return err
	}

	for range rand.IntN(10) + 1 {
		r := result[rand.IntN(len(result)-1)]

		updateFilter := bson.M{"index": r.Index}
		newStatus := uint8(rand.IntN(2))
		update := bson.M{"$set": bson.M{"status": newStatus}}

		_, err = c.Coll.UpdateOne(ctx, updateFilter, update)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			c.log.Error(err, "cant update decoy status")
			return err
		}

		c.log.Info("updateRandomDecoy", "index", r.Index, "newStatus", newStatus)
	}

	return nil
}

func (c *StatusListColl) UpdateStatus(ctx context.Context, index int64, status uint8) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:status_list:updateStatus")
	defer span.End()

	filter := bson.M{"index": index}
	update := bson.M{"$set": bson.M{"status": status}}

	if err := c.UpdateRandomDecoy(ctx); err != nil {
		return err
	}

	_, err := c.Coll.UpdateOne(ctx, filter, update)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "cant update status")
		return err
	}

	return nil
}
