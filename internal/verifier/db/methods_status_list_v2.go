package db

import (
	"context"
	"math/rand/v2"
	"vc/pkg/logger"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.opentelemetry.io/otel/codes"
)

// StatusListV2Coll is the collection for status list
type StatusListV2Coll struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

// NewStatusListV2Coll creates a new StatusListV2Coll
func NewStatusListV2Coll(ctx context.Context, collName string, service *Service, log *logger.Log) (*StatusListV2Coll, error) {
	c := &StatusListV2Coll{
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

func (c *StatusListV2Coll) createIndex(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:status_list:createIndex")
	defer span.End()

	// TODO(masv): make mongodb do the index

	indexUniq := mongo.IndexModel{
		Keys: bson.D{
			bson.E{Key: "index", Value: 1},
			bson.E{Key: "section", Value: 1},
		},
		Options: options.Index().SetName("index_uniq").SetUnique(true),
	}
	_, err := c.Coll.Indexes().CreateMany(ctx, []mongo.IndexModel{indexUniq})
	if err != nil {
		return err
	}

	return nil
}

func (c *StatusListV2Coll) getRandomDecoys(ctx context.Context, section int) ([]StatusListDoc, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:status_list:getRandomDecoyIndexes")
	defer span.End()

	pipeline := []bson.D{
		bson.D{
			{"$sample", bson.D{{"size", 10}}},
		},
	}

	cursor, err := c.Coll.Aggregate(ctx, pipeline)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "cant get decoy indexes")
		return nil, err
	}

	var docs []StatusListDoc
	if err = cursor.All(ctx, &docs); err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "cant decode decoy indexes")
		return nil, err
	}

	l := len(docs)
	c.log.Debug("getrandomdecoys", "len", l)

	if l <= 0 {
		c.log.Error(nil, "no decoy indexes found")
		return nil, nil
	}

	var result []StatusListDoc
	for range rand.IntN(len(docs)) {
		i := rand.IntN(len(docs) - 1)

		result = append(result, docs[i])
	}

	return result, nil
}

// Add adds a new status to the status list collection, return index of the added status or an error
func (c *StatusListV2Coll) Add(ctx context.Context, section int, status uint8) (int64, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:status_list:add")
	defer span.End()

	decoys, err := c.getRandomDecoys(ctx, 1)
	if err != nil {
		return 0, err
	}

	c.log.Debug("add", "decoys", decoys)

	if len(decoys) < 4 {
		c.log.Error(nil, "not enough decoy indexes to add status")

		// make a new section
	}

	doc := &StatusListDoc{
		Index:   decoys[0].Index,
		Status:  status,
		Decoy:   false,
		Section: 1,
	}

	_, err = c.Coll.InsertOne(ctx, doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "cant add status")
		return 0, err
	}

	for _, index := range decoys[1:] {
		filter := bson.M{"index": index}
		updateDoc := bson.M{"$set": bson.M{"status": status}}

		_, err := c.Coll.UpdateOne(ctx, filter, updateDoc)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			c.log.Error(err, "cant update status")
			return 0, err
		}
	}

	return decoys[0].Index, nil
}

//func (c *StatusListV2Coll) UpdateStatus(ctx context.Context, index int64, status uint8) error {
//	ctx, span := c.Service.tracer.Start(ctx, "db:status_list:updateStatus")
//	defer span.End()
//
//	filter := bson.M{"index": index}
//	update := bson.M{"$set": bson.M{"status": status}}
//
//	if err := c.UpdateRandomDecoy(ctx); err != nil {
//		return err
//	}
//
//	_, err := c.Coll.UpdateOne(ctx, filter, update)
//	if err != nil {
//		span.SetStatus(codes.Error, err.Error())
//		c.log.Error(err, "cant update status")
//		return err
//	}
//
//	return nil
//}
