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

// NewStatusListColl creates a new StatusListV2Coll
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

func (c *StatusListColl) CountDocs(ctx context.Context, filter bson.M) (int64, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:status_list:countDocs")
	defer span.End()

	count, err := c.Coll.CountDocuments(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return 0, err
	}

	return count, nil
}

func (c *StatusListColl) CreateNewSection(ctx context.Context, section int64) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:status_list:createNewSection")
	defer span.End()

	docs := []*StatusListDoc{}
	for i := 0; i < 1000000; i++ {
		docs = append(docs, &StatusListDoc{
			Index:   int64(i),
			Status:  uint8(rand.IntN(3)),
			Decoy:   true,
			Section: int64(section),
		})
	}

	c.log.Debug("createNewSection", "number of decoys", len(docs))
	_, err := c.Coll.InsertMany(ctx, docs)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "cant pre-seed section", "section", section)
		return err
	}

	return nil
}

func (c *StatusListColl) getRandomDecoys(ctx context.Context, section int64) ([]StatusListDoc, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:status_list:getRandomDecoyIndexes")
	defer span.End()
	match := bson.D{{Key: "section", Value: section}, {Key: "decoy", Value: true}}
	sample := bson.M{"size": 10}

	pipeline := mongo.Pipeline{
		{{"$match", match}},
		{{"$sample", sample}},
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

	return docs, nil
}

// Add adds a new status to the status list collection, return index of the added status or an error
func (c *StatusListColl) Add(ctx context.Context, section int64, status uint8) (int64, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:status_list:add")
	defer span.End()

	decoys, err := c.getRandomDecoys(ctx, section)
	if err != nil {
		return 0, err
	}

	c.log.Debug("add", "decoys", decoys)

	doc := &StatusListDoc{
		Index:   decoys[rand.IntN(len(decoys)-1)].Index,
		Status:  status,
		Decoy:   false,
		Section: section,
	}

	_, err = c.Coll.UpdateOne(ctx, bson.M{"index": doc.Index}, bson.M{"$set": doc})
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "cant add status")
		return 0, err
	}

	for _, decoy := range decoys {
		if decoy.Index == doc.Index {
			continue
		}

		filter := bson.M{"index": decoy.Index}
		updateDoc := bson.M{"$set": bson.M{"status": rand.Int64N(3)}}

		_, err := c.Coll.UpdateOne(ctx, filter, updateDoc)
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
			c.log.Error(err, "cant update status")
			return 0, err
		}
	}

	return doc.Index, nil
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
