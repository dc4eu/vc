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

// TSLColl is the collection for status list
type TSLColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

// TSLDoc represents a document in the Token Status List document
type TSLDoc struct {
	Index   int64 `bson:"index"`
	Status  uint8 `bson:"status"`
	Decoy   bool  `bson:"decoy"`
	Section int64 `bson:"section"`
}

// NewTSLColl creates a new Token Status List coll
func NewTSLColl(ctx context.Context, collName string, service *Service, log *logger.Log) (*TSLColl, error) {
	c := &TSLColl{
		log:     log,
		Service: service,
	}

	c.Coll = c.Service.mongoClient.Database(databaseName).Collection(collName)

	if err := c.createIndex(ctx); err != nil {
		return nil, err
	}

	c.log.Info("Started")

	return c, nil
}

// InitializeIfEmpty checks if the collection is empty and initializes it with sample data
func (c *TSLColl) InitializeIfEmpty(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:tsl:initializeIfEmpty")
	defer span.End()

	count, err := c.CountDocs(ctx, bson.M{})
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	if count > 0 {
		c.log.Info("Status list collection already initialized", "documents", count)
		return nil
	}

	c.log.Info("Status list collection is empty, initializing section 0 with decoys")

	// Create section 0 with decoy entries, use config section size
	sectionSize := c.Service.cfg.Registry.TokenStatusLists.SectionSize
	if err := c.CreateNewSection(ctx, 0, sectionSize); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	c.log.Info("Status list collection initialized with section 0")
	return nil
}

func (c *TSLColl) createIndex(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:tsl:createIndex")
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

// CountDocs counts documents matching the filter
func (c *TSLColl) CountDocs(ctx context.Context, filter bson.M) (int64, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:tsl:countDocs")
	defer span.End()

	count, err := c.Coll.CountDocuments(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return 0, err
	}

	return count, nil
}

// FindOne finds a single status entry by section and index
func (c *TSLColl) FindOne(ctx context.Context, section, index int64) (*TSLDoc, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:tsl:findOne")
	defer span.End()

	filter := bson.M{"section": section, "index": index}

	var doc TSLDoc
	err := c.Coll.FindOne(ctx, filter).Decode(&doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "cant find status entry", "section", section, "index", index)
		return nil, err
	}

	return &doc, nil
}

// CreateNewSection creates a new section with decoy entries.
// If sectionSize is 0 or negative, it defaults to 500,000.
func (c *TSLColl) CreateNewSection(ctx context.Context, section int64, sectionSize int64) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:tsl:createNewSection")
	defer span.End()

	// Default to 500,000 if not set
	if sectionSize <= 0 {
		sectionSize = 500000
	}

	docs := []*TSLDoc{}
	for i := int64(0); i < sectionSize; i++ {
		docs = append(docs, &TSLDoc{
			Index:   i,
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

func (c *TSLColl) getRandomDecoys(ctx context.Context, section int64) ([]TSLDoc, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:tsl:getRandomDecoyIndexes")
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

	var docs []TSLDoc
	if err = cursor.All(ctx, &docs); err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "cant decode decoy indexes")
		return nil, err
	}

	return docs, nil
}

// Add adds a new status to the status list collection, return index of the added status or an error
func (c *TSLColl) Add(ctx context.Context, section int64, status uint8) (int64, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:tsl:add")
	defer span.End()

	decoys, err := c.getRandomDecoys(ctx, section)
	if err != nil {
		return 0, err
	}

	c.log.Debug("add", "decoys", decoys)

	doc := &TSLDoc{
		Index:   decoys[rand.IntN(len(decoys)-1)].Index,
		Status:  status,
		Decoy:   false,
		Section: section,
	}

	_, err = c.Coll.UpdateOne(ctx, bson.M{"index": doc.Index, "section": doc.Section}, bson.M{"$set": doc})
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "cant add status")
		return 0, err
	}

	// Update random decoys to add noise
	for _, decoy := range decoys {
		if decoy.Index == doc.Index {
			continue
		}

		filter := bson.M{"index": decoy.Index, "section": section}
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

// GetAllStatusesForSection retrieves all status entries for a given section, ordered by index.
// Returns a slice of status values (uint8) suitable for encoding into a Status List Token.
func (c *TSLColl) GetAllStatusesForSection(ctx context.Context, section int64) ([]uint8, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:tsl:getAllStatusesForSection")
	defer span.End()

	filter := bson.M{"section": section}
	opts := options.Find().SetSort(bson.D{{Key: "index", Value: 1}})

	cursor, err := c.Coll.Find(ctx, filter, opts)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "cant get statuses for section", "section", section)
		return nil, err
	}
	defer cursor.Close(ctx)

	var docs []TSLDoc
	if err = cursor.All(ctx, &docs); err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "cant decode statuses", "section", section)
		return nil, err
	}

	statuses := make([]uint8, len(docs))
	for i, doc := range docs {
		statuses[i] = doc.Status
	}

	return statuses, nil
}

// UpdateStatus updates the status of an existing entry at the given section and index.
func (c *TSLColl) UpdateStatus(ctx context.Context, section int64, index int64, status uint8) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:tsl:updateStatus")
	defer span.End()

	filter := bson.M{"section": section, "index": index}
	update := bson.M{"$set": bson.M{"status": status}}

	result, err := c.Coll.UpdateOne(ctx, filter, update)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		c.log.Error(err, "cant update status", "section", section, "index", index)
		return err
	}

	if result.MatchedCount == 0 {
		c.log.Info("no document found to update", "section", section, "index", index)
	}

	return nil
}
