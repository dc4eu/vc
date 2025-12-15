package db

import (
	"context"
	"vc/pkg/logger"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// TSLMetadataColl is the collection for status list metadata
type TSLMetadataColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

// TSLMetadataDoc represents a document in the status list metadata collection
type TSLMetadataDoc struct {
	CurrentSection int64   `bson:"current_section"`
	Sections       []int64 `bson:"sections"`
}

// NewTSLMetadataColl creates a new StatusListMetadataColl
func NewTSLMetadataColl(ctx context.Context, collName string, service *Service, log *logger.Log) (*TSLMetadataColl, error) {
	c := &TSLMetadataColl{
		log:     log,
		Service: service,
	}

	c.Coll = c.Service.mongoClient.Database(databaseName).Collection(collName)

	if err := c.initMetadataDoc(ctx); err != nil {
		return nil, err
	}

	c.log.Info("Started")

	return c, nil
}

func (c *TSLMetadataColl) initMetadataDoc(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:tsl_metadata:initMetadataDoc")
	defer span.End()

	doc := &TSLMetadataDoc{}

	err := c.Coll.FindOne(ctx, bson.M{}).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			doc = &TSLMetadataDoc{
				CurrentSection: 0,
				Sections:       []int64{0},
			}
			_, err := c.Coll.InsertOne(ctx, doc)
			return err
		}
		return err
	}

	return nil
}

// GetCurrentSection returns the current section number
func (c *TSLMetadataColl) GetCurrentSection(ctx context.Context) (int64, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:tsl_metadata:getCurrentSection")
	defer span.End()

	var doc TSLMetadataDoc

	err := c.Coll.FindOne(ctx, bson.M{}).Decode(&doc)
	if err != nil {
		return 0, err
	}

	return doc.CurrentSection, nil
}

// UpdateCurrentSection updates the current section and adds it to the sections list
func (c *TSLMetadataColl) UpdateCurrentSection(ctx context.Context, newSection int64) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:tsl_metadata:updateCurrentSection")
	defer span.End()

	doc := &TSLMetadataDoc{}
	if err := c.Coll.FindOne(ctx, bson.M{}).Decode(doc); err != nil {
		return err
	}

	doc.CurrentSection = newSection
	doc.Sections = append(doc.Sections, doc.CurrentSection)

	update := bson.M{
		"$set": bson.M{
			"current_section": doc.CurrentSection,
			"sections":        doc.Sections,
		},
	}
	_, err := c.Coll.UpdateOne(ctx, bson.M{}, update)
	return err
}

// GetAllSections returns all section IDs that have been created.
// Used for Status List Aggregation (Section 9.3).
func (c *TSLMetadataColl) GetAllSections(ctx context.Context) ([]int64, error) {
	ctx, span := c.Service.tracer.Start(ctx, "db:tsl_metadata:getAllSections")
	defer span.End()

	var doc TSLMetadataDoc

	err := c.Coll.FindOne(ctx, bson.M{}).Decode(&doc)
	if err != nil {
		return nil, err
	}

	return doc.Sections, nil
}
