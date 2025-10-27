package db

import (
	"context"
	"vc/pkg/logger"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// StatusListMetadataColl is the collection for status list metadata
type StatusListMetadataColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

type StatusListMetadataDoc struct {
	CurrentSection int64   `bson:"current_section"`
	Sections       []int64 `bson:"sections"`
}

// NewStatusListMetadataColl creates a new StatusListMetadataColl
func NewStatusListMetadataColl(ctx context.Context, collName string, service *Service, log *logger.Log) (*StatusListMetadataColl, error) {
	c := &StatusListMetadataColl{
		log:     log,
		Service: service,
	}

	c.Coll = c.Service.dbClient.Database("vc").Collection(collName)

	if err := c.initMetadataDoc(ctx); err != nil {
		return nil, err
	}

	c.log.Info("Started")

	return c, nil
}

func (c *StatusListMetadataColl) initMetadataDoc(ctx context.Context) error {
	doc := &StatusListMetadataDoc{}

	err := c.Coll.FindOne(ctx, bson.M{}).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			doc = &StatusListMetadataDoc{
				CurrentSection: 1,
				Sections:       []int64{1},
			}
			_, err := c.Coll.InsertOne(ctx, doc)
			return err
		}
		return err
	}

	return nil
}

func (c *StatusListMetadataColl) GetCurrentSection(ctx context.Context) (int64, error) {
	var doc StatusListMetadataDoc

	err := c.Coll.FindOne(ctx, bson.M{}).Decode(&doc)
	if err != nil {
		return 0, err
	}

	return doc.CurrentSection, nil
}

func (c *StatusListMetadataColl) createNewSection(ctx context.Context) error {
	doc := &StatusListMetadataDoc{}
	if err := c.Coll.FindOne(ctx, bson.M{}).Decode(doc); err != nil {
		return err
	}

	doc.CurrentSection = doc.CurrentSection + 1
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
