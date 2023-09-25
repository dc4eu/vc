package db

import (
	"context"
	"vc/pkg/pda1"

	"go.mongodb.org/mongo-driver/mongo"
)

// EducationColl is the collection of PDA1 documents
type EducationColl struct {
	Service *Service
	Coll    *mongo.Collection
}

func (c *EducationColl) createIndex(ctx context.Context) error {
	//indexModel := mongo.IndexModel{
	//	Keys: bson.M{"transaction_id": 1},
	//}
	//_, err := c.coll.Indexes().CreateOne(ctx, indexModel)
	//if err != nil {
	//	return err
	//}
	return nil
}

// Save saves one document to the PDA1 collection
func (c *EducationColl) Save(ctx context.Context, doc *pda1.Document) error {
	_, err := c.Coll.InsertOne(ctx, doc)
	return err
}
