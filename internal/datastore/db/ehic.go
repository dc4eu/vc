package db

import (
	"context"
	"vc/pkg/ehic"
	"vc/pkg/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// EHICColl is the collection of PDA1 documents
type EHICColl struct {
	Service *Service
	Coll    *mongo.Collection
}

func (c *EHICColl) createIndex(ctx context.Context) error {
	//indexModel := mongo.IndexModel{
	//	Keys: bson.M{"transaction_id": 1},
	//}
	//_, err := c.coll.Indexes().CreateOne(ctx, indexModel)
	//if err != nil {
	//	return err
	//}
	return nil
}

// EHICUpload is the model for the EHIC push/upload integration
type EHICUpload struct {
	Data *ehic.Document `json:"data" validate:"required"`
	Meta *model.Meta    `json:"meta" validate:"required"`
}

// Save saves one document to the PDA1 collection
func (c *EHICColl) Save(ctx context.Context, doc *EHICUpload) error {
	_, err := c.Coll.InsertOne(ctx, doc)
	return err
}

// GetID return matching document with id if any, or error
func (c *EHICColl) GetID(ctx context.Context, id string) (*EHICUpload, error) {
	filter := bson.M{"meta.upload_id": id}
	res := &EHICUpload{}
	if err := c.Coll.FindOne(ctx, filter).Decode(res); err != nil {
		return nil, err
	}
	return res, nil
}
