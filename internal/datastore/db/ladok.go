package db

import (
	"context"
	"vc/pkg/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type LadokColl struct {
	Service *Service
	Coll    *mongo.Collection
}

func (c *LadokColl) createIndex(ctx context.Context) error {
	//indexModel := mongo.IndexModel{
	//	Keys: bson.M{"transaction_id": 1},
	//}
	//_, err := c.coll.Indexes().CreateOne(ctx, indexModel)
	//if err != nil {
	//	return err
	//}
	return nil
}

// LadokUpload is the uploaded document
type LadokUpload struct {
	Data *model.Ladok `json:"data" validate:"required"`
	Meta *model.Meta  `json:"meta" validate:"required"`
}

// Save saves one document to the PDA1 collection
func (c *LadokColl) Save(ctx context.Context, doc *LadokUpload) error {
	_, err := c.Coll.InsertOne(ctx, doc)
	return err
}

// GetID return matching document with id if any, or error
func (c *LadokColl) GetID(ctx context.Context, id string) (*LadokUpload, error) {
	filter := bson.M{"meta.upload_id": id}
	res := &LadokUpload{}
	if err := c.Coll.FindOne(ctx, filter).Decode(res); err != nil {
		return nil, err
	}
	return res, nil
}
