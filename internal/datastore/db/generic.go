package db

import (
	"context"
	"vc/pkg/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// GenericColl is the generic collection
type GenericColl struct {
	Service *Service
	Coll    *mongo.Collection
}

func (c *GenericColl) createIndex(ctx context.Context) error {
	indexModel := mongo.IndexModel{
		Keys: bson.M{"document_id": 1},
	}
	_, err := c.Coll.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		return err
	}
	return nil
}

// Save saves one document to the generic collection
func (c *GenericColl) Save(ctx context.Context, doc *model.GenericUpload) error {
	_, err := c.Coll.InsertOne(ctx, doc)
	return err
}

// Get return matching document if any, or error
func (c *GenericColl) Get(ctx context.Context, attr *model.GenericAttributes) (*model.GenericUpload, error) {
	filter := bson.M{
		"attributes.first_name":    attr.FirstName,
		"attributes.last_name":     attr.LastName,
		"attributes.date_of_birth": attr.DateOfBirth,
		"attributes.document_type": attr.DocumentType,
		"attributes.document_id":   attr.DocumentID,
	}

	res := &model.GenericUpload{}
	if err := c.Coll.FindOne(ctx, filter).Decode(res); err != nil {
		return nil, err
	}
	return res, nil
}

// List returns all matching documents if any, or error
func (c *GenericColl) List(ctx context.Context, attr *model.GenericAttributes) ([]model.GenericUpload, error) {
	filter := bson.M{
		"attributes.first_name":    attr.FirstName,
		"attributes.last_name":     attr.LastName,
		"attributes.date_of_birth": attr.DateOfBirth,
		"attributes.document_type": attr.DocumentType,
	}

	cursor, err := c.Coll.Find(ctx, filter)
	if err != nil {
		return nil, err
	}

	res := []model.GenericUpload{}
	if err := cursor.All(ctx, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// Revoke revokes a document
func (c *GenericColl) Revoke(ctx context.Context, attr *model.GenericAttributes) error {
	filter := bson.M{
		"attributes.first_name":    attr.FirstName,
		"attribute.last_name":      attr.LastName,
		"attributes.date_of_birth": attr.DateOfBirth,
		"attributes.document_type": attr.DocumentType,
	}
	_, err := c.Coll.DeleteOne(ctx, filter)
	return err
}
