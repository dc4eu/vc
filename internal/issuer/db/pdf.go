package db

import (
	"context"
	"errors"
	"time"
	"vc/pkg/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// PDFColl is the collection of documents
type PDFColl struct {
	service *Service
	coll    *mongo.Collection
}

func (c *PDFColl) createIndex(ctx context.Context) error {
	indexModel := mongo.IndexModel{
		Keys: bson.M{"transaction_id": 1},
	}
	_, err := c.coll.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		return err
	}
	return nil
}

// Save saves one document
func (c *PDFColl) Save(ctx context.Context, doc *model.Document) error {
	_, err := c.coll.InsertOne(ctx, doc)
	return err
}

// AddSigned adds a signed document to a document
func (c *PDFColl) AddSigned(ctx context.Context, transactionID string, doc *model.Document) error {
	filter := bson.M{"transaction_id": transactionID}
	update := bson.M{"$set": bson.M{"signed": doc}}
	_, err := c.coll.UpdateOne(ctx, filter, update)
	return err
}

// Get gets one document
func (c *PDFColl) Get(ctx context.Context, transactionID string) (*model.Document, error) {
	reply := &model.Document{}
	filter := bson.M{"transaction_id": transactionID}
	err := c.coll.FindOne(ctx, filter).Decode(reply)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.New("no document found")
		}
		return nil, err
	}
	return reply, nil
}

// Revoke revokes all documents for a ladokUID
func (c *PDFColl) Revoke(ctx context.Context, ladokUID string) error {
	revokeTS := time.Now().Unix()
	filter := bson.M{"ladok_uid": ladokUID}
	update := bson.M{"$set": bson.M{"revoked_ts": revokeTS}}
	_, err := c.coll.UpdateMany(ctx, filter, update)
	if err != nil {
		return err
	}

	return nil
}
