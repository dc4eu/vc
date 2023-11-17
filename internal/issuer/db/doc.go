package db

import (
	"context"
	"errors"
	"time"

	"github.com/masv3971/gosunetca/types"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.opentelemetry.io/otel/codes"
)

// PDFColl is the collection of documents
type PDFColl struct {
	service *Service
	coll    *mongo.Collection
}

func (c *PDFColl) createIndex(ctx context.Context) error {
	ctx, span := c.service.tp.Start(ctx, "db:doc:createIndex")
	defer span.End()

	indexModel := mongo.IndexModel{
		Keys: bson.M{"transaction_id": 1},
	}
	_, err := c.coll.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// Save saves one document
func (c *PDFColl) Save(ctx context.Context, doc *types.Document) error {
	ctx, span := c.service.tp.Start(ctx, "db:doc:save")
	defer span.End()

	_, err := c.coll.InsertOne(ctx, doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// Revoke revokes a document
func (c *PDFColl) Revoke(ctx context.Context, transactionID string) error {
	ctx, span := c.service.tp.Start(ctx, "db:doc:revoke")
	defer span.End()

	filter := bson.M{
		"transaction_id": bson.M{"$eq": transactionID},
	}
	update := bson.M{
		"$set": bson.M{
			"revoke_ts": time.Now().Unix(),
		},
	}
	_, err := c.coll.UpdateOne(ctx, filter, update)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

// IsRevoked checks if a document is revoked
func (c *PDFColl) IsRevoked(ctx context.Context, transactionID string) bool {
	ctx, span := c.service.tp.Start(ctx, "db:doc:isRevoked")
	defer span.End()

	doc, err := c.Get(ctx, transactionID)
	if err != nil {
		span.SetStatus(codes.Ok, "document not found")
		return false
	}

	if doc.RevokedTS != 0 {
		return true
	}
	return false
}

// Get gets one document
func (c *PDFColl) Get(ctx context.Context, transactionID string) (*types.Document, error) {
	ctx, span := c.service.tp.Start(ctx, "db:doc:get")
	defer span.End()

	reply := &types.Document{}
	filter := bson.M{
		"transaction_id": bson.M{"$eq": transactionID},
	}
	err := c.coll.FindOne(ctx, filter).Decode(reply)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			span.SetStatus(codes.Ok, "document not found")
			return nil, errors.New("no document found")
		}
		return nil, err
	}
	return reply, nil
}
