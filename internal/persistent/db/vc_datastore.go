package db

import (
	"context"
	"errors"
	"time"
	"vc/pkg/model"

	"github.com/masv3971/gosunetca/types"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.opentelemetry.io/otel/codes"
)

// VCDatastoreColl is the collection of datastore
type VCDatastoreColl struct {
	service *Service
	coll    *mongo.Collection
}

func (c *VCDatastoreColl) createIndex(ctx context.Context) error {
	ctx, span := c.service.tp.Start(ctx, "db:vc:datastore:createIndex")
	defer span.End()

	indexDocumentIDInAuthenticSourceUniq := mongo.IndexModel{
		Keys: bson.D{
			primitive.E{Key: "meta.document_id", Value: 1},
			primitive.E{Key: "meta.authentic_source", Value: 1},
		},
		Options: options.Index().SetName("document_id_uniq").SetUnique(true),
	}
	indexes, err := c.coll.Indexes().CreateMany(ctx, []mongo.IndexModel{indexDocumentIDInAuthenticSourceUniq})
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	c.service.log.Info("created indexes", "indexes", indexes)

	return nil
}

// Save saves one document
func (c *VCDatastoreColl) Save(ctx context.Context, doc *model.Upload) error {
	ctx, span := c.service.tp.Start(ctx, "db:vc:datastore:save")
	defer span.End()

	res, err := c.coll.InsertOne(ctx, doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	c.service.log.Info("saved document", "document_id", doc.Meta.DocumentID, "inserted_id", res.InsertedID)
	return nil
}

// Delete deletes a document
func (c *VCDatastoreColl) Delete(ctx context.Context, doc *model.MetaData) error {
	ctx, span := c.service.tp.Start(ctx, "db:vc:datastore:delete")
	defer span.End()

	filter := bson.M{
		"meta.document_id":      bson.M{"$eq": doc.DocumentID},
		"meta.authentic_source": bson.M{"$eq": doc.AuthenticSource},
	}
	_, err := c.coll.DeleteOne(ctx, filter)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	c.service.log.Info("deleted document", "document_id", doc.DocumentID, "from authentic_source", doc.AuthenticSource)
	return nil

}

// Revoke revokes a document
func (c *VCDatastoreColl) Revoke(ctx context.Context, transactionID string) error {
	ctx, span := c.service.tp.Start(ctx, "db:vc:datastore:revoke")
	defer span.End()

	filter := bson.M{
		"transaction_id": bson.M{"$eq": transactionID},
	}
	update := bson.M{
		"$set": bson.M{
			"revoked_ts": time.Now().Unix(),
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
func (c *VCDatastoreColl) IsRevoked(ctx context.Context, transactionID string) bool {
	ctx, span := c.service.tp.Start(ctx, "db:vc:datastore:isRevoked")
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
func (c *VCDatastoreColl) Get(ctx context.Context, transactionID string) (*types.Document, error) {
	ctx, span := c.service.tp.Start(ctx, "db:vc:datastore:get")
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
