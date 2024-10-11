package db

import (
	"context"
	"vc/pkg/model"

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
	ctx, span := c.service.tracer.Start(ctx, "db:vc:datastore:createIndex")
	defer span.End()

	indexDocumentIDInAuthenticSourceUniq := mongo.IndexModel{
		Keys: bson.D{
			primitive.E{Key: "meta.document_id", Value: 1},
			primitive.E{Key: "meta.authentic_source", Value: 1},
		},
		Options: options.Index().SetName("document_id_uniq").SetUnique(true),
	}
	_, err := c.coll.Indexes().CreateMany(ctx, []mongo.IndexModel{indexDocumentIDInAuthenticSourceUniq})
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	return nil
}

// Save saves one document
func (c *VCDatastoreColl) Save(ctx context.Context, doc *model.CompleteDocument) error {
	ctx, span := c.service.tracer.Start(ctx, "db:vc:datastore:save")
	defer span.End()

	res, err := c.coll.InsertOne(ctx, doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	c.service.log.Info("saved document", "document_id", doc.Meta.DocumentID, "inserted_id", res.InsertedID)
	return nil
}

// Get gets one document
func (c *VCDatastoreColl) Get(ctx context.Context, doc *model.MetaData) (*model.CompleteDocument, error) {
	ctx, span := c.service.tracer.Start(ctx, "db:vc:datastore:get")
	defer span.End()

	filter := bson.M{
		"meta.document_id":      bson.M{"$eq": doc.DocumentID},
		"meta.authentic_source": bson.M{"$eq": doc.AuthenticSource},
	}
	res := &model.CompleteDocument{}
	if err := c.coll.FindOne(ctx, filter).Decode(res); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	return res, nil
}

// Replace replaces one document
func (c *VCDatastoreColl) Replace(ctx context.Context, doc *model.CompleteDocument) error {
	ctx, span := c.service.tracer.Start(ctx, "db:vc:datastore:replace")
	defer span.End()

	filter := bson.M{
		"meta.document_id":      bson.M{"$eq": doc.Meta.DocumentID},
		"meta.authentic_source": bson.M{"$eq": doc.Meta.AuthenticSource},
	}

	_, err := c.coll.ReplaceOne(ctx, filter, doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	c.service.log.Info("updated document", "document_id", doc.Meta.DocumentID)
	return nil
}

// Delete deletes a document
func (c *VCDatastoreColl) Delete(ctx context.Context, doc *model.MetaData) error {
	ctx, span := c.service.tracer.Start(ctx, "db:vc:datastore:delete")
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
