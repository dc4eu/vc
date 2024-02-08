package db

import (
	"context"
	"vc/pkg/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// DatastoreColl is the generic collection
type DatastoreColl struct {
	Service *Service
	Coll    *mongo.Collection
}

func (c *DatastoreColl) createIndex(ctx context.Context) error {
	ctx, span := c.Service.tp.Start(ctx, "db:doc:createIndex")
	defer span.End()

	indexModel := mongo.IndexModel{
		Keys: bson.M{
			"document_id": 1,
		},
	}
	_, err := c.Coll.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		return err
	}
	return nil
}

// Save saves one document to the generic collection
func (c *DatastoreColl) Save(ctx context.Context, doc *model.Upload) error {
	_, err := c.Coll.InsertOne(ctx, doc)
	return err
}

// IDMapping return authentic source person id if any
func (c *DatastoreColl) IDMapping(ctx context.Context, query *model.MetaData) (string, error) {
	filter := bson.M{
		"meta.authentic_source": bson.M{"$eq": query.AuthenticSource},
		"meta.collect_id":       bson.M{"$eq": query.CollectID},
		"meta.document_type":    bson.M{"$eq": query.DocumentType},
		"meta.document_id":      bson.M{"$eq": query.DocumentID},
		"meta.uid":              bson.M{"$eq": query.UID},
		"meta.date_of_birth":    bson.M{"$eq": query.DateOfBirth},
		"meta.last_name":        bson.M{"$eq": query.LastName},
		"meta.first_name":       bson.M{"$eq": query.FirstName},
	}
	opts := options.FindOne().SetProjection(bson.M{"meta.authentic_source_person_id": 1})
	var res string
	if err := c.Coll.FindOne(ctx, filter, opts).Decode(res); err != nil {
		return "", err
	}
	return res, nil
}

// GetDocument return matching document if any, or error
func (c *DatastoreColl) GetDocument(ctx context.Context, attr *model.MetaData) (*model.Upload, error) {
	filter := bson.M{
		"meta.authentic_source": bson.M{"$eq": attr.AuthenticSource},
		"meta.document_type":    bson.M{"$eq": attr.DocumentType},
		"meta.document_id":      bson.M{"$eq": attr.DocumentID},
	}
	opt := options.FindOne().SetProjection(bson.M{
		"meta.revocation_id": 1,
		"meta.collect_id":    1,
		"meta.document_data": 1,
	})

	res := &model.Upload{}
	if err := c.Coll.FindOne(ctx, filter, opt).Decode(res); err != nil {
		return nil, err
	}
	return res, nil
}

// GetDocumentByCollectCode return matching document if any, or error
func (c *DatastoreColl) GetDocumentByCollectCode(ctx context.Context, query *model.MetaData) (*model.Upload, error) {
	filter := bson.M{
		"meta.authentic_source": bson.M{"$eq": query.AuthenticSource},
		"meta.collect_id":       bson.M{"$eq": query.CollectID},
		"meta.document_type":    bson.M{"$eq": query.DocumentType},
		"meta.document_id":      bson.M{"$eq": query.DocumentID},
		"meta.uid":              bson.M{"$eq": query.UID},
		"meta.date_of_birth":    bson.M{"$eq": query.DateOfBirth},
		"meta.last_name":        bson.M{"$eq": query.LastName},
		"meta.first_name":       bson.M{"$eq": query.FirstName},
	}

	opt := options.FindOne().SetProjection(bson.M{
		"meta.document_type": 1,
		"meta.document_id":   1,
		"meta.revocation_id": 1,
		"meta.collect_id":    1,
		"meta.document_data": 1,
	})

	res := &model.Upload{}
	if err := c.Coll.FindOne(ctx, filter, opt).Decode(res); err != nil {
		return nil, err
	}
	return res, nil
}

// ListMetadata returns a list of information to be used for geting documents
func (c *DatastoreColl) ListMetadata(ctx context.Context, query *model.MetaData) ([]model.MetaData, error) {
	filter := bson.M{
		"meta.authentic_source":           bson.M{"$eq": query.AuthenticSource},
		"meta.authentic_source_person_id": bson.M{"$eq": query.AuthenticSourcePersonID},
	}
	opt := options.Find().SetProjection(
		bson.M{
			"meta.document_type": 1,
			"meta.document_id":   1,
			"meta.revocation_id": 1,
			"meta.collection_id": 1,
		},
	)

	cursor, err := c.Coll.Find(ctx, filter, opt)
	if err != nil {
		return nil, err
	}

	res := []model.MetaData{}
	if err := cursor.All(ctx, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// PortalData returns a list of portal data
func (c *DatastoreColl) PortalData(ctx context.Context, query *model.MetaData) ([]*model.MetaData, error) {
	filter := bson.M{
		"meta.authentic_source":           query.AuthenticSource,
		"meta.authentic_source_person_id": query.AuthenticSourcePersonID,
	}
	opt := options.Find().SetProjection(
		bson.M{
			"meta.DocumentType":  1,
			"meta.DocumentID":    1,
			"meta.revocation_id": 1,
			"meta.collect_id":    1,
			"meta.qr":            1,
		})

	cursor, err := c.Coll.Find(ctx, filter, opt)
	if err != nil {
		return nil, err
	}
	res := []*model.MetaData{}
	if err := cursor.All(ctx, &res); err != nil {
		return nil, err
	}
	return res, nil
}
