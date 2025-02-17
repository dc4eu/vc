package db

import (
	"context"
	"vc/pkg/helpers"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/openid4vci"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.opentelemetry.io/otel/codes"
)

// VCWalletColl is the generic collection
type VCWalletColl struct {
	Service *Service
	Coll    *mongo.Collection
	log     *logger.Log
}

func (c *VCWalletColl) createIndex(ctx context.Context) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:datastore:createIndex")
	defer span.End()

	indexDocumentIDInAuthenticSourceUniq := mongo.IndexModel{
		Keys: bson.D{
			primitive.E{Key: "meta.document_id", Value: 1},
			primitive.E{Key: "meta.authentic_source", Value: 1},
			primitive.E{Key: "meta.document_type", Value: 1},
		},
		Options: options.Index().SetName("document_unique_within_namespace").SetUnique(true),
	}
	_, err := c.Coll.Indexes().CreateMany(ctx, []mongo.IndexModel{indexDocumentIDInAuthenticSourceUniq})
	if err != nil {
		return err
	}
	return nil
}

// Save saves one document to the generic collection
func (c *VCWalletColl) Save(ctx context.Context, doc *model.CompleteDocument) error {
	ctx, span := c.Service.tracer.Start(ctx, "db:vc:datastore:save")
	defer span.End()

	_, err := c.Coll.InsertOne(ctx, doc)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())

		return err
	}

	return nil
}

// AddDocumentIdentityQuery is the query to add document identity
type AddDocumentIdentityQuery struct {
	AuthenticSource string            `json:"authentic_source" bson:"authentic_source"`
	DocumentType    string            `json:"document_type" bson:"document_type"`
	DocumentID      string            `json:"document_id" bson:"document_id"`
	Identities      []*model.Identity `json:"identities" bson:"identities"`
}

// AddDocumentIdentity adds document identity
func (c *VCWalletColl) AddDocumentIdentity(ctx context.Context, query *AddDocumentIdentityQuery) error {
	filter := bson.M{
		"meta.authentic_source": bson.M{"$eq": query.AuthenticSource},
		"meta.document_id":      bson.M{"$eq": query.DocumentID},
		"meta.document_type":    bson.M{"$eq": query.DocumentType},
	}

	// This needs to make sure no duplicate authentic_source_person_id is added in the future
	update := bson.M{"$addToSet": bson.M{"identities": bson.M{"$each": query.Identities}}}

	result, err := c.Coll.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if result.ModifiedCount == 0 {
		return helpers.ErrNoDocumentFound
	}

	return nil
}

// DeleteDocumentIdentityQuery is the query to delete identity in document
type DeleteDocumentIdentityQuery struct {
	AuthenticSource         string `json:"authentic_source" bson:"authentic_source"`
	DocumentType            string `json:"document_type" bson:"document_type"`
	DocumentID              string `json:"document_id" bson:"document_id"`
	AuthenticSourcePersonID string `json:"authentic_source_person_id" bson:"authentic_source_person_id"`
}

// DeleteDocumentIdentity deletes identity in document
func (c *VCWalletColl) DeleteDocumentIdentity(ctx context.Context, query *DeleteDocumentIdentityQuery) error {
	filter := bson.M{
		"meta.authentic_source": bson.M{"$eq": query.AuthenticSource},
		"meta.document_id":      bson.M{"$eq": query.DocumentID},
		"meta.document_type":    bson.M{"$eq": query.DocumentType},
	}

	update := bson.M{"$pull": bson.M{"identities": bson.M{"authentic_source_person_id": query.AuthenticSourcePersonID}}}
	_, err := c.Coll.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	return nil
}

// GetDocumentQuery is the query to get document attestation
type GetDocumentQuery struct {
	Meta     *model.MetaData
	Identity *model.Identity
}

// GetDocument return matching document if any, or error
func (c *VCWalletColl) GetDocument(ctx context.Context, query *GetDocumentQuery) (*model.Document, error) {
	filter := bson.M{
		"meta.authentic_source": bson.M{"$eq": query.Meta.AuthenticSource},
		"meta.document_type":    bson.M{"$eq": query.Meta.DocumentType},
		"meta.document_id":      bson.M{"$eq": query.Meta.DocumentID},
		//"identities.authentic_source_person_id": bson.M{"$eq": query.Identity.AuthenticSourcePersonID},
	}
	opt := options.FindOne().SetProjection(bson.M{
		"meta":          1,
		"document_data": 1,
	})

	res := &model.CompleteDocument{}
	if err := c.Coll.FindOne(ctx, filter, opt).Decode(res); err != nil {
		return nil, err
	}

	reply := &model.Document{
		Meta:         res.Meta,
		DocumentData: res.DocumentData,
	}
	return reply, nil
}

// DocumentListQuery is the query to get document list
type DocumentListQuery struct {
	AuthenticSource string          `json:"authentic_source" bson:"authentic_source"`
	Identity        *model.Identity `json:"identity" bson:"identity" validate:"required"`
	DocumentType    string          `json:"document_type" bson:"document_type"`
	ValidFrom       int64           `json:"valid_from" bson:"valid_from"`
	ValidTo         int64           `json:"valid_to" bson:"valid_to"`
}

// DocumentList return matching documents if any, or error
func (c *VCWalletColl) DocumentList(ctx context.Context, query *DocumentListQuery) ([]*model.DocumentList, error) {
	if err := helpers.Check(ctx, c.Service.cfg, query, c.Service.log); err != nil {
		return nil, err
	}

	filter := bson.M{
		"identities.schema.name": bson.M{"$eq": query.Identity.Schema.Name},
	}

	if query.AuthenticSource != "" {
		filter["meta.authentic_source"] = bson.M{"$eq": query.AuthenticSource}
	}

	if query.DocumentType != "" {
		filter["meta.document_type"] = bson.M{"$eq": query.DocumentType}
	}

	if query.Identity.AuthenticSourcePersonID != "" {
		filter["identities.authentic_source_person_id"] = bson.M{"$eq": query.Identity.AuthenticSourcePersonID}
	} else {
		filter["identities.family_name"] = bson.M{"$eq": query.Identity.FamilyName}
		filter["identities.given_name"] = bson.M{"$eq": query.Identity.GivenName}
		filter["identities.birth_date"] = bson.M{"$eq": query.Identity.BirthDate}
	}

	cursor, err := c.Coll.Find(ctx, filter)
	if err != nil {
		return nil, err
	}

	res := []*model.DocumentList{}
	if err := cursor.All(ctx, &res); err != nil {
		return nil, err
	}

	return res, nil
}

// GetQR return matching document and return its QR code, else error
func (c *VCWalletColl) GetQR(ctx context.Context, attr *model.MetaData) (*openid4vci.QR, error) {
	filter := bson.M{
		"meta.authentic_source": bson.M{"$eq": attr.AuthenticSource},
		"meta.document_type":    bson.M{"$eq": attr.DocumentType},
		"meta.document_id":      bson.M{"$eq": attr.DocumentID},
	}
	opt := options.FindOne().SetProjection(bson.M{
		"qr": 1,
	})

	res := &model.CompleteDocument{}
	if err := c.Coll.FindOne(ctx, filter, opt).Decode(res); err != nil {
		return nil, err
	}
	return res.QR, nil
}

// GetDocumentCollectIDQuery is the query to get document attestation
type GetDocumentCollectIDQuery struct {
	Identity *model.Identity
	Meta     *model.MetaData
}

// GetDocumentCollectID return matching document if any, or error
func (c *VCWalletColl) GetDocumentCollectID(ctx context.Context, query *GetDocumentCollectIDQuery) (*model.Document, error) {
	filter := bson.M{
		"meta.authentic_source":  bson.M{"$eq": query.Meta.AuthenticSource},
		"meta.collect.id":        bson.M{"$eq": query.Meta.Collect.ID},
		"meta.document_type":     bson.M{"$eq": query.Meta.DocumentType},
		"identities.schema.name": bson.M{"$eq": query.Identity.Schema.Name},
	}

	if query.Identity.AuthenticSourcePersonID != "" {
		filter["identities.authentic_source_person_id"] = bson.M{"$eq": query.Identity.AuthenticSourcePersonID}
	} else {
		filter["identities.family_name"] = bson.M{"$eq": query.Identity.FamilyName}
		filter["identities.given_name"] = bson.M{"$eq": query.Identity.GivenName}
		filter["identities.birth_date"] = bson.M{"$eq": query.Identity.BirthDate}
	}

	opts := options.FindOne().SetProjection(bson.M{
		"meta":          1,
		"document_data": 1,
	})

	res := &model.CompleteDocument{}
	if err := c.Coll.FindOne(ctx, filter, opts).Decode(res); err != nil {
		return nil, err
	}

	reply := &model.Document{
		Meta:         res.Meta,
		DocumentData: res.DocumentData,
	}
	return reply, nil
}

// GetByRevocationID gets one document by meta.revocation.id and meta.authentic_source
func (c *VCWalletColl) GetByRevocationID(ctx context.Context, q *model.MetaData) (*model.CompleteDocument, error) {
	filter := bson.M{
		"meta.authentic_source": bson.M{"$eq": q.AuthenticSource},
		"meta.document_type":    bson.M{"$eq": q.DocumentType},
		"meta.revocation.id":    bson.M{"$eq": q.Revocation.ID},
	}
	res := &model.CompleteDocument{}
	if err := c.Coll.FindOne(ctx, filter).Decode(res); err != nil {
		return nil, err
	}
	return res, nil
}
