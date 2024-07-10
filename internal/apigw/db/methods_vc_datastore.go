package db

import (
	"context"
	"vc/pkg/helpers"
	"vc/pkg/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// VCDatastoreColl is the generic collection
type VCDatastoreColl struct {
	Service *Service
	Coll    *mongo.Collection
}

func (c *VCDatastoreColl) createIndex(ctx context.Context) error {
	ctx, span := c.Service.tp.Start(ctx, "db:vc:datastore:createIndex")
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
func (c *VCDatastoreColl) Save(ctx context.Context, doc *model.CompleteDocument) error {
	_, err := c.Coll.InsertOne(ctx, doc)
	return err
}

// IDMappingQuery is the query to get authentic source person id
type IDMappingQuery struct {
	AuthenticSource string
	Identity        *model.Identity
}

// IDMapping return authentic source person id if any
func (c *VCDatastoreColl) IDMapping(ctx context.Context, query *IDMappingQuery) (string, error) {
	filter := bson.M{
		"meta.authentic_source":     bson.M{"$eq": query.AuthenticSource},
		"identities.schema.version": bson.M{"$eq": query.Identity.Schema.Version},
		"identities.family_name":    bson.M{"$eq": query.Identity.FamilyName},
		"identities.given_name":     bson.M{"$eq": query.Identity.GivenName},
		"identities.birth_date":     bson.M{"$eq": query.Identity.BirthDate},
	}

	opts := options.FindOne().SetProjection(bson.M{
		"identities.authentic_source_person_id": 1,
	})
	res := &model.CompleteDocument{}
	if err := c.Coll.FindOne(ctx, filter, opts).Decode(&res); err != nil {
		return "", err
	}
	if res.Identities == nil || len(res.Identities) == 0 {
		return "", helpers.ErrNoIdentityFound
	}

	return res.Identities[0].AuthenticSourcePersonID, nil
}

// AddDocumentIdentityQuery is the query to add document identity
type AddDocumentIdentityQuery struct {
	AuthenticSource string            `json:"authentic_source" bson:"authentic_source"`
	DocumentType    string            `json:"document_type" bson:"document_type"`
	DocumentID      string            `json:"document_id" bson:"document_id"`
	Identities      []*model.Identity `json:"identities" bson:"identities"`
}

// AddDocumentIdentity adds document identity
func (c *VCDatastoreColl) AddDocumentIdentity(ctx context.Context, query *AddDocumentIdentityQuery) error {
	filter := bson.M{
		"meta.authentic_source": bson.M{"$eq": query.AuthenticSource},
		"meta.document_id":      bson.M{"$eq": query.DocumentID},
		"meta.document_type":    bson.M{"$eq": query.DocumentType},
	}

	// This needs to make sure no duplicate authentic_source_person_id is added in the future
	update := bson.M{"$addToSet": bson.M{"identities": bson.M{"$each": query.Identities}}}

	_, err := c.Coll.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
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
func (c *VCDatastoreColl) DeleteDocumentIdentity(ctx context.Context, query *DeleteDocumentIdentityQuery) error {
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
func (c *VCDatastoreColl) GetDocument(ctx context.Context, query *GetDocumentQuery) (*model.Document, error) {
	filter := bson.M{
		"meta.authentic_source": bson.M{"$eq": query.Meta.AuthenticSource},
		"meta.document_type":    bson.M{"$eq": query.Meta.DocumentType},
		"meta.document_id":      bson.M{"$eq": query.Meta.DocumentID},
	}
	opt := options.FindOne().SetProjection(bson.M{
		"meta.authentic_source_person_id": 1,
		"meta.authentic_source":           1,
		"meta.document_type":              1,
		"meta.document_id":                1,
		"meta.revocation":                 1,
		"meta.collect_id":                 1,
		"meta.document_version":           1,
		"meta.valid_from":                 1,
		"meta.valid_to":                   1,
		"document_data":                   1,
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

// GetQR return matching document and return its QR code, else error
func (c *VCDatastoreColl) GetQR(ctx context.Context, attr *model.MetaData) (*model.QR, error) {
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
func (c *VCDatastoreColl) GetDocumentCollectID(ctx context.Context, query *GetDocumentCollectIDQuery) (*model.Document, error) {
	filter := bson.M{
		"meta.authentic_source":   bson.M{"$eq": query.Meta.AuthenticSource},
		"meta.collect_id":         bson.M{"$eq": query.Meta.Collect.ID},
		"meta.document_type":      bson.M{"$eq": query.Meta.DocumentType},
		"identity.schema.version": bson.M{"$eq": query.Identity.Schema.Version},
		"identity.family_name":    bson.M{"$eq": query.Identity.FamilyName},
		"identity.given_name":     bson.M{"$eq": query.Identity.GivenName},
		"identity.birth_date":     bson.M{"$eq": query.Identity.BirthDate},
	}

	opt := options.FindOne().SetProjection(bson.M{
		"meta.document_type":              1,
		"meta.document_id":                1,
		"meta.document_version":           1,
		"meta.revocation_id":              1,
		"meta.revoked":                    1,
		"meta.collect_id":                 1,
		"meta.authentic_source_person_id": 1,
		"meta.authentic_source":           1,
		"meta.valid_from":                 1,
		"meta.valid_to":                   1,
		"document_data":                   1,
	})

	res := &model.Document{}
	if err := c.Coll.FindOne(ctx, filter, opt).Decode(res); err != nil {
		return nil, err
	}
	return res, nil
}

// PortalQuery is the query to get portal data
type PortalQuery struct {
	AuthenticSource         string
	AuthenticSourcePersonID string
	DocumentType            string
	ValidTo                 int64
	ValidFrom               int64
}

// PortalData returns a list of portal data
func (c *VCDatastoreColl) PortalData(ctx context.Context, query *PortalQuery) ([]model.CompleteDocument, error) {
	filter := bson.M{
		"meta.authentic_source":           bson.M{"$eq": query.AuthenticSource},
		"meta.authentic_source_person_id": bson.M{"$eq": query.AuthenticSourcePersonID},
	}

	if query.ValidFrom != 0 {
		filter["meta.valid_from"] = bson.M{"$gte": query.ValidFrom}
	}
	if query.ValidTo != 0 {
		c.Service.log.Debug("filter", "valid_to", query.ValidTo)
		filter["meta.valid_to"] = bson.M{"$lte": query.ValidTo}
	}

	if query.DocumentType != "" {
		filter["meta.document_type"] = bson.M{"$eq": query.DocumentType}
	}

	cursor, err := c.Coll.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	res := []model.CompleteDocument{}
	if err := cursor.All(ctx, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// Get gets one document
func (c *VCDatastoreColl) Get(ctx context.Context, doc *model.MetaData) (*model.CompleteDocument, error) {
	filter := bson.M{
		"meta.document_id":      bson.M{"$eq": doc.DocumentID},
		"meta.authentic_source": bson.M{"$eq": doc.AuthenticSource},
		"meta.document_type":    bson.M{"$eq": doc.DocumentType},
	}
	res := &model.CompleteDocument{}
	if err := c.Coll.FindOne(ctx, filter).Decode(res); err != nil {
		return nil, err
	}
	return res, nil
}

// GetByRevocationID gets one document by meta.revocation.id and meta.authentic_source
func (c *VCDatastoreColl) GetByRevocationID(ctx context.Context, q *model.MetaData) (*model.CompleteDocument, error) {
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
