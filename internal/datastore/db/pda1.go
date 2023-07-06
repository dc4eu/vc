package db

import (
	"context"
	"vc/pkg/model"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// PDA1Coll is the collection of PDA1 documents
type PDA1Coll struct {
	Service *Service
	Coll    *mongo.Collection
}

func (c *PDA1Coll) createIndex(ctx context.Context) error {
	indexModel := mongo.IndexModel{
		Keys: bson.M{"meta.upload_id": 1},
	}
	_, err := c.Coll.Indexes().CreateOne(ctx, indexModel)
	if err != nil {
		return err
	}
	return nil
}

// PDA1Upload is the uploaded document
type PDA1Upload struct {
	Data *model.PDA1 `json:"data" validate:"required"`
	Meta *model.Meta `json:"meta"`
}

// Save saves one document to the PDA1 collection
func (c *PDA1Coll) Save(ctx context.Context, doc *PDA1Upload) error {
	_, err := c.Coll.InsertOne(ctx, doc)
	return err
}

// GetID return matching document with id if any, or error
func (c *PDA1Coll) GetID(ctx context.Context, id string) (*PDA1Upload, error) {
	filter := bson.M{"meta.upload_id": id}
	res := &PDA1Upload{}
	if err := c.Coll.FindOne(ctx, filter).Decode(res); err != nil {
		return nil, err
	}
	return res, nil
}

// PDA1SearchAttributes is the search attributes
type PDA1SearchAttributes struct {
	PersonalIdentificationNumber string `json:"personalidentificationnumber" bson:"personal_identification_number"`
	Sex                          string `json:"sex"`
	Surname                      string `json:"surname"`
	Forenames                    string `json:"forenames"`
	SurnameAtBirth               string `json:"surnameatbirth" bson:"surname_at_birth"`
	DateBirth                    string `json:"datebirth" bson:"date_birth"`
}

// Search returns matching document if any, or error
// This needs a clear definition of uniqueness in terms of the search attributes
// Maybe have a pre-defined set of search attributes that needs to be present in order to guarantee uniqueness?
func (c *PDA1Coll) Search(ctx context.Context, d *PDA1SearchAttributes) (*model.PDA1, error) {
	filter := bson.M{}

	if d.PersonalIdentificationNumber != "" {
		filter["data.personal_details.personal_identification_number"] = d.PersonalIdentificationNumber
	}
	if d.Sex != "" {
		filter["data.personal_details.sex"] = d.Sex
	}
	if d.Surname != "" {
		filter["data.personal_details.surname"] = d.Surname
	}
	if d.Forenames != "" {
		filter["data.personal_details.forenames"] = d.Forenames
	}
	if d.SurnameAtBirth != "" {
		filter["data.personal_details.surname_at_birth"] = d.SurnameAtBirth
	}
	if d.DateBirth != "" {
		filter["data.personal_details.date_birth"] = d.DateBirth
	}

	c.Service.log.Debug("Search filter", filter)

	res := &PDA1Upload{}
	if err := c.Coll.FindOne(ctx, filter).Decode(res); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, ErrNoDocuments
		}
		return nil, err
	}
	return res.Data, nil
}
