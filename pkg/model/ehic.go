package model

// EHIC is the EHIC model
type EHIC struct {
	ID string `json:"id" bson:"id" validate:"required"`
}
