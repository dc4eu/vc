package eidas

// Identification is the EIDAS identification model
type Identification struct {
	FirstName   string   `json:"firstName" bson:"firstName" validate:"required"`
	LastName    string   `json:"lastName" bson:"lastName" validate:"required"`
	Gender      string   `json:"gender" bson:"gender" validate:"required"`
	PINS        []string `json:"pins" bson:"pins" validate:"required"`
	ExhibitorID string   `json:"exhibitorID" bson:"exhibitorID" validate:"required"`
}
