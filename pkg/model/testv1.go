package model

// Testv1 is the Testv1 model
type Testv1 struct {
	Name    Testv1Name    `json:"name" bson:"name" validate:"required"`
	Address Testv1Address `json:"address" bson:"address" validate:"required"`
}

// Testv1Name is the Testv1Name model
type Testv1Name struct {
	GivenName  string `json:"given_name" bson:"given_name" validate:"required"`
	FamilyName string `json:"family_name" bson:"family_name" validate:"required"`
}

// Testv1Address is the Testv1Address model
type Testv1Address struct {
	Country string `json:"country" bson:"country" validate:"required"`
	Street  string `json:"street" bson:"street" validate:"required"`
}
