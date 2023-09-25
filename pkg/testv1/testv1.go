package testv1

// Document is the Testv1 model
type Document struct {
	Name    Name    `json:"name" bson:"name" validate:"required"`
	Address Address `json:"address" bson:"address" validate:"required"`
}

// Name is the Name model
type Name struct {
	GivenName  string `json:"given_name" bson:"given_name" validate:"required"`
	FamilyName string `json:"family_name" bson:"family_name" validate:"required"`
}

// Address is the Address model
type Address struct {
	Country string `json:"country" bson:"country" validate:"required"`
	Street  string `json:"street" bson:"street" validate:"required"`
}
