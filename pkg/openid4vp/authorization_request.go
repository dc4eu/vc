package openid4vp

type PresentationDefinitionParameter struct {
	// ID The Presentation Definition **MUST** contain an id property. The value of this property **MUST** be a string. The string **SHOULD** provide a unique ID for the desired context. For example, a UUID such as 32f54163-7166-48f1-93d8-f f217bdb0653 could provide an ID that is unique in a global context, while a simple string such as my_presentation_definition_1 could be suitably unique in a local context. The id property **SHOULD** be unique within the Presentation Definition itself, meaning no other id values should exist at any level with the same value.
	ID          string `json:"id,omitempty" bson:"id,omitempty" validate:"required"`
	Title       string `json:"title,omitempty" bson:"title,omitempty" validate:"omitempty"`
	Description string `json:"description,omitempty" bson:"description,omitempty" validate:"omitempty"`

	// InputDescriptors The Presentation Definition **MUST** contain an input_descriptors property. Its value **MUST** be an array of Input Descriptor Objects, the composition of which are described in the Input Descriptors section below.
	InputDescriptors []InputDescriptor `json:"input_descriptors,omitempty" bson:"input_descriptors,omitempty" validate:"required"`

	// Name The Presentation Definition **MAY** contain a name property. If present, its value **SHOULD** be a human-friendly string intended to constitute a distinctive designation of the Presentation Definition.
	Name string `json:"name,omitempty" bson:"name,omitempty"`

	// Purpose The Presentation Definition **MAY** contain a purpose property. If present, its value **MUST** be a string that describes the purpose for which the Presentation Definition's inputs are being used for.
	Purpose string `json:"purpose,omitempty" bson:"purpose,omitempty"`
}
