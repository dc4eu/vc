package helpers

import (
	"testing"
	"vc/pkg/model"

	"github.com/stretchr/testify/assert"
)

func TestValidationIdentity(t *testing.T) {
	tts := []struct {
		name string
		have *model.Identity
		want error
	}{
		{
			name: "empty",
			have: &model.Identity{},
			want: &Error{
				Title: "validation_error",
				Details: []map[string]interface{}{
					{
						"field":           "schema",
						"namespace":       "schema",
						"type":            "ptr",
						"validation":      "required",
						"validationParam": "",
						"value":           (*model.IdentitySchema)(nil),
					},
					{
						"field":           "birth_date",
						"namespace":       "birth_date",
						"type":            "string",
						"validation":      "datetime",
						"validationParam": "2006-01-02",
						"value":           "",
					},
				},
			},
		},
		{
			name: "ok",
			have: &model.Identity{
				Schema: &model.IdentitySchema{
					Name:    "SE",
					Version: "1.0.0",
				},
				BirthDate: "1970-01-01",
			},
			want: nil,
		},
		{
			name: "wrong datetime format",
			have: &model.Identity{
				Schema: &model.IdentitySchema{
					Name: "SE",
				},
				BirthDate: "1972-10-27 10:15:31.432635902 +0000 UTC",
			},
			want: &Error{
				Title: "validation_error",
				Details: []map[string]interface{}{
					{
						"field":           "birth_date",
						"namespace":       "birth_date",
						"type":            "string",
						"validation":      "datetime",
						"validationParam": "2006-01-02",
						"value":           "1972-10-27 10:15:31.432635902 +0000 UTC",
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckSimple(tt.have)
			assert.Equal(t, tt.want, got)
		})
	}
}

var identity = &model.Identity{
	Schema: &model.IdentitySchema{
		Name: "SE",
	},
	BirthDate: "1970-01-01",
}

func TestValidationArrayOfIdentity(t *testing.T) {
	tts := []struct {
		name string
		have []model.Identity `validate:"dive"`
		want error
	}{
		{
			name: "Correct datetime format",
			have: []model.Identity{
				{
					Schema: &model.IdentitySchema{
						Name: "SE",
					},
					BirthDate: "1972-10-27",
				},
			},
			want: nil,
		},
		{
			name: "wrong datetime format",
			have: []model.Identity{
				{
					Schema: &model.IdentitySchema{
						Name: "SE",
					},
					BirthDate: "1972-10-27 10:15:31.432635902 +0000 UTC",
				},
			},
			want: &Error{
				Title: "validation_error",
				Details: []map[string]interface{}{
					{
						"field":           "birth_date",
						"namespace":       "birth_date",
						"type":            "string",
						"validation":      "datetime",
						"validationParam": "2006-01-02",
						"value":           "1972-10-27 10:15:31.432635902 +0000 UTC",
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckSimple(tt.have[0])
			assert.Equal(t, tt.want, got)
		})
	}
}
