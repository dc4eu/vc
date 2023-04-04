package gosunetca

import (
	"github.com/go-playground/validator"
)

// Check checks for validation error
func Check(s interface{}) error {
	validate := validator.New()

	err := validate.Struct(s)
	if err != nil {
		return err
	}
	return nil
}
