package gosunetca

import (
	"github.com/go-playground/validator"
)

// check checks for validation error
func check(s interface{}) error {
	validate := validator.New()

	err := validate.Struct(s)
	if err != nil {
		return err
	}
	return nil
}
