package helpers

import (
	"errors"
	"fmt"
	"vc/pkg/logger"

	"github.com/go-playground/validator/v10"
)

// Check checks for validation error
func Check(s interface{}, log *logger.Log) error {
	validate := validator.New()

	err := validate.Struct(s)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			msg := fmt.Sprintf("Validation error: Field %q of type %q violates rule: %q\n", err.Namespace(), err.Kind(), err.Tag())
			return errors.New(msg)
		}
	}
	return nil
}
