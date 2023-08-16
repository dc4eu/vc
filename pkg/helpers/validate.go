package helpers

import (
	"reflect"
	"strings"
	"vc/pkg/logger"

	"github.com/go-playground/validator/v10"
)

// Check checks for validation error
func Check(s any, log *logger.Log) error {
	validate := validator.New()
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]

		if name == "-" {
			return ""
		}

		return name
	})

	err := validate.Struct(s)
	if err != nil {
		return NewErrorFromError(err)
	}
	return nil
}
