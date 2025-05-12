package httphelpers

import (
	"context"
	"net/http"
	"reflect"
	"time"
	"vc/pkg/logger"
	"vc/pkg/openid4vci"

	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

type validatorHandler struct {
	log    *logger.Log
	client *Client
}

// DefaultValidator is the default validator for httphelpers
type DefaultValidator struct {
	Validate *validator.Validate
}

var _ binding.StructValidator = &DefaultValidator{}

// ValidateStruct satisfies the binding.StructValidator interface
func (v *DefaultValidator) ValidateStruct(obj any) error {
	if kindOfData(obj) == reflect.Struct {
		if err := v.Validate.Struct(obj); err != nil {
			return err
		}
	}
	return nil
}

// Engine satisfy the binding.Validator interface
func (v *DefaultValidator) Engine() any {
	return v.Validate
}

func kindOfData(data any) reflect.Kind {
	value := reflect.ValueOf(data)
	valueType := value.Kind()
	if valueType == reflect.Ptr {
		valueType = value.Elem().Kind()
	}
	return valueType
}

// StatusCode returns the status code of the error
func StatusCode(ctx context.Context, err error) int {
	_, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	switch err := err.(type) {
	case *openid4vci.Error:
		return openid4vci.StatusCode(err)
	default:
		return http.StatusTeapot
	}
}
