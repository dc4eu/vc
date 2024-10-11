package helpers

import (
	"context"
	"reflect"
	"strings"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
)

// NewValidator creates a new validator
func NewValidator() (*validator.Validate, error) {
	validate := validator.New()

	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]

		if name == "-" {
			return ""
		}

		return name
	})

	return validate, nil
}

// Check checks for validation error
func Check(ctx context.Context, cfg *model.Cfg, s any, log *logger.Log) error {
	tp, err := trace.New(ctx, cfg, "vc", log)
	if err != nil {
		return err
	}

	ctx, span := tp.Start(ctx, "helpers:check")
	defer span.End()

	validate, err := NewValidator()
	if err != nil {
		return err
	}

	if err := validate.Struct(s); err != nil {
		return NewErrorFromError(err)
	}

	return nil
}

// CheckSimple checks for validation error with a simpler signature
func CheckSimple(s any) error {
	validate, err := NewValidator()
	if err != nil {
		return err
	}

	if err := validate.Struct(s); err != nil {
		return NewErrorFromError(err)
	}

	return nil
}

type DefaultValidator struct {
	Validate *validator.Validate
}

var _ binding.StructValidator = &DefaultValidator{}

func (v *DefaultValidator) ValidateStruct(obj any) error {
	if kindOfData(obj) == reflect.Struct {
		if err := v.Validate.Struct(obj); err != nil {
			return err
		}
	}
	return nil
}

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

// BindingValidator returns a new DefaultValidator instance with validator. Used for gin binding
func BindingValidator() (*DefaultValidator, error) {
	validate, err := NewValidator()
	if err != nil {
		return nil, err
	}

	return &DefaultValidator{Validate: validate}, nil
}
