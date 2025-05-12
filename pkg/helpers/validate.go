package helpers

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/go-playground/validator/v10"
	"github.com/kaptinlin/jsonschema"
)

// NewValidator creates a new validator
func NewValidator() (*validator.Validate, error) {
	validate := validator.New(validator.WithRequiredStructEnabled())

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

	_, span := tp.Start(ctx, "helpers:check")
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

// ValidateDocumentData validates DocumentData against the schemaRef in MetaData.DocumentDataValidationRef
func ValidateDocumentData(ctx context.Context, completeDocument *model.CompleteDocument, log *logger.Log) error {
	_, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	if completeDocument.Meta.DocumentDataValidationRef == "" {
		return nil
	}

	if completeDocument.DocumentData == nil {
		return fmt.Errorf("no document data")
	}

	compiler := jsonschema.NewCompiler()

	jsonSchema, err := getValidationSchema(completeDocument.Meta.DocumentDataValidationRef, compiler)
	if err != nil {
		return err
	}

	result := jsonSchema.Validate(completeDocument.DocumentData)

	if !result.IsValid() {
		return NewErrorFromError(result)
	}

	return nil
}
