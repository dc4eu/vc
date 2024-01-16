package helpers

import (
	"context"
	"reflect"
	"strings"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/go-playground/validator/v10"
)

// Check checks for validation error
func Check(ctx context.Context, cfg *model.Cfg, s any, log *logger.Log) error {
	tp, err := trace.New(ctx, cfg, log, "vc", "vc")
	if err != nil {
		return err
	}

	ctx, span := tp.Start(ctx, "helpers:check")
	defer span.End()

	validate := validator.New()
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]

		if name == "-" {
			return ""
		}

		return name
	})

	if err := validate.Struct(s); err != nil {
		return NewErrorFromError(err)
	}

	return nil
}
