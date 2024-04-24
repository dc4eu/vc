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

var iso31661Alpha3EU = map[string]bool{
	"AUT": true, "BEL": true, "BGR": true, "HRV": true, "CYP": true,
	"CZE": true, "DNK": true, "EST": true, "FIN": true, "FRA": true,
	"DEU": true, "GRC": true, "HUN": true, "IRL": true, "ITA": true,
	"LVA": true, "LTU": true, "LUX": true, "MLT": true, "NLD": true,
	"POL": true, "PRT": true, "ROU": true, "SVK": true, "SVN": true,
	"ESP": true, "SWE": true,
}

var iso31661Alpha2EU = map[string]bool{
	"AT": true, "BE": true, "BG": true, "HR": true, "CY": true,
	"CZ": true, "DK": true, "EE": true, "FI": true, "FR": true,
	"DE": true, "GR": true, "HU": true, "IE": true, "IT": true,
	"LV": true, "LT": true, "LU": true, "MT": true, "NL": true,
	"PL": true, "PT": true, "RO": true, "SK": true, "SI": true,
	"ES": true, "SE": true,
}

// NewValidator creates a new validator
func NewValidator() (*validator.Validate, error) {
	validate := validator.New()
	if err := validate.RegisterValidation("iso3166_1_alpha3_eu", ISO31661Alpha3EUValidator); err != nil {
		return nil, err
	}

	if err := validate.RegisterValidation("iso3166_1_alpha2_eu", ISO31661Alpha2EUValidator); err != nil {
		return nil, err
	}

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
	tp, err := trace.New(ctx, cfg, log, "vc", "vc")
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

// ISO31661Alpha3EUValidator validates the ISO31661 Alpha3 code for EU countries
func ISO31661Alpha3EUValidator(fl validator.FieldLevel) bool {
	val := fl.Field().String()
	return iso31661Alpha3EU[val]
}

// ISO31661Alpha2EUValidator validates the ISO31661 Alpha2 code for EU countries
func ISO31661Alpha2EUValidator(fl validator.FieldLevel) bool {
	val := fl.Field().String()
	return iso31661Alpha2EU[val]
}
