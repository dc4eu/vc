package httphelpers

import (
	"context"
	"encoding/json"
	"vc/pkg/helpers"
	"vc/pkg/logger"

	"github.com/gin-gonic/gin"
)

// bindingHandler is the bindingHandler object for httphelpers
type bindingHandler struct {
	client *Client
	log    *logger.Log
}

// FastAndSimple binds the request body to the given struct without use of struct tags (except for json)
func (b *bindingHandler) FastAndSimple(ctx context.Context, c *gin.Context, v any) error {
	_, span := b.client.tracer.Start(ctx, "httpserver:bindFastAndSimple")
	defer span.End()

	return json.NewDecoder(c.Request.Body).Decode(&v)
}

func (b *bindingHandler) Request(ctx context.Context, c *gin.Context, v any) error {
	if err := c.ShouldBind(v); err != nil {
		b.log.Debug("error", "error", err)
		return err
	}

	if err := c.BindUri(v); err != nil {
		return err
	}

	if err := c.ShouldBindHeader(v); err != nil {
		return err
	}

	return nil
}

// BindingValidator returns a new DefaultValidator instance with validator. Used for gin binding
func (b *bindingHandler) Validator() (*DefaultValidator, error) {
	validate, err := helpers.NewValidator()
	if err != nil {
		return nil, err
	}

	return &DefaultValidator{Validate: validate}, nil
}
