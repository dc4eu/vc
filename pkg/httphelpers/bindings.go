package httphelpers

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
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
	//if err := c.ShouldBind(v); err != nil {
	//	b.log.Debug("error", "error", err)
	//	return err
	//}

	if err := c.BindUri(v); err != nil {
		return err
	}

	return nil
}

func (b *bindingHandler) RequestV2(ctx context.Context, c *gin.Context, v any) error {
	typ := reflect.TypeOf(v)
	fmt.Println("type", typ, typ.Kind())

	for i := 0; i < typ.NumField(); i++ {
		// Get the field, returns https://golang.org/pkg/reflect/#StructField
		field := typ.Field(i)

		// Get the field tag value
		tag := field.Tag.Get("uri")

		fmt.Printf("%d. %v (%v), tag: '%v'\n", i+1, field.Name, field.Type.Name(), tag)
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
