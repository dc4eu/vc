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
	ctx, span := b.client.tracer.Start(ctx, "httpserver:bindV2")
	defer span.End()

	return json.NewDecoder(c.Request.Body).Decode(&v)
}

func (b *bindingHandler) Request(ctx context.Context, c *gin.Context, v any) error {
	if err := c.ShouldBind(v); err != nil {
		b.log.Debug("error", "error", err)
		return err
	}

	if err := b.BindMultiPart(ctx, c, v); err != nil {
		return err
	}
	return nil
}

// Request binds the request body to a map structure
//func (b *bindingHandler) Request(ctx context.Context, c *gin.Context, v any) error {
//	ctx, span := b.client.tracer.Start(ctx, "httpserver:bindRequest")
//	defer span.End()
//
//	if c.ContentType() == gin.MIMEJSON {
//		if err := c.ShouldBindJSON(v); err != nil {
//			return err
//		}
//	}
//
//	if err := b.bindRequestQuery(ctx, c, v); err != nil {
//		return err
//	}
//
//	//if err := b.bindMultiPart(ctx, c, v); err != nil {
//	//	return err
//	//}
//
//
//
//	if err := c.ShouldBindQuery(v); err != nil {
//		return err
//	}
//
//	return c.ShouldBindUri(v)
//}

func (b *bindingHandler) BindMultiPart(ctx context.Context, c *gin.Context, v any) error {
	ctx, span := b.client.tracer.Start(ctx, "httpserver:bindMultiPart")
	defer span.End()

	//refV := reflect.ValueOf(v).Elem()
	refT := reflect.ValueOf(v).Elem().Type()
	for i := 0; i < refT.NumField(); i++ {
		field := refT.Field(i)
		fieldType := field.Type
		fieldKey := field.Tag.Get("mura")
		//if fieldKey != "" {
		//	refV.FieldByName(field.Name).Set(reflect.ValueOf(v))
		//	b.log.Debug("fieldkey", "fk", fieldKey, "type", fieldType.String(), "field", field.Name, "refV", refV)
		//}
		if fieldKey == "" {
			continue
		}

		fmt.Println("MURA", fieldType.String())

		switch fieldType.String() {
		case "string":
			fmt.Println("STRIIIING")
		case "struct":
			fmt.Println("STRUUUUCT")
		}
	}
	return nil
}

func (b *bindingHandler) bindRequestQuery(ctx context.Context, c *gin.Context, v any) error {
	ctx, span := b.client.tracer.Start(ctx, "httpserver:bindRequestQuery")
	defer span.End()

	refV := reflect.ValueOf(v).Elem()
	refT := reflect.ValueOf(v).Elem().Type()
	for i := 0; i < refT.NumField(); i++ {
		field := refT.Field(i)
		fieldType := field.Type
		fieldKey := field.Tag.Get("form")
		if fieldKey == "" {
			fieldKey = field.Name
		}
		switch fieldType.String() {
		case "map[string]string":
			v := c.QueryMap(fieldKey)
			if len(v) == 0 {
				continue
			}
			refV.FieldByName(field.Name).Set(reflect.ValueOf(v))
		case "*map[string]string":
			v := c.QueryMap(fieldKey)
			if len(v) == 0 {
				continue
			}
			refV.FieldByName(field.Name).Set(reflect.ValueOf(&v))
		case "map[string][]string":
			v := make(map[string][]string)
			for key := range c.QueryMap(fieldKey) {
				v[key] = c.QueryArray(fmt.Sprintf("%s[%s]", fieldKey, key))
			}
			if len(v) == 0 {
				continue
			}
			refV.FieldByName(field.Name).Set(reflect.ValueOf(v))
		case "*map[string][]string":
			v := make(map[string][]string)
			for key := range c.QueryMap(fieldKey) {
				v[key] = c.QueryArray(fmt.Sprintf("%s[%s]", fieldKey, key))
			}
			if len(v) == 0 {
				continue
			}
			refV.FieldByName(field.Name).Set(reflect.ValueOf(&v))
		}
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
