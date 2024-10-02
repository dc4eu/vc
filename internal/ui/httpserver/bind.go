package httpserver

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"reflect"
)

//TODO(mk): remove file after generic bind.go is created in pkg that support marshal support for map string any

import (
	"encoding/json"
	"errors"
)

func (s *Service) bindV2(ctx context.Context, c *gin.Context, v any) error {
	ctx, span := s.tp.Start(ctx, "httpserver:bindV2")
	defer span.End()

	return json.NewDecoder(c.Request.Body).Decode(&v)
}

func (s *Service) bindRequest(ctx context.Context, c *gin.Context, v any) error {
	ctx, span := s.tp.Start(ctx, "httpserver:bindRequest")
	defer span.End()

	if c.ContentType() == gin.MIMEJSON {
		if err := c.ShouldBindJSON(v); err != nil {
			return err
		}
	}
	if err := s.bindRequestQuery(ctx, c, v); err != nil {
		return err
	}
	if err := c.ShouldBindQuery(v); err != nil {
		return err
	}
	err := c.ShouldBindUri(v)

	return err
}

func (s *Service) bindRequestQuery(ctx context.Context, c *gin.Context, v any) error {
	ctx, span := s.tp.Start(ctx, "httpserver:bindRequestQuery")
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
		default:
			return errors.New("fieldType.String(): " + fieldType.String())
		}
	}
	return nil
}
