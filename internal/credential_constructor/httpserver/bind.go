package httpserver

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-json"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

func (s *Service) bindV2(ctx context.Context, c *gin.Context, v interface{}) error {
	ctx, span := s.tp.Start(ctx, "httpserver:bindV2")
	defer span.End()

	return json.NewDecoder(c.Request.Body).Decode(&v)
}

func (s *Service) bindRequest(ctx context.Context, c *gin.Context, v interface{}) error {
	ctx, span := s.tp.Start(ctx, "httpserver:bindRequest")
	defer span.End()

	if c.ContentType() == gin.MIMEJSON {
		span.AddEvent("bindRequest:ShouldBindJSON start")
		start := time.Now()
		if err := c.ShouldBindJSON(v); err != nil {
			span.SetStatus(codes.Error, err.Error())
			return err
		}
		d := time.Since(start)
		span.AddEvent("bindRequest:ShouldBindJSON stop", trace.WithAttributes(attribute.Int64("duration ms", d.Milliseconds())))
	}

	span.AddEvent("bindRequest:bindRequestQuery")
	if err := s.bindRequestQuery(ctx, c, v); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.AddEvent("bindRequest:ShouldBindQuery")
	if err := c.ShouldBindQuery(v); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	span.AddEvent("bindRequest:ShouldBindUri")
	if err := c.ShouldBindUri(v); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return err
	}
	return nil
}

func (s *Service) bindRequestQuery(ctx context.Context, c *gin.Context, v interface{}) error {
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
		}
	}
	return nil
}
