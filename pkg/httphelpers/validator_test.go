package httphelpers

import (
	"reflect"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
)

func TestDefaultValidator_ValidateStruct(t *testing.T) {
	v := &DefaultValidator{
		Validate: validator.New(),
	}

	t.Run("valid struct", func(t *testing.T) {
		type ValidStruct struct {
			Name  string `validate:"required"`
			Email string `validate:"required,email"`
		}

		valid := ValidStruct{
			Name:  "John Doe",
			Email: "john@example.com",
		}

		err := v.ValidateStruct(valid)
		assert.NoError(t, err)
	})

	t.Run("invalid struct - required field missing", func(t *testing.T) {
		type ValidStruct struct {
			Name  string `validate:"required"`
			Email string `validate:"required,email"`
		}

		invalid := ValidStruct{
			Email: "john@example.com",
		}

		err := v.ValidateStruct(invalid)
		assert.Error(t, err)
	})

	t.Run("invalid struct - email format", func(t *testing.T) {
		type ValidStruct struct {
			Name  string `validate:"required"`
			Email string `validate:"required,email"`
		}

		invalid := ValidStruct{
			Name:  "John Doe",
			Email: "not-an-email",
		}

		err := v.ValidateStruct(invalid)
		assert.Error(t, err)
	})

	t.Run("non-struct type", func(t *testing.T) {
		nonStruct := "not a struct"
		err := v.ValidateStruct(nonStruct)
		assert.NoError(t, err) // Should not validate non-struct types
	})

	t.Run("pointer to struct", func(t *testing.T) {
		type ValidStruct struct {
			Name string `validate:"required"`
		}

		valid := &ValidStruct{
			Name: "John Doe",
		}

		err := v.ValidateStruct(valid)
		assert.NoError(t, err)
	})
}

func TestDefaultValidator_Engine(t *testing.T) {
	v := &DefaultValidator{
		Validate: validator.New(),
	}

	engine := v.Engine()
	assert.NotNil(t, engine)
	assert.IsType(t, &validator.Validate{}, engine)
}

func TestKindOfData(t *testing.T) {
	t.Run("struct", func(t *testing.T) {
		type TestStruct struct {
			Name string
		}
		data := TestStruct{Name: "test"}
		kind := kindOfData(data)
		assert.Equal(t, reflect.Struct, kind)
	})

	t.Run("pointer to struct", func(t *testing.T) {
		type TestStruct struct {
			Name string
		}
		data := &TestStruct{Name: "test"}
		kind := kindOfData(data)
		assert.Equal(t, reflect.Struct, kind)
	})

	t.Run("string", func(t *testing.T) {
		data := "test string"
		kind := kindOfData(data)
		assert.Equal(t, reflect.String, kind)
	})

	t.Run("int", func(t *testing.T) {
		data := 42
		kind := kindOfData(data)
		assert.Equal(t, reflect.Int, kind)
	})

	t.Run("slice", func(t *testing.T) {
		data := []string{"a", "b", "c"}
		kind := kindOfData(data)
		assert.Equal(t, reflect.Slice, kind)
	})

	t.Run("map", func(t *testing.T) {
		data := map[string]int{"key": 1}
		kind := kindOfData(data)
		assert.Equal(t, reflect.Map, kind)
	})

	t.Run("pointer to non-struct", func(t *testing.T) {
		num := 42
		data := &num
		kind := kindOfData(data)
		assert.Equal(t, reflect.Int, kind)
	})
}
