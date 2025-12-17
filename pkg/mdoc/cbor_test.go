package mdoc

import (
	"bytes"
	"testing"
)

func TestNewCBOREncoder(t *testing.T) {
	encoder, err := NewCBOREncoder()
	if err != nil {
		t.Fatalf("NewCBOREncoder() error = %v", err)
	}
	if encoder == nil {
		t.Fatal("NewCBOREncoder() returned nil")
	}
}

func TestCBOREncoder_MarshalUnmarshal(t *testing.T) {
	encoder, err := NewCBOREncoder()
	if err != nil {
		t.Fatalf("NewCBOREncoder() error = %v", err)
	}

	tests := []struct {
		name  string
		value any
	}{
		{"string", "hej världen"},
		{"int", 42},
		{"bool", true},
		{"bytes", []byte{1, 2, 3, 4}},
		{"array", []int{1, 2, 3}},
		{"map", map[string]int{"a": 1, "b": 2}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := encoder.Marshal(tt.value)
			if err != nil {
				t.Errorf("Marshal() error = %v", err)
				return
			}
			if len(data) == 0 {
				t.Error("Marshal() returned empty data")
			}
		})
	}
}

func TestCBOREncoder_StructRoundTrip(t *testing.T) {
	encoder, err := NewCBOREncoder()
	if err != nil {
		t.Fatalf("NewCBOREncoder() error = %v", err)
	}

	type TestStruct struct {
		Name  string `cbor:"name"`
		Value int    `cbor:"value"`
	}

	original := TestStruct{Name: "Andersson", Value: 123}

	data, err := encoder.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded TestStruct
	if err := encoder.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if decoded.Name != original.Name || decoded.Value != original.Value {
		t.Errorf("Round trip failed: got %+v, want %+v", decoded, original)
	}
}

func TestTaggedValue(t *testing.T) {
	encoder, err := NewCBOREncoder()
	if err != nil {
		t.Fatalf("NewCBOREncoder() error = %v", err)
	}

	tagged := TaggedValue{
		Tag:   24,
		Value: []byte{0x01, 0x02, 0x03},
	}

	data, err := encoder.Marshal(tagged)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshal() returned empty data for TaggedValue")
	}
}

func TestWrapInEncodedCBOR(t *testing.T) {
	original := map[string]int{"test": 42}
	wrapped, err := WrapInEncodedCBOR(original)
	if err != nil {
		t.Fatalf("WrapInEncodedCBOR() error = %v", err)
	}

	if len(wrapped) == 0 {
		t.Error("WrapInEncodedCBOR() returned empty data")
	}
}

func TestUnwrapEncodedCBOR(t *testing.T) {
	original := map[string]int{"test": 42}
	wrapped, err := WrapInEncodedCBOR(original)
	if err != nil {
		t.Fatalf("WrapInEncodedCBOR() error = %v", err)
	}

	var unwrapped map[string]int
	if err := UnwrapEncodedCBOR(wrapped, &unwrapped); err != nil {
		t.Fatalf("UnwrapEncodedCBOR() error = %v", err)
	}

	if unwrapped["test"] != 42 {
		t.Errorf("UnwrapEncodedCBOR() got %v, want %v", unwrapped["test"], 42)
	}
}

func TestFullDate(t *testing.T) {
	encoder, err := NewCBOREncoder()
	if err != nil {
		t.Fatalf("NewCBOREncoder() error = %v", err)
	}

	date := FullDate("2024-06-15")

	data, err := encoder.Marshal(date)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded FullDate
	if err := encoder.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if decoded != date {
		t.Errorf("FullDate round trip failed: got %v, want %v", decoded, date)
	}
}

func TestTDate(t *testing.T) {
	encoder, err := NewCBOREncoder()
	if err != nil {
		t.Fatalf("NewCBOREncoder() error = %v", err)
	}

	tdate := TDate("2024-06-15T10:30:00Z")

	data, err := encoder.Marshal(tdate)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded TDate
	if err := encoder.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if decoded != tdate {
		t.Errorf("TDate round trip failed: got %v, want %v", decoded, tdate)
	}
}

func TestGenerateRandom(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"16 bytes", 16},
		{"32 bytes", 32},
		{"64 bytes", 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			random, err := GenerateRandom(tt.length)
			if err != nil {
				t.Fatalf("GenerateRandom() error = %v", err)
			}

			if len(random) != tt.length {
				t.Errorf("GenerateRandom() length = %d, want %d", len(random), tt.length)
			}

			// Verify randomness by generating another and comparing
			random2, err := GenerateRandom(tt.length)
			if err != nil {
				t.Fatalf("GenerateRandom() second call error = %v", err)
			}

			if bytes.Equal(random, random2) {
				t.Error("GenerateRandom() returned same value twice")
			}
		})
	}
}

func TestGenerateRandom_MinLength(t *testing.T) {
	// Request less than 16 bytes, should get 16
	random, err := GenerateRandom(8)
	if err != nil {
		t.Fatalf("GenerateRandom() error = %v", err)
	}

	if len(random) != 16 {
		t.Errorf("GenerateRandom() should enforce minimum 16 bytes, got %d", len(random))
	}
}

func TestEncodedCBORBytes_MarshalUnmarshal(t *testing.T) {
	encoder, err := NewCBOREncoder()
	if err != nil {
		t.Fatalf("NewCBOREncoder() error = %v", err)
	}

	// Create some inner data
	innerData, err := encoder.Marshal(map[string]string{"key": "värde"})
	if err != nil {
		t.Fatalf("Marshal inner data error = %v", err)
	}

	original := EncodedCBORBytes(innerData)

	// Marshal the EncodedCBORBytes
	data, err := encoder.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Unmarshal back
	var decoded EncodedCBORBytes
	if err := encoder.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if !bytes.Equal(original, decoded) {
		t.Errorf("EncodedCBORBytes round trip failed")
	}
}

func TestDataElementBytes(t *testing.T) {
	testCases := []struct {
		name  string
		value DataElementValue
	}{
		{"string", "Erik Andersson"},
		{"int", 42},
		{"bool", true},
		{"bytes", []byte{0x01, 0x02}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := DataElementBytes(tc.value)
			if err != nil {
				t.Errorf("DataElementBytes() error = %v", err)
			}
			if len(data) == 0 {
				t.Error("DataElementBytes() returned empty data")
			}
		})
	}
}

func TestCompareCBOR(t *testing.T) {
	encoder, _ := NewCBOREncoder()

	a, _ := encoder.Marshal(map[string]int{"x": 1})
	b, _ := encoder.Marshal(map[string]int{"x": 1})
	c, _ := encoder.Marshal(map[string]int{"x": 2})

	if !CompareCBOR(a, b) {
		t.Error("CompareCBOR() should return true for equal values")
	}
	if CompareCBOR(a, c) {
		t.Error("CompareCBOR() should return false for different values")
	}
}
