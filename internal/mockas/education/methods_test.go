package education

import (
	"context"
	"testing"
	"vc/pkg/logger"

	"github.com/stretchr/testify/assert"
)

func TestApply(t *testing.T) {
	tts := []struct {
		name string
	}{
		{
			name: "TestApply",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			c, err := New(context.TODO(), "", logger.NewSimple("test"))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			resp, err := c.apply(context.TODO())
			assert.NoError(t, err)

			t.Logf("resp: %v", resp)
		})
	}
}
