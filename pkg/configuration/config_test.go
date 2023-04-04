package configuration

import (
	"fmt"
	"os"
	"testing"
	"wallet/pkg/logger"
	"wallet/pkg/model"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"gopkg.in/yaml.v3"
)

var mockConfig = []byte(`
---
  api_server:
    host: :8080
  production: false
  redis:
    db: 3
    host: localhost:6379
    sentinel_hosts:
    #  - localhost:1231
    #  - localhost:12313
    sentinel_service_name: redis-cluster
`)

func TestParse(t *testing.T) {
	tempDir := t.TempDir()

	tts := []struct {
		name           string
		setEnvVariable bool
	}{
		{
			name:           "OK",
			setEnvVariable: true,
		},
	}

	for _, tt := range tts {
		path := fmt.Sprintf("%s/test.cfg", tempDir)
		if err := os.WriteFile(path, mockConfig, 0666); err != nil {
			assert.NoError(t, err)
		}
		if tt.setEnvVariable {
			os.Setenv("EDUID_CONFIG_YAML", path)
		}

		want := &model.Cfg{}
		err := yaml.Unmarshal(mockConfig, want)
		assert.NoError(t, err)

		testLog := logger.Logger{
			Logger: *zaptest.NewLogger(t, zaptest.Level(zap.PanicLevel)),
		}

		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Parse(&testLog)
			assert.NoError(t, err)

			assert.Equal(t, &want, cfg)

		})
	}

}
