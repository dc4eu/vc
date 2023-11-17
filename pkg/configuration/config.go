package configuration

import (
	"context"
	"errors"
	"os"
	"vc/pkg/helpers"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v2"
)

type envVars struct {
	EduIDConfigYAML string `envconfig:"VC_CONFIG_YAML" required:"true"`
}

// Parse parses config file from VC_CONFIG_YAML environment variable
func Parse(ctx context.Context, logger *logger.Log) (*model.Cfg, error) {
	logger.Info("Read environmental variable")
	env := envVars{}
	if err := envconfig.Process("", &env); err != nil {
		return nil, err
	}

	configPath := env.EduIDConfigYAML

	cfg := &model.Cfg{}

	configFile, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	fileInfo, err := os.Stat(configPath)
	if err != nil {
		return nil, err
	}

	if fileInfo.IsDir() {
		return nil, errors.New("config is a folder")
	}

	if err := yaml.Unmarshal(configFile, cfg); err != nil {
		return nil, err
	}

	if err := helpers.Check(ctx, cfg, logger); err != nil {
		return nil, err
	}

	return cfg, nil
}
