package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSAMLConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      SAMLConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "disabled config is valid",
			config: SAMLConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "valid MDQ configuration",
			config: SAMLConfig{
				Enabled:   true,
				MDQServer: "https://md.example.org/entities/",
			},
			expectError: false,
		},
		{
			name: "valid static IdP with path",
			config: SAMLConfig{
				Enabled: true,
				StaticIDPMetadata: &StaticIDPConfig{
					EntityID:     "https://idp.example.com",
					MetadataPath: "/path/to/metadata.xml",
				},
			},
			expectError: false,
		},
		{
			name: "valid static IdP with URL",
			config: SAMLConfig{
				Enabled: true,
				StaticIDPMetadata: &StaticIDPConfig{
					EntityID:    "https://idp.example.com",
					MetadataURL: "https://idp.example.com/metadata",
				},
			},
			expectError: false,
		},
		{
			name: "enabled but no MDQ or static IdP",
			config: SAMLConfig{
				Enabled: true,
			},
			expectError: true,
			errorMsg:    "neither mdq_server nor static_idp_metadata configured",
		},
		{
			name: "both MDQ and static IdP configured",
			config: SAMLConfig{
				Enabled:   true,
				MDQServer: "https://md.example.org/entities/",
				StaticIDPMetadata: &StaticIDPConfig{
					EntityID:     "https://idp.example.com",
					MetadataPath: "/path/to/metadata.xml",
				},
			},
			expectError: true,
			errorMsg:    "cannot have both mdq_server and static_idp_metadata",
		},
		{
			name: "static IdP without entityID",
			config: SAMLConfig{
				Enabled: true,
				StaticIDPMetadata: &StaticIDPConfig{
					MetadataPath: "/path/to/metadata.xml",
				},
			},
			expectError: true,
			errorMsg:    "static_idp_metadata.entity_id is required",
		},
		{
			name: "static IdP without metadata source",
			config: SAMLConfig{
				Enabled: true,
				StaticIDPMetadata: &StaticIDPConfig{
					EntityID: "https://idp.example.com",
				},
			},
			expectError: true,
			errorMsg:    "requires either metadata_path or metadata_url",
		},
		{
			name: "static IdP with both path and URL",
			config: SAMLConfig{
				Enabled: true,
				StaticIDPMetadata: &StaticIDPConfig{
					EntityID:     "https://idp.example.com",
					MetadataPath: "/path/to/metadata.xml",
					MetadataURL:  "https://idp.example.com/metadata",
				},
			},
			expectError: true,
			errorMsg:    "cannot have both metadata_path and metadata_url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
