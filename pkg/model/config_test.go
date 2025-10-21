package model

import (
	"context"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
	"gotest.tools/v3/golden"
)

func TestCredentialConstructor(t *testing.T) {
	tts := []struct {
		name string
		have map[string]*CredentialConstructor
	}{
		{
			name: "Valid Config",
			have: map[string]*CredentialConstructor{
				"urn:eudi:pid:1": {
					VCTMFilePath: "./testdata/vctm_pid.json",
				},
				"urn:eudi:pda1:1": {
					VCTMFilePath: "./testdata/vctm_pda1.json",
				},
				"urn:eudi:ehic:1": {
					VCTMFilePath: "./testdata/vctm_ehic.json",
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.TODO()

			for _, cc := range tt.have {
				err := cc.LoadFile(ctx)
				assert.NoError(t, err)

				t.Logf("Loaded VCTM: %s", cc.VCT)
			}
		})
	}
}

func TestCredentialConstructorFormatting(t *testing.T) {
	tts := []struct {
		name     string
		cfgPath  string
		loadVCTM []string
		want     map[string]*CredentialConstructor
	}{
		{
			name:     "Valid Config",
			cfgPath:  "cfg.yaml",
			loadVCTM: []string{"ehic"},
			want: map[string]*CredentialConstructor{
				"diploma": {
					VCT: "urn:eudi:diploma:1",
				},
				"elm": {
					VCT: "urn:eudi:elm:1",
				},
				"micro_credential": {
					VCT: "urn:eudi:micro_credential:1",
				},
				"pid": {
					VCT: "urn:eudi:pid:1",
				},
				"openbadge_basic": {
					VCT: "urn:eudi:openbadge_basic:1",
				},
				"openbadge_complete": {
					VCT: "urn:eudi:openbadge_complete:1",
				},
				"openbadge_endorsements": {
					VCT: "urn:eudi:openbadge_endorsements:1",
				},
				"pda1": {
					VCT: "urn:eudi:pda1:1",
				},
				"ehic": {
					VCT: "urn:eudi:ehic:1",
					Attributes: map[string]map[string][]string{
						"en-US": {
							"Social Security PIN":        {"personal_administrative_number"},
							"Issuing authority":          {"issuing_authority"},
							"Issuing authority id":       {"issuing_authority", "id"},
							"Issuing authority name":     {"issuing_authority", "name"},
							"Issuing country":            {"issuing_country"},
							"Expiry date":                {"date_of_expiry"},
							"Issue date":                 {"date_of_issuance"},
							"Competent institution":      {"authentic_source"},
							"Competent institution id":   {"authentic_source", "id"},
							"Competent institution name": {"authentic_source", "name"},
							"Ending date":                {"ending_date"},
							"Starting date":              {"starting_date"},
							"Document number":            {"document_number"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			cfgFile := golden.Get(t, tt.cfgPath)

			cfg := &Cfg{}
			err := yaml.Unmarshal(cfgFile, cfg)
			assert.NoError(t, err)

			for credentialName, cc := range cfg.CredentialConstructor {
				if slices.Contains(tt.loadVCTM, credentialName) {
					err := cc.LoadFile(ctx)
					assert.NoError(t, err)
					cc.Attributes = cc.VCTM.Attributes()
				}

				cc.VCTMFilePath = ""
				cc.AuthMethod = ""
				cc.VCTM = nil
			}

			assert.Equal(t, tt.want, cfg.CredentialConstructor)
		})
	}
}
