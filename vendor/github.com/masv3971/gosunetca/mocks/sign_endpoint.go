package mocks

import (
	"github.com/masv3971/gosunetca/types"
)

// JSONSignDocumentRequest200 is a sample request to the Sign endpoint.
var JSONSignDocumentRequest200 = []byte(`{
		"meta": {
			"version": 1,
			"encoding": "base64",
			"key_label": "pkcs11_sign_test15",
			"key_type": "secp256r1"
		},
		"documents": [
			{
				"id": "e06a50d2-b687-11ed-9fd2-0bad217296d7",
				"data": "0c91fecff72ca85921e655c52d2bed0e39c9111eff1d8b140be96a49eaec9149"
			},
			{
				"id": "e06a50d2-b687-11ed-9fd2-0bad217296d8",
				"data": "913271fd1510ceb9827d3982bd83200722f434f50ada2578e57c19ef07c08367"
			},
			{
				"id": "e06a50d2-b687-11ed-9fd2-0bad217296d9",
				"data": "0c91fecff72ca85921e655c52d2bed0e39c9111eff1d8b140be96a49eaec9149"
			}
		]
	}`)

// MockRequestSign is a sample request to the Sign endpoint.
var MockRequestSign = &types.SignRequest{
	Meta: types.SignMetaRequest{
		Version:  1,
		KeyLabel: "pkcs11_sign_test15",
		Encoding: "base64",
		KeyType:  "secp256r1",
	},
	Documents: []types.UnsignedDocument{
		{
			ID:   "e06a50d2-b687-11ed-9fd2-0bad217296d7",
			Data: "0c91fecff72ca85921e655c52d2bed0e39c9111eff1d8b140be96a49eaec9149",
		},
		{
			ID:   "e06a50d2-b687-11ed-9fd2-0bad217296d8",
			Data: "913271fd1510ceb9827d3982bd83200722f434f50ada2578e57c19ef07c08367",
		},
		{
			ID:   "e06a50d2-b687-11ed-9fd2-0bad217296d9",
			Data: "0c91fecff72ca85921e655c52d2bed0e39c9111eff1d8b140be96a49eaec9149",
		},
	},
}

// JSONSignDocumentReply200 is a sample response from the Sign endpoint.
var JSONSignDocumentReply200 = []byte(`{
	"meta": {
	  	"version": 1,
		"encoding": "base64",
		"signer_public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE32cZi4nLmKIxdwbzg6BcDfOPQoJ+\n5NyBNFt2BceWkZ+Rv+gJXOkrb5isXo5IOtvPzDRJLs9GL35du0hChwOGnw==\n-----END PUBLIC KEY-----\n",
		"signature_algorithm": "sha256_ecdsa"
	},
	"signature_values": [
		{
			"id": "e06a50d2-b687-11ed-9fd2-0bad217296d7",
			"signature": "MEUCIQDz2Uqs1GE5sJGgW2R1gVTJRJdj8JVxqwMzNnboiNA9pAIgFhWhr85H/EARoyotYhjjI49SWOnsvQpl4jnzpZ0rMj0="
		},
		{
			"id": "e06a50d2-b687-11ed-9fd2-0bad217296d8",
			"signature": "MEQCIAJ2fcp/sSODCXbkr0HWCkdLYBgYtCzTdqC65bAOLj1PAiAqPv5kNZdtkdATrRYjZ8TETV0dsPUOz6zQutCEk7Uq/g=="
		},
		{
			"id": "e06a50d2-b687-11ed-9fd2-0bad217296d9",
			"signature": "MEUCIQCODv6ydL1VIysPdStkqn9Qsfe/eUCfGMKP8jMZfdVNogIgXg6ReSW3/uA+RaQ3XsonH+7ovrstEFm22iwpUbGwtZE="
		}
	]
  }`)

// MockReplySign is a sample response from the Sign endpoint.
var MockReplySign = &types.SignReply{
	Meta: types.SignMetaReply{
		Version:            1,
		Encoding:           "base64",
		SignerPublicKey:    "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE32cZi4nLmKIxdwbzg6BcDfOPQoJ+\n5NyBNFt2BceWkZ+Rv+gJXOkrb5isXo5IOtvPzDRJLs9GL35du0hChwOGnw==\n-----END PUBLIC KEY-----\n",
		SignatureAlgorithm: "sha256_ecdsa",
	},
	SignatureValues: []types.SignedDocument{
		{
			ID:        "e06a50d2-b687-11ed-9fd2-0bad217296d7",
			Signature: "MEUCIQDz2Uqs1GE5sJGgW2R1gVTJRJdj8JVxqwMzNnboiNA9pAIgFhWhr85H/EARoyotYhjjI49SWOnsvQpl4jnzpZ0rMj0=",
		},
		{
			ID:        "e06a50d2-b687-11ed-9fd2-0bad217296d8",
			Signature: "MEQCIAJ2fcp/sSODCXbkr0HWCkdLYBgYtCzTdqC65bAOLj1PAiAqPv5kNZdtkdATrRYjZ8TETV0dsPUOz6zQutCEk7Uq/g==",
		},
		{
			ID:        "e06a50d2-b687-11ed-9fd2-0bad217296d9",
			Signature: "MEUCIQCODv6ydL1VIysPdStkqn9Qsfe/eUCfGMKP8jMZfdVNogIgXg6ReSW3/uA+RaQ3XsonH+7ovrstEFm22iwpUbGwtZE=",
		},
	},
}

// JSONReply401 is a sample response from CA when token is missing.
var JSONReply401 = []byte(`{
		"message": "Missing Authorization token"
}`)

// MockErrorReplyMissingToken is a sample response from ca when token is missing.
var MockErrorReplyMissingToken = &types.ErrorReply{
	Message: "Missing Authorization token",
}
