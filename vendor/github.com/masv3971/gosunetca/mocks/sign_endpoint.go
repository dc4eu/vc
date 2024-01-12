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
	"document": {
		"transaction_id": "e06a50d2-b687-11ed-9fd2-0bad217296d7",
		"data": "0c91fecff72ca85921e655c52d2bed0e39c9111eff1d8b140be96a49eaec9149"
	}
}`)

// MockRequestSign is a sample request to the Sign endpoint.
var MockRequestSign = &types.SignRequest{
	Document: &types.Document{
		TransactionID: "",
		Base64Data:    "0c91fecff72ca85921e655c52d2bed0e39c9111eff1d8b140be96a49eaec9149",
	},
}

// JSONSignDocumentReply200 is a sample response from the Sign endpoint.
var JSONSignDocumentReply200 = []byte(`{
	"transaction_id: "e06a50d2-b687-11ed-9fd2-0bad217296d7",
    "pdf_b64_data": "MEUCIQDz2Uqs1GE5sJGgW2R1gVTJRJdj8JVxqwMzNnboiNA9pAIgFhWhr85H/EARoyotYhjjI49SWOnsvQpl4jnzpZ0rMj0="
  }`)

//// MockReplySign is a sample response from the Sign endpoint.
//var MockReplySign = &types.SignReply{
//	Meta: types.SignMetaReply{
//		Version:            1,
//		SignerPublicKey:    "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE32cZi4nLmKIxdwbzg6BcDfOPQoJ+\n5NyBNFt2BceWkZ+Rv+gJXOkrb5isXo5IOtvPzDRJLs9GL35du0hChwOGnw==\n-----END PUBLIC KEY-----\n",
//		SignatureAlgorithm: "sha256_ecdsa",
//	},
//	Document: types.Document{
//		TransactionID: "677fd5c0-ef0d-11ed-ba24-87b4bf5b52b1",
//		Encoding:      "base64",
//		TS:            0,
//		Data:          "0c91fecff72ca85921e655c52d2bed0e39c9111eff1d8b140be96a49eaec9149",
//		SHA256Hash:    "",
//	},
//}

// JSONReply401 is a sample response from CA when token is missing.
var JSONReply401 = []byte(`{
		"message": "Missing valid authorization token"
}`)

// MockErrorReplyMissingToken is a sample response from ca when token is missing.
var MockErrorReplyMissingToken = &types.ErrorReply{
	Message: "Missing valid authorization token",
}
