package jws

import (
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/v3/jwa"
)

type VerifierFactory interface {
	Create() (Verifier, error)
}
type VerifierFactoryFn func() (Verifier, error)

func (fn VerifierFactoryFn) Create() (Verifier, error) {
	return fn()
}

var muVerifierDB sync.RWMutex
var verifierDB map[jwa.SignatureAlgorithm]VerifierFactory

// RegisterVerifier is used to register a factory object that creates
// Verifier objects based on the given algorithm.
//
// For example, if you would like to provide a custom verifier for
// jwa.EdDSA, use this function to register a `VerifierFactory`
// (probably in your `init()`)
//
// Unlike the `UnregisterVerifier` function, this function automatically
// calls `jwa.RegisterSignatureAlgorithm` to register the algorithm
// in this module's algorithm database.
func RegisterVerifier(alg jwa.SignatureAlgorithm, f VerifierFactory) {
	jwa.RegisterSignatureAlgorithm(alg)
	muVerifierDB.Lock()
	verifierDB[alg] = f
	muVerifierDB.Unlock()
}

// UnregisterVerifier removes the signer factory associated with
// the given algorithm.
//
// Note that when you call this function, the algorithm itself is
// not automatically unregistered from this module's algorithm database.
// This is because the algorithm may still be required for signing or
// some other operation (however unlikely, it is still possible).
// Therefore, in order to completely remove the algorithm, you must
// call `jwa.UnregisterSignatureAlgorithm` yourself.
func UnregisterVerifier(alg jwa.SignatureAlgorithm) {
	muVerifierDB.Lock()
	delete(verifierDB, alg)
	muVerifierDB.Unlock()
}

func init() {
	verifierDB = make(map[jwa.SignatureAlgorithm]VerifierFactory)

	for _, alg := range []jwa.SignatureAlgorithm{jwa.RS256(), jwa.RS384(), jwa.RS512(), jwa.PS256(), jwa.PS384(), jwa.PS512()} {
		RegisterVerifier(alg, func(alg jwa.SignatureAlgorithm) VerifierFactory {
			return VerifierFactoryFn(func() (Verifier, error) {
				return newRSAVerifier(alg), nil
			})
		}(alg))
	}

	for _, alg := range []jwa.SignatureAlgorithm{jwa.ES256(), jwa.ES384(), jwa.ES512(), jwa.ES256K()} {
		RegisterVerifier(alg, func(alg jwa.SignatureAlgorithm) VerifierFactory {
			return VerifierFactoryFn(func() (Verifier, error) {
				return newECDSAVerifier(alg), nil
			})
		}(alg))
	}

	for _, alg := range []jwa.SignatureAlgorithm{jwa.HS256(), jwa.HS384(), jwa.HS512()} {
		RegisterVerifier(alg, func(alg jwa.SignatureAlgorithm) VerifierFactory {
			return VerifierFactoryFn(func() (Verifier, error) {
				return newHMACVerifier(alg), nil
			})
		}(alg))
	}

	RegisterVerifier(jwa.EdDSA(), VerifierFactoryFn(func() (Verifier, error) {
		return newEdDSAVerifier(), nil
	}))
}

// NewVerifier creates a verifier that signs payloads using the given signature algorithm.
func NewVerifier(alg jwa.SignatureAlgorithm) (Verifier, error) {
	muVerifierDB.RLock()
	f, ok := verifierDB[alg]
	muVerifierDB.RUnlock()

	if ok {
		return f.Create()
	}
	return nil, fmt.Errorf(`unsupported signature algorithm "%s"`, alg)
}
