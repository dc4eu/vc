package jwk

import (
	"crypto"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/lestrrat-go/jwx/v3/internal/base64"
	"github.com/lestrrat-go/jwx/v3/internal/pool"
	"github.com/lestrrat-go/jwx/v3/jwa"
)

func init() {
	RegisterKeyExporter(jwa.RSA(), KeyExportFunc(rsaJWKToRaw))
}

func (k *rsaPrivateKey) Import(rawKey *rsa.PrivateKey) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	d, err := bigIntToBytes(rawKey.D)
	if err != nil {
		return fmt.Errorf(`invalid rsa.PrivateKey: %w`, err)
	}
	k.d = d

	l := len(rawKey.Primes)

	if l < 0 /* I know, I'm being paranoid */ || l > 2 {
		return fmt.Errorf(`invalid number of primes in rsa.PrivateKey: need 0 to 2, but got %d`, len(rawKey.Primes))
	}

	if l > 0 {
		p, err := bigIntToBytes(rawKey.Primes[0])
		if err != nil {
			return fmt.Errorf(`invalid rsa.PrivateKey: %w`, err)
		}
		k.p = p
	}

	if l > 1 {
		q, err := bigIntToBytes(rawKey.Primes[1])
		if err != nil {
			return fmt.Errorf(`invalid rsa.PrivateKey: %w`, err)
		}
		k.q = q
	}

	// dp, dq, qi are optional values
	if v, err := bigIntToBytes(rawKey.Precomputed.Dp); err == nil {
		k.dp = v
	}
	if v, err := bigIntToBytes(rawKey.Precomputed.Dq); err == nil {
		k.dq = v
	}
	if v, err := bigIntToBytes(rawKey.Precomputed.Qinv); err == nil {
		k.qi = v
	}

	// public key part
	n, e, err := importRsaPublicKeyByteValues(&rawKey.PublicKey)
	if err != nil {
		return fmt.Errorf(`invalid rsa.PrivateKey: %w`, err)
	}
	k.n = n
	k.e = e

	return nil
}

func importRsaPublicKeyByteValues(rawKey *rsa.PublicKey) ([]byte, []byte, error) {
	n, err := bigIntToBytes(rawKey.N)
	if err != nil {
		return nil, nil, fmt.Errorf(`invalid rsa.PublicKey: %w`, err)
	}

	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(rawKey.E))
	i := 0
	for ; i < len(data); i++ {
		if data[i] != 0x0 {
			break
		}
	}
	return n, data[i:], nil
}

func (k *rsaPublicKey) Import(rawKey *rsa.PublicKey) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	n, e, err := importRsaPublicKeyByteValues(rawKey)
	if err != nil {
		return fmt.Errorf(`invalid rsa.PrivateKey: %w`, err)
	}
	k.n = n
	k.e = e

	return nil
}

func buildRSAPublicKey(key *rsa.PublicKey, n, e []byte) {
	bin := pool.GetBigInt()
	bie := pool.GetBigInt()
	defer pool.ReleaseBigInt(bie)

	bin.SetBytes(n)
	bie.SetBytes(e)

	key.N = bin
	key.E = int(bie.Int64())
}

func rsaJWKToRaw(key Key, hint interface{}) (interface{}, error) {
	switch key := key.(type) {
	case *rsaPublicKey:
		switch hint.(type) {
		case *rsa.PublicKey, *interface{}:
		default:
			return nil, fmt.Errorf(`invalid destination object type %T for public RSA JWK: %w`, hint, ContinueError())
		}

		key.mu.RLock()
		defer key.mu.RUnlock()
		var pubkey rsa.PublicKey
		buildRSAPublicKey(&pubkey, key.n, key.e)

		return &pubkey, nil
	case *rsaPrivateKey:
		switch hint.(type) {
		case *rsa.PrivateKey, *interface{}:
		default:
			return nil, fmt.Errorf(`invalid destination object type %T for private RSA JWK: %w`, hint, ContinueError())
		}
		key.mu.RLock()
		defer key.mu.RUnlock()

		var d, q, p big.Int // note: do not use from sync.Pool

		d.SetBytes(key.d)
		q.SetBytes(key.q)
		p.SetBytes(key.p)

		// optional fields
		var dp, dq, qi *big.Int
		if len(key.dp) > 0 {
			dp = &big.Int{} // note: do not use from sync.Pool
			dp.SetBytes(key.dp)
		}

		if len(key.dq) > 0 {
			dq = &big.Int{} // note: do not use from sync.Pool
			dq.SetBytes(key.dq)
		}

		if len(key.qi) > 0 {
			qi = &big.Int{} // note: do not use from sync.Pool
			qi.SetBytes(key.qi)
		}

		var privkey rsa.PrivateKey
		buildRSAPublicKey(&privkey.PublicKey, key.n, key.e)
		privkey.D = &d
		privkey.Primes = []*big.Int{&p, &q}

		if dp != nil {
			privkey.Precomputed.Dp = dp
		}
		if dq != nil {
			privkey.Precomputed.Dq = dq
		}
		if qi != nil {
			privkey.Precomputed.Qinv = qi
		}
		// This may look like a no-op, but it's required if we want to
		// compare it against a key generated by rsa.GenerateKey
		privkey.Precomputed.CRTValues = []rsa.CRTValue{}
		return &privkey, nil
	default:
		return nil, ContinueError()
	}
}

func makeRSAPublicKey(src Key) (Key, error) {
	newKey := newRSAPublicKey()

	// Iterate and copy everything except for the bits that should not be in the public key
	for _, k := range src.Keys() {
		switch k {
		case RSADKey, RSADPKey, RSADQKey, RSAPKey, RSAQKey, RSAQIKey:
			continue
		default:
			var v interface{}
			if err := src.Get(k, &v); err != nil {
				return nil, fmt.Errorf(`rsa: makeRSAPublicKey: failed to get field %q: %w`, k, err)
			}
			if err := newKey.Set(k, v); err != nil {
				return nil, fmt.Errorf(`rsa: makeRSAPublicKey: failed to set field %q: %w`, k, err)
			}
		}
	}

	return newKey, nil
}

func (k *rsaPrivateKey) PublicKey() (Key, error) {
	return makeRSAPublicKey(k)
}

func (k *rsaPublicKey) PublicKey() (Key, error) {
	return makeRSAPublicKey(k)
}

// Thumbprint returns the JWK thumbprint using the indicated
// hashing algorithm, according to RFC 7638
func (k rsaPrivateKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	var key rsa.PrivateKey
	if err := Export(&k, &key); err != nil {
		return nil, fmt.Errorf(`failed to materialize RSA private key: %w`, err)
	}
	return rsaThumbprint(hash, &key.PublicKey)
}

func (k rsaPublicKey) Thumbprint(hash crypto.Hash) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	var key rsa.PublicKey
	if err := Export(&k, &key); err != nil {
		return nil, fmt.Errorf(`failed to materialize RSA public key: %w`, err)
	}
	return rsaThumbprint(hash, &key)
}

func rsaThumbprint(hash crypto.Hash, key *rsa.PublicKey) ([]byte, error) {
	buf := pool.GetBytesBuffer()
	defer pool.ReleaseBytesBuffer(buf)

	buf.WriteString(`{"e":"`)
	buf.WriteString(base64.EncodeUint64ToString(uint64(key.E)))
	buf.WriteString(`","kty":"RSA","n":"`)
	buf.WriteString(base64.EncodeToString(key.N.Bytes()))
	buf.WriteString(`"}`)

	h := hash.New()
	if _, err := buf.WriteTo(h); err != nil {
		return nil, fmt.Errorf(`failed to write rsaThumbprint: %w`, err)
	}
	return h.Sum(nil), nil
}

func validateRSAKey(key interface {
	N() ([]byte, bool)
	E() ([]byte, bool)
}, checkPrivate bool) error {
	n, ok := key.N()
	if !ok {
		return fmt.Errorf(`missing "n" value`)
	}

	e, ok := key.E()
	if !ok {
		return fmt.Errorf(`missing "e" value`)
	}

	if len(n) == 0 {
		// Ideally we would like to check for the actual length, but unlike
		// EC keys, we have nothing in the key itself that will tell us
		// how many bits this key should have.
		return fmt.Errorf(`missing "n" value`)
	}
	if len(e) == 0 {
		return fmt.Errorf(`missing "e" value`)
	}
	if checkPrivate {
		if priv, ok := key.(keyWithD); ok {
			if d, ok := priv.D(); !ok || len(d) == 0 {
				return fmt.Errorf(`missing "d" value`)
			}
		} else {
			return fmt.Errorf(`missing "d" value`)
		}
	}

	return nil
}

func (k *rsaPrivateKey) Validate() error {
	if err := validateRSAKey(k, true); err != nil {
		return NewKeyValidationError(fmt.Errorf(`jwk.RSAPrivateKey: %w`, err))
	}
	return nil
}

func (k *rsaPublicKey) Validate() error {
	if err := validateRSAKey(k, false); err != nil {
		return NewKeyValidationError(fmt.Errorf(`jwk.RSAPublicKey: %w`, err))
	}
	return nil
}
