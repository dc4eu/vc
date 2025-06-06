package jws

import (
	"bytes"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/internal/base64"
	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/jwx/v3/internal/pool"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func NewSignature() *Signature {
	return &Signature{}
}

func (s *Signature) DecodeCtx() DecodeCtx {
	return s.dc
}

func (s *Signature) SetDecodeCtx(dc DecodeCtx) {
	s.dc = dc
}

func (s Signature) PublicHeaders() Headers {
	return s.headers
}

func (s *Signature) SetPublicHeaders(v Headers) *Signature {
	s.headers = v
	return s
}

func (s Signature) ProtectedHeaders() Headers {
	return s.protected
}

func (s *Signature) SetProtectedHeaders(v Headers) *Signature {
	s.protected = v
	return s
}

func (s Signature) Signature() []byte {
	return s.signature
}

func (s *Signature) SetSignature(v []byte) *Signature {
	s.signature = v
	return s
}

type signatureUnmarshalProbe struct {
	Header    Headers `json:"header,omitempty"`
	Protected *string `json:"protected,omitempty"`
	Signature *string `json:"signature,omitempty"`
}

func (s *Signature) UnmarshalJSON(data []byte) error {
	var sup signatureUnmarshalProbe
	sup.Header = NewHeaders()
	if err := json.Unmarshal(data, &sup); err != nil {
		return fmt.Errorf(`failed to unmarshal signature into temporary struct: %w`, err)
	}

	s.headers = sup.Header
	if buf := sup.Protected; buf != nil {
		src := []byte(*buf)
		if !bytes.HasPrefix(src, []byte{'{'}) {
			decoded, err := base64.Decode(src)
			if err != nil {
				return fmt.Errorf(`failed to base64 decode protected headers: %w`, err)
			}
			src = decoded
		}

		prt := NewHeaders()
		//nolint:forcetypeassert
		prt.(*stdHeaders).SetDecodeCtx(s.DecodeCtx())
		if err := json.Unmarshal(src, prt); err != nil {
			return fmt.Errorf(`failed to unmarshal protected headers: %w`, err)
		}
		//nolint:forcetypeassert
		prt.(*stdHeaders).SetDecodeCtx(nil)
		s.protected = prt
	}

	if sup.Signature != nil {
		decoded, err := base64.DecodeString(*sup.Signature)
		if err != nil {
			return fmt.Errorf(`failed to base decode signature: %w`, err)
		}
		s.signature = decoded
	}
	return nil
}

// Sign populates the signature field, with a signature generated by
// given the signer object and payload.
//
// The first return value is the raw signature in binary format.
// The second return value s the full three-segment signature
// (e.g. "eyXXXX.XXXXX.XXXX")
func (s *Signature) Sign(payload []byte, signer Signer, key interface{}) ([]byte, []byte, error) {
	hdrs, err := mergeHeaders(s.headers, s.protected)
	if err != nil {
		return nil, nil, fmt.Errorf(`failed to merge headers: %w`, err)
	}

	if err := hdrs.Set(AlgorithmKey, signer.Algorithm()); err != nil {
		return nil, nil, fmt.Errorf(`failed to set "alg": %w`, err)
	}

	// If the key is a jwk.Key instance, obtain the raw key
	if jwkKey, ok := key.(jwk.Key); ok {
		// If we have a key ID specified by this jwk.Key, use that in the header
		if kid, ok := jwkKey.KeyID(); ok && kid != "" {
			if err := hdrs.Set(jwk.KeyIDKey, kid); err != nil {
				return nil, nil, fmt.Errorf(`set key ID from jwk.Key: %w`, err)
			}
		}
	}
	hdrbuf, err := json.Marshal(hdrs)
	if err != nil {
		return nil, nil, fmt.Errorf(`failed to marshal headers: %w`, err)
	}

	buf := pool.GetBytesBuffer()
	defer pool.ReleaseBytesBuffer(buf)

	encoder := s.encoder
	if encoder == nil {
		encoder = base64.DefaultEncoder()
	}
	buf.WriteString(encoder.EncodeToString(hdrbuf))
	buf.WriteByte('.')

	var plen int
	b64 := getB64Value(hdrs)
	if b64 {
		encoded := encoder.EncodeToString(payload)
		plen = len(encoded)
		buf.WriteString(encoded)
	} else {
		if !s.detached {
			if bytes.Contains(payload, []byte{'.'}) {
				return nil, nil, fmt.Errorf(`payload must not contain a "."`)
			}
		}
		plen = len(payload)
		buf.Write(payload)
	}

	signature, err := signer.Sign(buf.Bytes(), key)
	if err != nil {
		return nil, nil, fmt.Errorf(`failed to sign payload: %w`, err)
	}
	s.signature = signature

	// Detached payload, this should be removed from the end result
	if s.detached {
		buf.Truncate(buf.Len() - plen)
	}

	buf.WriteByte('.')
	buf.WriteString(encoder.EncodeToString(signature))
	ret := make([]byte, buf.Len())
	copy(ret, buf.Bytes())

	return signature, ret, nil
}

func NewMessage() *Message {
	return &Message{}
}

// Clears the internal raw buffer that was accumulated during
// the verify phase
func (m *Message) clearRaw() {
	for _, sig := range m.signatures {
		if protected := sig.protected; protected != nil {
			if cr, ok := protected.(*stdHeaders); ok {
				cr.raw = nil
			}
		}
	}
}

func (m *Message) SetDecodeCtx(dc DecodeCtx) {
	m.dc = dc
}

func (m *Message) DecodeCtx() DecodeCtx {
	return m.dc
}

// Payload returns the decoded payload
func (m Message) Payload() []byte {
	return m.payload
}

func (m *Message) SetPayload(v []byte) *Message {
	m.payload = v
	return m
}

func (m Message) Signatures() []*Signature {
	return m.signatures
}

func (m *Message) AppendSignature(v *Signature) *Message {
	m.signatures = append(m.signatures, v)
	return m
}

func (m *Message) ClearSignatures() *Message {
	m.signatures = nil
	return m
}

// LookupSignature looks up a particular signature entry using
// the `kid` value
func (m Message) LookupSignature(kid string) []*Signature {
	var sigs []*Signature
	for _, sig := range m.signatures {
		if hdr := sig.PublicHeaders(); hdr != nil {
			hdrKeyID, ok := hdr.KeyID()
			if ok && hdrKeyID == kid {
				sigs = append(sigs, sig)
				continue
			}
		}

		if hdr := sig.ProtectedHeaders(); hdr != nil {
			hdrKeyID, ok := hdr.KeyID()
			if ok && hdrKeyID == kid {
				sigs = append(sigs, sig)
				continue
			}
		}
	}
	return sigs
}

// This struct is used to first probe for the structure of the
// incoming JSON object. We then decide how to parse it
// from the fields that are populated.
type messageUnmarshalProbe struct {
	Payload    *string           `json:"payload"`
	Signatures []json.RawMessage `json:"signatures,omitempty"`
	Header     Headers           `json:"header,omitempty"`
	Protected  *string           `json:"protected,omitempty"`
	Signature  *string           `json:"signature,omitempty"`
}

func (m *Message) UnmarshalJSON(buf []byte) error {
	m.payload = nil
	m.signatures = nil
	m.b64 = true

	var mup messageUnmarshalProbe
	mup.Header = NewHeaders()
	if err := json.Unmarshal(buf, &mup); err != nil {
		return fmt.Errorf(`failed to unmarshal into temporary structure: %w`, err)
	}

	b64 := true
	if mup.Signature == nil { // flattened signature is NOT present
		if len(mup.Signatures) == 0 {
			return fmt.Errorf(`required field "signatures" not present`)
		}

		m.signatures = make([]*Signature, 0, len(mup.Signatures))
		for i, rawsig := range mup.Signatures {
			var sig Signature
			sig.SetDecodeCtx(m.DecodeCtx())
			if err := json.Unmarshal(rawsig, &sig); err != nil {
				return fmt.Errorf(`failed to unmarshal signature #%d: %w`, i+1, err)
			}
			sig.SetDecodeCtx(nil)

			if sig.protected == nil {
				// Instead of barfing on a nil protected header, use an empty header
				sig.protected = NewHeaders()
			}

			if i == 0 {
				if !getB64Value(sig.protected) {
					b64 = false
				}
			} else {
				if b64 != getB64Value(sig.protected) {
					return fmt.Errorf(`b64 value must be the same for all signatures`)
				}
			}

			m.signatures = append(m.signatures, &sig)
		}
	} else { // .signature is present, it's a flattened structure
		if len(mup.Signatures) != 0 {
			return fmt.Errorf(`invalid format ("signatures" and "signature" keys cannot both be present)`)
		}

		var sig Signature
		sig.headers = mup.Header
		if src := mup.Protected; src != nil {
			decoded, err := base64.DecodeString(*src)
			if err != nil {
				return fmt.Errorf(`failed to base64 decode flattened protected headers: %w`, err)
			}
			prt := NewHeaders()
			//nolint:forcetypeassert
			prt.(*stdHeaders).SetDecodeCtx(m.DecodeCtx())
			if err := json.Unmarshal(decoded, prt); err != nil {
				return fmt.Errorf(`failed to unmarshal flattened protected headers: %w`, err)
			}
			//nolint:forcetypeassert
			prt.(*stdHeaders).SetDecodeCtx(nil)
			sig.protected = prt
		}

		if sig.protected == nil {
			// Instead of barfing on a nil protected header, use an empty header
			sig.protected = NewHeaders()
		}

		decoded, err := base64.DecodeString(*mup.Signature)
		if err != nil {
			return fmt.Errorf(`failed to base64 decode flattened signature: %w`, err)
		}
		sig.signature = decoded

		m.signatures = []*Signature{&sig}
		b64 = getB64Value(sig.protected)
	}

	if mup.Payload != nil {
		if !b64 { // NOT base64 encoded
			m.payload = []byte(*mup.Payload)
		} else {
			decoded, err := base64.DecodeString(*mup.Payload)
			if err != nil {
				return fmt.Errorf(`failed to base64 decode payload: %w`, err)
			}
			m.payload = decoded
		}
	}
	m.b64 = b64
	return nil
}

func (m Message) MarshalJSON() ([]byte, error) {
	if len(m.signatures) == 1 {
		return m.marshalFlattened()
	}
	return m.marshalFull()
}

func (m Message) marshalFlattened() ([]byte, error) {
	buf := pool.GetBytesBuffer()
	defer pool.ReleaseBytesBuffer(buf)

	sig := m.signatures[0]

	buf.WriteRune('{')
	var wrote bool

	if hdr := sig.headers; hdr != nil {
		hdrjs, err := json.Marshal(hdr)
		if err != nil {
			return nil, fmt.Errorf(`failed to marshal "header" (flattened format): %w`, err)
		}
		buf.WriteString(`"header":`)
		buf.Write(hdrjs)
		wrote = true
	}

	if wrote {
		buf.WriteRune(',')
	}
	buf.WriteString(`"payload":"`)
	buf.WriteString(base64.EncodeToString(m.payload))
	buf.WriteRune('"')

	if protected := sig.protected; protected != nil {
		protectedbuf, err := json.Marshal(protected)
		if err != nil {
			return nil, fmt.Errorf(`failed to marshal "protected" (flattened format): %w`, err)
		}
		buf.WriteString(`,"protected":"`)
		buf.WriteString(base64.EncodeToString(protectedbuf))
		buf.WriteRune('"')
	}

	buf.WriteString(`,"signature":"`)
	buf.WriteString(base64.EncodeToString(sig.signature))
	buf.WriteRune('"')
	buf.WriteRune('}')

	ret := make([]byte, buf.Len())
	copy(ret, buf.Bytes())
	return ret, nil
}

func (m Message) marshalFull() ([]byte, error) {
	buf := pool.GetBytesBuffer()
	defer pool.ReleaseBytesBuffer(buf)

	buf.WriteString(`{"payload":"`)
	buf.WriteString(base64.EncodeToString(m.payload))
	buf.WriteString(`","signatures":[`)
	for i, sig := range m.signatures {
		if i > 0 {
			buf.WriteRune(',')
		}

		buf.WriteRune('{')
		var wrote bool
		if hdr := sig.headers; hdr != nil {
			hdrbuf, err := json.Marshal(hdr)
			if err != nil {
				return nil, fmt.Errorf(`failed to marshal "header" for signature #%d: %w`, i+1, err)
			}
			buf.WriteString(`"header":`)
			buf.Write(hdrbuf)
			wrote = true
		}

		if protected := sig.protected; protected != nil {
			protectedbuf, err := json.Marshal(protected)
			if err != nil {
				return nil, fmt.Errorf(`failed to marshal "protected" for signature #%d: %w`, i+1, err)
			}
			if wrote {
				buf.WriteRune(',')
			}
			buf.WriteString(`"protected":"`)
			buf.WriteString(base64.EncodeToString(protectedbuf))
			buf.WriteRune('"')
			wrote = true
		}

		if len(sig.signature) > 0 {
			// If InsecureNoSignature is enabled, signature may not exist
			if wrote {
				buf.WriteRune(',')
			}
			buf.WriteString(`"signature":"`)
			buf.WriteString(base64.EncodeToString(sig.signature))
			buf.WriteString(`"`)
		}
		buf.WriteString(`}`)
	}
	buf.WriteString(`]}`)

	ret := make([]byte, buf.Len())
	copy(ret, buf.Bytes())
	return ret, nil
}

// Compact generates a JWS message in compact serialization format from
// `*jws.Message` object. The object contain exactly one signature, or
// an error is returned.
//
// If using a detached payload, the payload must already be stored in
// the `*jws.Message` object, and the `jws.WithDetached()` option
// must be passed to the function.
func Compact(msg *Message, options ...CompactOption) ([]byte, error) {
	if l := len(msg.signatures); l != 1 {
		return nil, fmt.Errorf(`jws.Compact: cannot serialize message with %d signatures (must be one)`, l)
	}

	var detached bool
	var encoder Base64Encoder = base64.DefaultEncoder()
	for _, option := range options {
		//nolint:forcetypeassert
		switch option.Ident() {
		case identDetached{}:
			detached = option.Value().(bool)
		case identBase64Encoder{}:
			encoder = option.Value().(Base64Encoder)
		}
	}

	s := msg.signatures[0]
	// XXX check if this is correct
	hdrs := s.ProtectedHeaders()

	hdrbuf, err := json.Marshal(hdrs)
	if err != nil {
		return nil, fmt.Errorf(`jws.Compress: failed to marshal headers: %w`, err)
	}

	buf := pool.GetBytesBuffer()
	defer pool.ReleaseBytesBuffer(buf)

	buf.WriteString(encoder.EncodeToString(hdrbuf))
	buf.WriteByte('.')

	if !detached {
		if getB64Value(hdrs) {
			encoded := encoder.EncodeToString(msg.payload)
			buf.WriteString(encoded)
		} else {
			if bytes.Contains(msg.payload, []byte{'.'}) {
				return nil, fmt.Errorf(`jws.Compress: payload must not contain a "."`)
			}
			buf.Write(msg.payload)
		}
	}

	buf.WriteByte('.')
	buf.WriteString(encoder.EncodeToString(s.signature))
	ret := make([]byte, buf.Len())
	copy(ret, buf.Bytes())
	return ret, nil
}
