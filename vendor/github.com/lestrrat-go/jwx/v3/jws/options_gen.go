// Code generated by tools/cmd/genoptions/main.go. DO NOT EDIT.

package jws

import (
	"context"
	"io/fs"

	"github.com/lestrrat-go/option"
)

type Option = option.Interface

// CompactOption describes options that can be passed to `jws.Compact`
type CompactOption interface {
	Option
	compactOption()
}

type compactOption struct {
	Option
}

func (*compactOption) compactOption() {}

// ReadFileOption is a type of `Option` that can be passed to `jwe.Parse`
type ParseOption interface {
	Option
	readFileOption()
}

type parseOption struct {
	Option
}

func (*parseOption) readFileOption() {}

// ReadFileOption is a type of `Option` that can be passed to `jws.ReadFile`
type ReadFileOption interface {
	Option
	readFileOption()
}

type readFileOption struct {
	Option
}

func (*readFileOption) readFileOption() {}

// SignOption describes options that can be passed to `jws.Sign`
type SignOption interface {
	Option
	signOption()
}

type signOption struct {
	Option
}

func (*signOption) signOption() {}

// SignVerifyCompactOption describes options that can be passed to either `jws.Verify`,
// `jws.Sign`, or `jws.Compact`
type SignVerifyCompactOption interface {
	Option
	signOption()
	verifyOption()
	compactOption()
	parseOption()
}

type signVerifyCompactOption struct {
	Option
}

func (*signVerifyCompactOption) signOption() {}

func (*signVerifyCompactOption) verifyOption() {}

func (*signVerifyCompactOption) compactOption() {}

func (*signVerifyCompactOption) parseOption() {}

// SignVerifyOption describes options that can be passed to either `jws.Verify` or `jws.Sign`
type SignVerifyOption interface {
	Option
	signOption()
	verifyOption()
	parseOption()
}

type signVerifyOption struct {
	Option
}

func (*signVerifyOption) signOption() {}

func (*signVerifyOption) verifyOption() {}

func (*signVerifyOption) parseOption() {}

type SignVerifyParseOption interface {
	Option
	signOption()
	verifyOption()
	parseOption()
	readFileOption()
}

type signVerifyParseOption struct {
	Option
}

func (*signVerifyParseOption) signOption() {}

func (*signVerifyParseOption) verifyOption() {}

func (*signVerifyParseOption) parseOption() {}

func (*signVerifyParseOption) readFileOption() {}

// VerifyOption describes options that can be passed to `jws.Verify`
type VerifyOption interface {
	Option
	verifyOption()
	parseOption()
}

type verifyOption struct {
	Option
}

func (*verifyOption) verifyOption() {}

func (*verifyOption) parseOption() {}

// JSONSuboption describes suboptions that can be passed to the `jws.WithJSON()` option.
type WithJSONSuboption interface {
	Option
	withJSONSuboption()
}

type withJSONSuboption struct {
	Option
}

func (*withJSONSuboption) withJSONSuboption() {}

// WithKeySetSuboption is a suboption passed to the `jws.WithKeySet()` option
type WithKeySetSuboption interface {
	Option
	withKeySetSuboption()
}

type withKeySetSuboption struct {
	Option
}

func (*withKeySetSuboption) withKeySetSuboption() {}

// WithKeySuboption describes option types that can be passed to the `jws.WithKey()`
// option.
type WithKeySuboption interface {
	Option
	withKeySuboption()
}

type withKeySuboption struct {
	Option
}

func (*withKeySuboption) withKeySuboption() {}

type identBase64Encoder struct{}
type identContext struct{}
type identDetached struct{}
type identDetachedPayload struct{}
type identFS struct{}
type identInferAlgorithmFromKey struct{}
type identKey struct{}
type identKeyProvider struct{}
type identKeyUsed struct{}
type identMessage struct{}
type identMultipleKeysPerKeyID struct{}
type identPretty struct{}
type identProtectedHeaders struct{}
type identPublicHeaders struct{}
type identRequireKid struct{}
type identSerialization struct{}
type identUseDefault struct{}
type identValidateKey struct{}

func (identBase64Encoder) String() string {
	return "WithBase64Encoder"
}

func (identContext) String() string {
	return "WithContext"
}

func (identDetached) String() string {
	return "WithDetached"
}

func (identDetachedPayload) String() string {
	return "WithDetachedPayload"
}

func (identFS) String() string {
	return "WithFS"
}

func (identInferAlgorithmFromKey) String() string {
	return "WithInferAlgorithmFromKey"
}

func (identKey) String() string {
	return "WithKey"
}

func (identKeyProvider) String() string {
	return "WithKeyProvider"
}

func (identKeyUsed) String() string {
	return "WithKeyUsed"
}

func (identMessage) String() string {
	return "WithMessage"
}

func (identMultipleKeysPerKeyID) String() string {
	return "WithMultipleKeysPerKeyID"
}

func (identPretty) String() string {
	return "WithPretty"
}

func (identProtectedHeaders) String() string {
	return "WithProtectedHeaders"
}

func (identPublicHeaders) String() string {
	return "WithPublicHeaders"
}

func (identRequireKid) String() string {
	return "WithRequireKid"
}

func (identSerialization) String() string {
	return "WithSerialization"
}

func (identUseDefault) String() string {
	return "WithUseDefault"
}

func (identValidateKey) String() string {
	return "WithValidateKey"
}

// WithBase64Encoder specifies the base64 encoder to be used while signing or
// verifying the JWS message. By default, the raw URL base64 encoding (no padding)
// is used.
func WithBase64Encoder(v Base64Encoder) SignVerifyCompactOption {
	return &signVerifyCompactOption{option.New(identBase64Encoder{}, v)}
}

func WithContext(v context.Context) VerifyOption {
	return &verifyOption{option.New(identContext{}, v)}
}

// WithDetached specifies that the `jws.Message` should be serialized in
// JWS compact serialization with detached payload. The resulting octet
// sequence will not contain the payload section.
func WithDetached(v bool) CompactOption {
	return &compactOption{option.New(identDetached{}, v)}
}

// WithDetachedPayload can be used to both sign or verify a JWS message with a
// detached payload.
//
// When this option is used for `jws.Sign()`, the first parameter (normally the payload)
// must be set to `nil`.
//
// If you have to verify using this option, you should know exactly how and why this works.
func WithDetachedPayload(v []byte) SignVerifyOption {
	return &signVerifyOption{option.New(identDetachedPayload{}, v)}
}

// WithFS specifies the source `fs.FS` object to read the file from.
func WithFS(v fs.FS) ReadFileOption {
	return &readFileOption{option.New(identFS{}, v)}
}

// WithInferAlgorithmFromKey specifies whether the JWS signing algorithm name
// should be inferred by looking at the provided key, in case the JWS
// message or the key does not have a proper `alg` header.
//
// When this option is set to true, a list of algorithm(s) that is compatible
// with the key type will be enumerated, and _ALL_ of them will be tried
// against the key/message pair. If any of them succeeds, the verification
// will be considered successful.
//
// Compared to providing explicit `alg` from the key this is slower, and
// verification may fail to verify if somehow our heuristics are wrong
// or outdated.
//
// Also, automatic detection of signature verification methods are always
// more vulnerable for potential attack vectors.
//
// It is highly recommended that you fix your key to contain a proper `alg`
// header field instead of resorting to using this option, but sometimes
// it just needs to happen.
func WithInferAlgorithmFromKey(v bool) WithKeySetSuboption {
	return &withKeySetSuboption{option.New(identInferAlgorithmFromKey{}, v)}
}

func WithKeyProvider(v KeyProvider) VerifyOption {
	return &verifyOption{option.New(identKeyProvider{}, v)}
}

// WithKeyUsed allows you to specify the `jws.Verify()` function to
// return the key used for verification. This may be useful when
// you specify multiple key sources or if you pass a `jwk.Set`
// and you want to know which key was successful at verifying the
// signature.
//
// `v` must be a pointer to an empty `interface{}`. Do not use
// `jwk.Key` here unless you are 100% sure that all keys that you
// have provided are instances of `jwk.Key` (remember that the
// jwx API allows users to specify a raw key such as *rsa.PublicKey)
func WithKeyUsed(v interface{}) VerifyOption {
	return &verifyOption{option.New(identKeyUsed{}, v)}
}

// WithMessage can be passed to Verify() to obtain the jws.Message upon
// a successful verification.
func WithMessage(v *Message) VerifyOption {
	return &verifyOption{option.New(identMessage{}, v)}
}

// WithMultipleKeysPerKeyID specifies if we should expect multiple keys
// to match against a key ID. By default it is assumed that key IDs are
// unique, i.e. for a given key ID, the key set only contains a single
// key that has the matching ID. When this option is set to true,
// multiple keys that match the same key ID in the set can be tried.
func WithMultipleKeysPerKeyID(v bool) WithKeySetSuboption {
	return &withKeySetSuboption{option.New(identMultipleKeysPerKeyID{}, v)}
}

// WithPretty specifies whether the JSON output should be formatted and
// indented
func WithPretty(v bool) WithJSONSuboption {
	return &withJSONSuboption{option.New(identPretty{}, v)}
}

// WithProtected is used with `jws.WithKey()` option when used with `jws.Sign()`
// to specify a protected header to be attached to the JWS signature.
//
// It has no effect if used when `jws.WithKey()` is passed to `jws.Verify()`
func WithProtectedHeaders(v Headers) WithKeySuboption {
	return &withKeySuboption{option.New(identProtectedHeaders{}, v)}
}

// WithPublic is used with `jws.WithKey()` option when used with `jws.Sign()`
// to specify a public header to be attached to the JWS signature.
//
// It has no effect if used when `jws.WithKey()` is passed to `jws.Verify()`
//
// `jws.Sign()` will result in an error if `jws.WithPublic()` is used
// and the serialization format is compact serialization.
func WithPublicHeaders(v Headers) WithKeySuboption {
	return &withKeySuboption{option.New(identPublicHeaders{}, v)}
}

// WithRequiredKid specifies whether the keys in the jwk.Set should
// only be matched if the target JWS message's Key ID and the Key ID
// in the given key matches.
func WithRequireKid(v bool) WithKeySetSuboption {
	return &withKeySetSuboption{option.New(identRequireKid{}, v)}
}

// WithCompact specifies that the result of `jws.Sign()` is serialized in
// compact format.
//
// By default `jws.Sign()` will opt to use compact format, so you usually
// do not need to specify this option other than to be explicit about it
func WithCompact() SignVerifyParseOption {
	return &signVerifyParseOption{option.New(identSerialization{}, fmtCompact)}
}

// WithUseDefault specifies that if and only if a jwk.Key contains
// exactly one jwk.Key, that key should be used.
func WithUseDefault(v bool) WithKeySetSuboption {
	return &withKeySetSuboption{option.New(identUseDefault{}, v)}
}

// WithValidateKey specifies whether the key used for signing or verification
// should be validated before using. Note that this means calling
// `key.Validate()` on the key, which in turn means that your key
// must be a `jwk.Key` instance, or a key that can be converted to
// a `jwk.Key` by calling `jwk.Import()`. This means that your
// custom hardware-backed keys will probably not work.
//
// You can directly call `key.Validate()` yourself if you need to
// mix keys that cannot be converted to `jwk.Key`.
//
// Please also note that use of this option will also result in
// one extra conversion of raw keys to a `jwk.Key` instance. If you
// care about shaving off as much as possible, consider using a
// pre-validated key instead of using this option to validate
// the key on-demand each time.
//
// By default, the key is not validated.
func WithValidateKey(v bool) SignVerifyOption {
	return &signVerifyOption{option.New(identValidateKey{}, v)}
}
