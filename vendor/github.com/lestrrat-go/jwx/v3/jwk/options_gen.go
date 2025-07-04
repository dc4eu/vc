// Code generated by tools/cmd/genoptions/main.go. DO NOT EDIT.

package jwk

import (
	"crypto"
	"io/fs"

	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/option/v2"
)

type Option = option.Interface

type AssignKeyIDOption interface {
	Option
	assignKeyIDOption()
}

type assignKeyIDOption struct {
	Option
}

func (*assignKeyIDOption) assignKeyIDOption() {}

// CacheOption is a type of Option that can be passed to the
// the `jwk.NewCache()` function.
type CacheOption interface {
	Option
	cacheOption()
}

type cacheOption struct {
	Option
}

func (*cacheOption) cacheOption() {}

// FetchOption is a type of Option that can be passed to `jwk.Fetch()`
// FetchOption also implements the `RegisterOption`, and thus can
// safely be passed to `(*jwk.Cache).Register()`
type FetchOption interface {
	Option
	fetchOption()
	parseOption()
	registerOption()
}

type fetchOption struct {
	Option
}

func (*fetchOption) fetchOption() {}

func (*fetchOption) parseOption() {}

func (*fetchOption) registerOption() {}

// GlobalOption is a type of Option that can be passed to the `jwk.Configure()` to
// change the global configuration of the jwk package.
type GlobalOption interface {
	Option
	globalOption()
}

type globalOption struct {
	Option
}

func (*globalOption) globalOption() {}

// ParseOption is a type of Option that can be passed to `jwk.Parse()`
// ParseOption also implements the `ReadFileOption` and `NewCacheOption`,
// and thus safely be passed to `jwk.ReadFile` and `(*jwk.Cache).Configure()`
type ParseOption interface {
	Option
	fetchOption()
	registerOption()
	readFileOption()
}

type parseOption struct {
	Option
}

func (*parseOption) fetchOption() {}

func (*parseOption) registerOption() {}

func (*parseOption) readFileOption() {}

// ReadFileOption is a type of `Option` that can be passed to `jwk.ReadFile`
type ReadFileOption interface {
	Option
	readFileOption()
}

type readFileOption struct {
	Option
}

func (*readFileOption) readFileOption() {}

// RegisterFetchOption describes options that can be passed to `(jwk.Cache).Register()` and `jwk.Fetch()`
type RegisterFetchOption interface {
	Option
	fetchOption()
	registerOption()
	parseOption()
}

type registerFetchOption struct {
	Option
}

func (*registerFetchOption) fetchOption() {}

func (*registerFetchOption) registerOption() {}

func (*registerFetchOption) parseOption() {}

// RegisterOption describes options that can be passed to `(jwk.Cache).Register()`
type RegisterOption interface {
	Option
	registerOption()
}

type registerOption struct {
	Option
}

func (*registerOption) registerOption() {}

// ResourceOption is a type of Option that can be passed to the `httprc.NewResource` function
// by way of RegisterOption.
type ResourceOption interface {
	Option
	resourceOption()
}

type resourceOption struct {
	Option
}

func (*resourceOption) resourceOption() {}

type identFS struct{}
type identFetchWhitelist struct{}
type identHTTPClient struct{}
type identIgnoreParseError struct{}
type identLocalRegistry struct{}
type identPEM struct{}
type identPEMDecoder struct{}
type identStrictKeyUsage struct{}
type identThumbprintHash struct{}
type identWaitReady struct{}

func (identFS) String() string {
	return "WithFS"
}

func (identFetchWhitelist) String() string {
	return "WithFetchWhitelist"
}

func (identHTTPClient) String() string {
	return "WithHTTPClient"
}

func (identIgnoreParseError) String() string {
	return "WithIgnoreParseError"
}

func (identLocalRegistry) String() string {
	return "withLocalRegistry"
}

func (identPEM) String() string {
	return "WithPEM"
}

func (identPEMDecoder) String() string {
	return "WithPEMDecoder"
}

func (identStrictKeyUsage) String() string {
	return "WithStrictKeyUsage"
}

func (identThumbprintHash) String() string {
	return "WithThumbprintHash"
}

func (identWaitReady) String() string {
	return "WithWaitReady"
}

// WithFS specifies the source `fs.FS` object to read the file from.
func WithFS(v fs.FS) ReadFileOption {
	return &readFileOption{option.New(identFS{}, v)}
}

// WithFetchWhitelist specifies the Whitelist object to use when
// fetching JWKs from a remote source. This option can be passed
// to both `jwk.Fetch()`
func WithFetchWhitelist(v Whitelist) FetchOption {
	return &fetchOption{option.New(identFetchWhitelist{}, v)}
}

// WithHTTPClient allows users to specify the "net/http".Client object that
// is used when fetching jwk.Set objects.
func WithHTTPClient(v HTTPClient) RegisterFetchOption {
	return &registerFetchOption{option.New(identHTTPClient{}, v)}
}

// WithIgnoreParseError is only applicable when used with `jwk.Parse()`
// (i.e. to parse JWK sets). If passed to `jwk.ParseKey()`, the function
// will return an error no matter what the input is.
//
// DO NOT USE WITHOUT EXHAUSTING ALL OTHER ROUTES FIRST.
//
// The option specifies that errors found during parsing of individual
// keys are ignored. For example, if you had keys A, B, C where B is
// invalid (e.g. it does not contain the required fields), then the
// resulting JWKS will contain keys A and C only.
//
// This options exists as an escape hatch for those times when a
// key in a JWKS that is irrelevant for your use case is causing
// your JWKS parsing to fail, and you want to get to the rest of the
// keys in the JWKS.
//
// Again, DO NOT USE unless you have exhausted all other routes.
// When you use this option, you will not be able to tell if you are
// using a faulty JWKS, except for when there are JSON syntax errors.
func WithIgnoreParseError(v bool) ParseOption {
	return &parseOption{option.New(identIgnoreParseError{}, v)}
}

// This option is only available for internal code. Users don't get to play with it
func withLocalRegistry(v *json.Registry) ParseOption {
	return &parseOption{option.New(identLocalRegistry{}, v)}
}

// WithPEM specifies that the input to `Parse()` is a PEM encoded key.
func WithPEM(v bool) ParseOption {
	return &parseOption{option.New(identPEM{}, v)}
}

// WithPEMDecoder specifies the PEMDecoder object to use when decoding
// PEM encoded keys. This option can be passed to `jwk.Parse()`
func WithPEMDecoder(v PEMDecoder) ParseOption {
	return &parseOption{option.New(identPEMDecoder{}, v)}
}

// WithStrictKeyUsage specifies if during JWK parsing, the "use" field
// should be confined to the values that have been registered via
// `jwk.RegisterKeyType()`. By default this option is true, and the
// initial allowed values are "use" and "enc" only.
//
// If this option is set to false, then the "use" field can be any
// value. If this options is set to true, then the "use" field must
// be one of the registered values, and otherwise an error will be
// reported during parsing / assignment to `jwk.KeyUsageType`
func WithStrictKeyUsage(v bool) GlobalOption {
	return &globalOption{option.New(identStrictKeyUsage{}, v)}
}

func WithThumbprintHash(v crypto.Hash) AssignKeyIDOption {
	return &assignKeyIDOption{option.New(identThumbprintHash{}, v)}
}

// WithWaitReady specifies that the `jwk.Cache` should wait until the
// first fetch is done before returning from the `Register()` call.
//
// This option is by default true. Specify a false value if you would
// like to return immediately from the `Register()` call.
//
// This options is exactly the same as `httprc.WithWaitReady()`
func WithWaitReady(v bool) RegisterOption {
	return &registerOption{option.New(identWaitReady{}, v)}
}
