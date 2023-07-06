package model

// APIServer holds the api server configuration
type APIServer struct {
	Addr string `yaml:"addr" validate:"required"`
}

// Mongo holds the database configuration
type Mongo struct {
	URI string `yaml:"uri" validate:"required"`
}

// KeyValue holds the key/value configuration
type KeyValue struct {
	Addr string `yaml:"addr" validate:"required"`
	DB   int    `yaml:"db" validate:"required"`
	PDF  PDF    `yaml:"pdf" validate:"required"`
}

// CA holds the ca configuration
type CA struct {
	Addr     string `yaml:"addr" validate:"required"`
	Token    string `yaml:"token" validate:"required"`
	KeyLabel string `yaml:"key_label" validate:"required"`
	KeyType  string `yaml:"key_type" validate:"required"`
}

// Log holds the log configuration
type Log struct {
	Level string `yaml:"level"`
}

// Common holds the common configuration
type Common struct {
	HTTPProxy  string            `yaml:"http_proxy"`
	Production bool              `yaml:"production"`
	Log        Log               `yaml:"log"`
	Mongo      Mongo             `yaml:"mongo" validate:"required"`
	BasicAuth  map[string]string `yaml:"basic_auth" validate:"required"`
}

// Issuer holds the issuer configuration
type Issuer struct {
	APIServer APIServer `yaml:"api_server" validate:"required"`
	//Mongo     Mongo     `yaml:"mongo" validate:"required"`
	CA       CA       `yaml:"ca" validate:"required"`
	KeyValue KeyValue `yaml:"key_value" validate:"required"`
}

// PDF holds the pdf configuration (special Ladok case)
type PDF struct {
	KeepSignedDuration   int `yaml:"keep_signed_duration"`
	KeepUnsignedDuration int `yaml:"keep_unsigned_duration"`
}

// Verifier holds the verifier configuration
type Verifier struct {
	APIServer APIServer `yaml:"api_server" validate:"required"`
}

// Datastore holds the datastore configuration
type Datastore struct {
	APIServer APIServer `yaml:"api_server" validate:"required"`
	//Mongo     Mongo     `yaml:"mongo" validate:"required"`
}

// Cfg is the main configuration structure for this application
type Cfg struct {
	Common    Common    `yaml:"common"`
	Issuer    Issuer    `yaml:"issuer"`
	Verifier  Verifier  `yaml:"verifier"`
	Datastore Datastore `yaml:"datastore"`
}
