package model

// APIServer holds the api server configuration
type APIServer struct {
	Host string `yaml:"host" validate:"required"`
}

// Mongo holds the database configuration
type Mongo struct {
	URI string `yaml:"uri" validate:"required"`
}

// CA holds the ca configuration
type CA struct {
	ServerURL string `yaml:"server_url" validate:"required"`
	Token     string `yaml:"token" validate:"required"`
	KeyLabel  string `yaml:"key_label" validate:"required"`
	KeyType   string `yaml:"key_type" validate:"required"`
}

// Log holds the log configuration
type Log struct {
	Level string `yaml:"level"`
}

// Common holds the common configuration
type Common struct {
	HTTPProxy  string `yaml:"http_proxy"`
	Production bool   `yaml:"production"`
	Log        Log    `yaml:"log"`
}

// Issuer holds the issuer configuration
type Issuer struct {
	APIServer APIServer `yaml:"api_server" validate:"required"`
	Mongo     Mongo     `yaml:"mongo" validate:"required"`
	CA        CA        `yaml:"ca" validate:"required"`
}

// Verifier holds the verifier configuration
type Verifier struct{}

// Cfg is the main configuration structure for this application
type Cfg struct {
	Common   Common   `yaml:"common"`
	Issuer   Issuer   `yaml:"issuer"`
	Verifier Verifier `yaml:"verifier"`
}
