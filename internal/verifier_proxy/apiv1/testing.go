package apiv1

// SetSigningKeyForTesting sets the OIDC signing key for testing purposes.
// This is needed because the production code has a TODO for loading the key from config.
func (c *Client) SetSigningKeyForTesting(key any, alg string) {
	c.oidcSigningKey = key
	c.oidcSigningAlg = alg
}
