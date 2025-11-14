package sdjwtv4

import (
	"fmt"
	"vc/pkg/sdjwt3"
)

// MakeCredential creates a SD-JWT credential from the provided data and VCTM.
func (c *Client) MakeCredential(data map[string]any, vctm *sdjwt3.VCTM) (map[string]any, error) {
	//data["_sd"] = []any{}

	data["_sd_alg"] = "sha256"

	for _, claim := range vctm.Claims {
		if len(claim.Path) == 1 {
			for _, path := range claim.Path {
				fmt.Println("path", *path)
				if claim.SD == "always" {
					if _, ok := data["_sd"]; !ok {
						data["_sd"] = []any{}
					}
					data["_sd"] = append(data["_sd"].([]any), "mockSDJWTHash_"+*path)
					delete(data, *path)
				}
			}
		} else if len(claim.Path) > 1 {
			current := data
			var parent map[string]any
			var key string
			for i, path := range claim.Path {
				if i == len(claim.Path)-1 {
					// Last element
					fmt.Println("index", i, "path", *path)
					if claim.SD == "always" {
						if _, ok := current["_sd"]; !ok {
							current["_sd"] = []any{}
						}
						current["_sd"] = append(current["_sd"].([]any), "mockSDJWTHash_"+*path)
						delete(current, *path)
					}
				} else {
					// Traverse deeper
					if next, ok := current[*path].(map[string]any); ok {
						parent = current
						key = *path
						current = next
					} else {
						break
					}
				}
			}
			// If the entire path was traversed and SD is "always", remove the parent key if empty
			if claim.SD == "always" {
				if len(current) == 0 && parent != nil {
					delete(parent, key)
				}
			}
		}
	}

	return data, nil
}
