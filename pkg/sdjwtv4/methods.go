package sdjwtv4

import (
	"fmt"
	"vc/pkg/sdjwt3"
)

// MakeCredential creates a SD-JWT credential from the provided data and VCTM.
func (c *Client) MakeCredential(data map[string]any, vctm *sdjwt3.VCTM) (map[string]any, []string, error) {
	//data["_sd"] = []any{}

	diclosurs := []string{}

	data["_sd_alg"] = "sha256"

	for _, claim := range vctm.Claims {
		if len(claim.Path) == 1 {
			for _, path := range claim.Path {
				fmt.Println("path", *path)
				if claim.SD == "always" {
					if _, ok := data["_sd"]; !ok {
						data["_sd"] = []any{}
					}
					hash := sdjwt3.Discloser{
						Salt:      "mockSalt",
						ClaimName: *path,
						Value:     data[*path],
					}
					sdHash, sdB64, _, err := hash.Hash()
					if err != nil {
						return nil, nil, err
					}
					diclosurs = append(diclosurs, sdB64)
					fmt.Println("sdHash", sdHash, "sdB64", sdB64)
					data["_sd"] = append(data["_sd"].([]any), sdHash)
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
						hash := sdjwt3.Discloser{
							Salt:      "mockSalt",
							ClaimName: *path,
							Value:     current[*path],
						}
						fmt.Println("value 2", current[*path])
						sdHash, sdB64, _, err := hash.Hash()
						if err != nil {
							return nil, nil, err
						}
						diclosurs = append(diclosurs, sdB64)
						fmt.Println("sdHash", sdHash, "sdB64", sdB64)
						current["_sd"] = append(current["_sd"].([]any), sdHash)
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

	return data, diclosurs, nil
}
