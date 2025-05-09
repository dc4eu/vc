package openid4vci

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestCredentialOffer(t *testing.T) {
	tts := []struct {
		name       string
		parameters *CredentialOfferParameters
		want       string
	}{
		{
			name: "authorization_code",
			parameters: &CredentialOfferParameters{
				CredentialIssuer: "issuer.sunet.se",
				CredentialConfigurationIDs: []string{
					"PDA1Credential",
				},
				Grants: map[string]any{
					"authorization_code": &GrantAuthorizationCode{
						IssuerState: fmt.Sprintf("collect_id=%s&document_type=%s&authentic_source=%s", "collect_id_1", "PDA1", "test_authentic_source"),
					},
				},
			},
			want: "credential_offer=%7B%22credential_issuer%22%3A%22issuer.sunet.se%22%2C%22credential_configuration_ids%22%3A%5B%22PDA1Credential%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22collect_id%3Dcollect_id_1%5Cu0026document_type%3DPDA1%5Cu0026authentic_source%3Dtest_authentic_source%22%7D%7D%7D",
		},
		{
			name: "pre-authorized_code",
			parameters: &CredentialOfferParameters{
				CredentialIssuer: "https://credential-issuer.example.com",
				CredentialConfigurationIDs: []string{
					"UniversityDegreeCredential",
					"org.iso.18013.5.1.mDL",
				},
				Grants: map[string]any{
					"urn:ietf:params:oauth:grant-type:pre-authorized_code": &GrantPreAuthorizedCode{
						PreAuthorizedCode: "oaKazRN8I0IbtZ0C7JuMn5",
						TXCode: TXCode{
							InputMode:   "numeric",
							Length:      4,
							Description: "Please provide the one-time code that was sent via e-mail",
						},
						AuthorizationServer: "",
					},
				},
			},
			want: "credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fcredential-issuer.example.com%22%2C%22credential_configuration_ids%22%3A%5B%22UniversityDegreeCredential%22%2C%22org.iso.18013.5.1.mDL%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre_authorized_code%22%3A%22oaKazRN8I0IbtZ0C7JuMn5%22%2C%22tx_code%22%3A%7B%22input_mode%22%3A%22numeric%22%2C%22length%22%3A4%2C%22description%22%3A%22Please+provide+the+one-time+code+that+was+sent+via+e-mail%22%7D%7D%7D%7D",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.parameters.CredentialOffer()
			assert.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseCredentialOffer(t *testing.T) {
	tts := []struct {
		name string
		have string
		want *CredentialOfferParameters
	}{
		{
			name: "espoo bootcamp",
			have: "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fagent.ssi.dev.sphereon.com%2Fdid-web%2Foid4vci%22%2C%22credential_configuration_ids%22%3A%5B%22PensionSdJwt%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22d270fee1-9185-4e60-9901-d291e1338d7a%22%7D%7D%7D",
			want: &CredentialOfferParameters{
				CredentialIssuer:           "https://agent.ssi.dev.sphereon.com/did-web/oid4vci",
				CredentialConfigurationIDs: []string{"PensionSdJwt"},
				Grants: map[string]any{
					"urn:ietf:params:oauth:grant-type:pre-authorized_code": &GrantPreAuthorizedCode{
						PreAuthorizedCode:   "d270fee1-9185-4e60-9901-d291e1338d7a",
						TXCode:              TXCode{},
						AuthorizationServer: "",
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCredentialOfferURI(tt.have)
			assert.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCredentialOfferQR(t *testing.T) {
	tts := []struct {
		name       string
		parameters *CredentialOfferParameters
		want       *QR
		walletHost string
	}{
		{
			name:       "openid-credential-offer",
			walletHost: "",
			parameters: &CredentialOfferParameters{
				CredentialIssuer: "issuer.sunet.se",
				CredentialConfigurationIDs: []string{
					"PDA1Credential",
				},
				Grants: map[string]any{
					"authorization_code": &GrantAuthorizationCode{
						IssuerState: fmt.Sprintf("collect_id=%s&document_type=%s&authentic_source=%s", "collect_id_1", "PDA1", "test_authentic_source"),
					},
				},
			},
			want: &QR{
				QRBase64:           "iVBORw0KGgoAAAANSUhEUgAAAQAAAAEAAQMAAABmvDolAAAABlBMVEX///8AAABVwtN+AAAFDklEQVR42uyYP661KhTFN6GgkwmYwzQsTJiSpR10lk6JxMJpYJwAp6MgrJft9Xy5ea0ei/c+i/vPX3I5sFl7rU1/n//XI4BqgC04gTBg8U3bUZTTO1og3AMEaqhzL5lF7HS0WUSLSiO1Hb97BljQkALZrGNHZvFiD0OlsWk7t90IkDaL13t224JkVmyYEJ8FJL+ZqO004FGsf1lQex/AW63ShqmRa4rSk1mTwVTp91l8GQBq2w3bMjX/+varJq8B/LRE1Dtd7BxlPqqaVGp/XZ4vA6K4RgbaMOl99QBEUR6YRPzsw2WA7JRaha04MmEwyA1ZbMhAHio9AwjkSmrG4t87EoB3VNiCEoXcbYAXUc0kIQoN25LfO3ztidWCHgMy9uyqhUbWoihdyAm+ZzSYcAtANIpiYQrpPejYO+wA2amaNeEpQE58eSvrb+e24hoTeJGikBY3ATZTyz+PiDb9rMEDWUc7nyX3fYAUYkdYcjJIpqhG5mFbPEngZ5HXATmlYwOIWpvI+jfLRO/0Dv+iZwABoFi8yInSsZy8CznDV3nFFu4Blnz8V3IaQCUCgvvpOISHALIZe9AoiiT/7oCgNzY2KyLdA0jQYVEmXWgAciOzxsKinJ4CRBkbvqeL58rbALEHt5UxyfzpOJcB+Hchekk2DmkDyGRHPeli02PAkqtZ5yqPDRDLlMyaRFFVZmfCLQDJSbAUk6ut4huD2GmzAFg9HgLEMumikliAQkPtVdOqWQAk89kvrgPAGyuLE9cQ4BuZeeN16TQeAsiiMVlHCWotTFDc40Uhktn91NxlQGBKbTdwC0d20f6oRU8sg/EpYJkOyTg8KHuYKg/Ty83h1MnrAMggkURqrY/SJ4M59qq2NJxr+DpAllc3v+xUSXmOMK31pih24zcBIjhqrUdQ76JSlGCLAnh2S2cg/T7A5bwi2imZzFLMEYaNgwFOKb4O8FddpccehheNHLirzCgKp/n/OkAsGXwWvkrMkZRGGFDc4U/vAdj4HTcGnItEILbAR7fNAx4CiFxjML96qnKdDV8w0oJjlE3mHuDUhy241JJ70ah3zPz3fU2/BeSrQHCcf8VyjE84yUROar6R6/y6CVgytd2AMr6LRe3VG1nXfmwMQA8B1BP2Nb3sRIYdN5qWBhRi/Oe4LwPc1ArbzKkxq682o1jPQdggnYH0+0AYsXOt5aZViSMUawgrlp3PSc5VgIhSy4GIhSGZMDaSu05mKcZTQO9QiEzgpD1EciLSOUU5+8VlQBTe7ZmdmASoH9+lc7UfUbrTLn4fIDlhx1yl15Eb6zmwwmEK7wEEciL1k9SU34I6va9me/YY4Ju2c7wdUWFbOD95AyT61OR1oDhq+SM7Fr6NKyprUegd1Xwe9/eBQLW1fE859HPJ7Su2Mla5+s8I9CJAPXE2O03Jy2bxk4Brq9KLHgJkrrw66Wtr/eENwyCKepc/NXkVEGEUUc3VAqXjTl5ZLWRuqBs+MvhtgOykgfnFMSNocKAJZNiNfyY514FjVuy24jgsRXm8ASb21b+GyV8FBFCJPzmIjmG53rPeikp/jPd1IBDrO5as2ZDJ/GZF5mjPhuUhYEFjkAQm9qBHf83DeRYm3Aa0KlHvqgn6xW4CeNlcZaBPjHoCIBrE4o9sxu3gmKmIHcmEe4BAbHo3vq4WArzVVPtR4xNIHwAAliM2hQYey0SksIWxGvg/VX0N+Pv8d55/AgAA//9h4ly0GvTadgAAAABJRU5ErkJggg==",
				CredentialOfferURL: "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22issuer.sunet.se%22%2C%22credential_configuration_ids%22%3A%5B%22PDA1Credential%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22collect_id%3Dcollect_id_1%5Cu0026document_type%3DPDA1%5Cu0026authentic_source%3Dtest_authentic_source%22%7D%7D%7D",
			},
		},
		{
			name:       "wallet.dc4eu.eu+cb",
			walletHost: "https://wallet.dc4eu.eu/cb",
			parameters: &CredentialOfferParameters{
				CredentialIssuer: "https://satosa-test-1.sunet.se",
				CredentialConfigurationIDs: []string{
					"EHICCredential",
				},
				Grants: map[string]any{
					"authorization_code": &GrantAuthorizationCode{
						IssuerState: fmt.Sprintf("collect_id=%s&document_type=%s&authentic_source=%s", "d779badf-f333-434a-8bdf-fc0d419231ef", "EHIC", "SUNET"),
					},
				},
			},
			want: &QR{
				QRBase64:           "iVBORw0KGgoAAAANSUhEUgAAAQAAAAEAAQMAAABmvDolAAAABlBMVEX///8AAABVwtN+AAAFb0lEQVR42uyYMY77KhfFD6KgMxuw4m1QRGJLni7V36RKF28JKYW3wYgN4I7C4ny6Tkb/18cT6Xt6FC6i38gMvufcc8F/61+1NFnVI/Sej5IjgP7SfNH85kymY4AAxzjq2gTufNNB8a4D0AEHAfPm1Db28t7k4ZnZ8MXK2A31g0CDHVh0YLW866pYMMHcjwRstD0sZxiyYYIvA9VyHCBHzbl3Ko6bK+bKGzAlqPjPb/HLAFnXx9y752O595fv5+MfJfceIMuSG+yDmsXsP49DaCb81cZ7gObmm581V5bNUz7kwCBF+5VvHwO4kCWh09QVfs2ySc2TX3NIxwAlc/+kxYfN2eWu68A5mSF2+rmH9wH2WB+EHHVm89dck2/Drbkv1k8B80C72d6XM6SimMPJN0xqub6O+m0AE+P6CMOiHoRZ41cmTBkIv76K9gAg+aLD5nGeMsmAi2LTVLymCZ8BNBnVBrLoOYvB9VPDtMmfDTwICMkzjsl3sofmpoRhuevbybRXRb0NYOxN21//CL2DU3mXBHc3TZ8BdOk9ZQFipL7BqKVJ7+j651G/DWCEWR+ifF2GCqgsXaJHM2u6HANIS1q3SbOcsbm1jmIzd0xDHP82918GgBzLecrR7h5QZZNuFOGE3uAQQOS/PsLmOh/0Uvy6XU6u68E4ZR4DwGrRxVDh5x5wGELC1zYlsz5N7AOAnpPnBs2my7DYpegbvDykDo4BYGE6jDnibJPvzEo+xWHCSzhvA9KSmi6aHUCq2vVG1U7Ecf8Rzu8Dc0LRJRm1IddOhHMyK29/Xe5tAFPv1TaylvPYe1X/YFKUo3ZfORwDaMLwUaSxzjp2GPupOckPUjDpM4B4GzDppQMyi2nAsHDD3571NqBnRvWYe6hHgetgt0uT1zd/fW3yfYAD+SiMOEMCdNFBwh4VydungLCh+ADfdEkoZt1dTtfmwxAOAoqk9iDdKOhlXe46DMsdEF0YHAOEHuLVC8lci2Gavhl0TSL/YwBgYME4sGGUZH7ff9CEJ0P6DCDyb+dJR/sIeYFvuMiEUvfp4CBgH/sDqSI218mmTm6S6D4Orxz1LoApLxIdaOWf2yeuhrG/JP+aWD8A6JJE/rmuLP3efilnb9QSenMMAJtM8bPMPHPeN1JPDrKHOeEgYMwsgFiKOIwbYb7rlG9N5jl8BtAzwG3snQx8Bl76rVPbpTnolw2+DZTN2bi3JEhstrnCSHTH10sXbwMY025iRj2oI5eC6eTFqzGKQj4DTJu3cYJvnpmdv+ub4v1ZUa9B7G3AwnCzukrs47pc0+XkLJmEPwgY0/NWrZO5sfn99VK56F7y/wAARhWtrnYfnReZruSok7+mKR0CiNrXOA3EGRvWaJMZOOcw7On2EAAjl05a397/yGtmwpeEvfCjzV8HxMw7KSsZIbnKKUNq+GS44RgAI6Bk3lCcYTp/3SZIfkj+ml/afBfQIdfdoRumHMt+l+Ysb4xf2ys//D5QdLSUpiF+VzxZvxmG0PxMHgPAZhZddO10YWxmvwqWrBTVYcCYoMhkcJ6SV1zTZR+xTphewvl9QM/D7j5Lwdi7fcRi/dObYQl4Rfe3gSB1VPLSnZFM97RpxVtz3Y8u3gc2t0Y7sJwxVHIV5Tcddl2kzwBPnxth7IMwe3Rv+05N6KdjgOe9vZiaD8mtyx0XxXsv0X34udB+Fwhw8Eym6LKhSK18R/RT8j97+AAwb66dR8buDL0fdVVLAfbojsOAlQV+ZUm+8zIYyLAAc/25qDkCaGfkWHSBs7GDGZY5U/GuPwYEuOYDWXxJaKb1lwQrnTf0l4OAvaKk653BqqpNOPkiyv/zGiffBv5b/zfrfwEAAP//DUrFw1K+9WoAAAAASUVORK5CYII=",
				CredentialOfferURL: "https://wallet.dc4eu.eu/cb?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fsatosa-test-1.sunet.se%22%2C%22credential_configuration_ids%22%3A%5B%22EHICCredential%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22collect_id%3Dd779badf-f333-434a-8bdf-fc0d419231ef%5Cu0026document_type%3DEHIC%5Cu0026authentic_source%3DSUNET%22%7D%7D%7D",
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			p, err := tt.parameters.CredentialOffer()
			assert.NoError(t, err)

			got, err := p.QR(0, 256, tt.walletHost)
			assert.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCredentialOfferURIQR(t *testing.T) {
	tts := []struct {
		name                 string
		parameters           *CredentialOfferParameters
		credentialServerAddr string
		want                 *QR
	}{
		{
			name: "",
			parameters: &CredentialOfferParameters{
				CredentialIssuer: "https://issuer.sunet.se",
				CredentialConfigurationIDs: []string{
					"PDA1Credential",
				},
				Grants: map[string]any{
					"authorization_code": &GrantAuthorizationCode{
						IssuerState: fmt.Sprintf("collect_id=%s&document_type=%s&authentic_source=%s", "d779badf-f333-434a-8bdf-fc0d419231ef", "PDA1", "SUNET"),
					},
				},
			},
			want: &QR{},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			p, err := tt.parameters.CredentialOfferURI()
			assert.NoError(t, err)

			qr, err := p.QR(0, 256, "https://wallet.dc4eu.eu/cb", "https://issuer.sunet.se")
			assert.NoError(t, err)

			assert.Equal(t, tt.want, qr)
		})
	}
}

func TestCredentialOfferURI(t *testing.T) {
	tts := []struct {
		name                 string
		parameters           *CredentialOfferParameters
		credentialServerAddr string
		want                 url.URL
	}{
		{
			name: "",
			parameters: &CredentialOfferParameters{
				CredentialIssuer: "https://issuer.sunet.se",
				CredentialConfigurationIDs: []string{
					"PDA1Credential",
				},
				Grants: map[string]any{
					"authorization_code": &GrantAuthorizationCode{
						IssuerState: fmt.Sprintf("collect_id=%s&document_type=%s&authentic_source=%s", "d779badf-f333-434a-8bdf-fc0d419231ef", "PDA1", "SUNET"),
					},
				},
			},
			want: url.URL{
				Scheme: "https",
				Host:   "issuer.sunet.se",
				Path:   "credential-offer",
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.parameters.CredentialOfferURI()
			assert.NoError(t, err)

			u, err := url.Parse(got.String())
			assert.NoError(t, err)

			assert.Equal(t, tt.want.Scheme, u.Scheme)
			assert.Equal(t, tt.want.Host, u.Host)
			assert.Equal(t, tt.want.Path, strings.Split(u.Path, "/")[1])
		})
	}
}

func TestUnpackCredentialOffer(t *testing.T) {
	tts := []struct {
		name  string
		offer CredentialOffer
		want  *CredentialOfferParameters
	}{
		{
			name:  "authorization_code",
			offer: "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Fvc_dev_apigw:8080%22%2C%22credential_configuration_ids%22%3A%5B%22EHICCredential%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22collect_id%3Dcdd81c80-f4ca-41fc-a6a6-6b4e322a77d7%5Cu0026document_type%3DEHIC%5Cu0026authentic_source%3DSUNET%22%7D%7D%7D",
			want: &CredentialOfferParameters{
				CredentialIssuer: "http://vc_dev_apigw:8080",
				CredentialConfigurationIDs: []string{
					"EHICCredential",
				},
				Grants: map[string]any{
					"authorization_code": &GrantAuthorizationCode{
						IssuerState: "collect_id=cdd81c80-f4ca-41fc-a6a6-6b4e322a77d7&document_type=EHIC&authentic_source=SUNET",
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.offer.Unpack(context.TODO())
			assert.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCredentialOfferUriUUID(t *testing.T) {
	tts := []struct {
		name string
		have *CredentialOfferParameters
	}{
		{
			name: "t1",
			have: &CredentialOfferParameters{
				CredentialIssuer: "http://test.sunet.se",
				CredentialConfigurationIDs: []string{
					"TestCredential",
				},
				Grants: map[string]any{
					"authorization_code": GrantAuthorizationCode{
						IssuerState: fmt.Sprintf("collect_id=%s&document_type=%s&authentic_source=%s", "test_collect_id", "document_type", "authentic_source"),
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			uri, err := tt.have.CredentialOfferURI()
			assert.NoError(t, err)

			got, err := uri.UUID()
			assert.NoError(t, err)

			err = uuid.Validate(got)
			assert.NoError(t, err)
		})
	}
}
