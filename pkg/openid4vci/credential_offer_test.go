package openid4vci

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

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

func TestQR(t *testing.T) {
	tts := []struct {
		name       string
		parameters *CredentialOfferParameters
		want       *QR
		walletHost string
	}{
		{
			name:       "qr",
			walletHost: "https://wallet.example.com",
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
				QRBase64:           "iVBORw0KGgoAAAANSUhEUgAAAQAAAAEAAQMAAABmvDolAAAABlBMVEX///8AAABVwtN+AAAFCUlEQVR42uyYMa6kOhOFy3LgDG8A4W0QIHlLhGR2RthbskTANozYgDtzYPn8Kpp7Nf9LoQneG5Keuf0FblN16pyiv89/6xFAbfsRwQmEEYtv2p6inN/RAuEeIFBDvSOZRex1tFlEi0oTtT1/9wywoCHSnc069mQWL/YwVpqatnfbrYBZvN6z2xYks2LDrOOzgORvZmp7DXgU6zsJau8D+KpV2jA3ck1RejJrMstc6c938WXgU3LbMjf/+Pj/mrwA8NMS0eB0sa8o81HVpFL7R/N8GRDFNTIQv+B99QBEUR6YRfy5h+tAcKlV2IojE0aD3JDFhgzksdJDQJkqqRcW/96RALyjwhaUKOTuAgAR1YskRKFxW/J7h68DiT1oegzI2LOrFhpZi6J0ISe4z2g04RaAaHoXC1NI70HHwWEHyPpq1oSnADlXuabK+tu7rbjGBCcWLwppcRNg80fYJ0SbPmfwQNbRvranAFKIypslJ4NkimpkHrfFkwTMTYCck8zUDUStTWT9m2VicHrHq6NnAAGg2FdHTpSe5eRdyBlu5RVbuAdYciJWXacBVCL+Z0cutT3hIYBsrjJoFEWS/++AoDeAFSvSPYAEUe86OetCI5AbmY/5CvjHgGHiiYrFI/a0AWIPbgvTG/kcOZcBsfh3IeokG4d0XEB2NJCONj0FkGQ5elV5XIBY5mTWJIqqMruzsy4DdhYsxeRqq7hjEHttFgCrx0OAWGZdVBILUGisg2pa9RIAyXzOi+sA5jdWFieAB6tvWC2k5/mDhwCyuTFZR/agFiYonvGiEJc60S2AgKe2HwW8QHbR5o8MKr2fjfMEsMwox0fTWvYwPAMNwMPh1MnrAMgAUSK11kfpkwGfobY0nmf4OkB25iKrdq6kPEeY1npTFLvxmwARHB02Xr2LSlGCLQrg2S2dgfT7AJfzimjnZDJLMUcYtqIG6XPIGwBKRLpKjz2MHU3vT+bVReE0/18HiCXDvjrrq8QrktII4zFmM90EiGX+dAw4F4lAbIFJshMe8RTAHhSvbqAq15fhBiPNwhVtMjcBmBNHUA5L5Dqa2ILx3/f1fN2PADpaiOVYn3CSiZzUfGPWHzd4HWBfPaIcKaIO6o2s6zA1BqCHABomYE2dncmw40bT0ohCqbWvz8S5DIii2KIAc2NWX21GsZ4sksl0JtbvA2HCzrWWm1YljlCsIaxYZ4S5DhAdP7kewpBMmBrJU+fcBz4EDA6F2CqIyAPAiUjnFuWcF5cBUUhg9ezEJEDD9C69q8OE0ruzu78OkJyxB83GKPJgPRdWwJ71TYAAkgSfQRTlt6BO76ux/i7Nvg/42vaaryMqbAuqWT17GLIvcRNQpnTYQMfCt3FF5RN/na/7+0Cg2loe5xz6ueT2FVuZeDj8rEAvAnSsntxpSjqbxSfacyt/sv8DgMyVTyd9ba0/vGEYD+Hqf2ryKiDCxLdaLVB6nuSV1ULmhvqf9ePXAXakEq/OojFBA3gjkFlmtoTnwuoycOyK3VYch6Uoj2+AmX31H8vkrwICqMS/HETHslzvWW9FpV/jfR0IxPqOJWs2ZDK/WZEHOurrKWBBY5DYynAE5fmaR7PM1Zx7uXuAViUaXDVBdwNxfDDIVa4/YfARgMiJxR/ZjMcBUSch9t/lwGUgUNMqv3G7WgjwVVMdJg347SkAqCaPYslk4LHMRApbmKpB+q3qa8Df59/z/C8AAP//jcBQ82xjA8sAAAAASUVORK5CYII=",
				CredentialOfferURL: "https://wallet.example.com?credential_offer=%7B%22credential_issuer%22%3A%22issuer.sunet.se%22%2C%22credential_configuration_ids%22%3A%5B%22PDA1Credential%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22collect_id%3Dcollect_id_1%5Cu0026document_type%3DPDA1%5Cu0026authentic_source%3Dtest_authentic_source%22%7D%7D%7D",
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
