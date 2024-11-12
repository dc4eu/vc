package sdjwt3

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitToken(t *testing.T) {
	type want struct {
		header, body, signature string
		selectiveDisclosure     []string
		err                     error
	}
	tts := []struct {
		name  string
		token string
		want  want
	}{
		{
			name:  "empty",
			token: "",
			want: want{
				header:              "",
				body:                "",
				signature:           "",
				selectiveDisclosure: nil,
				err:                 errors.New("empty token"),
			},
		},
		{
			name:  "without selective disclosure",
			token: "eyJraWQiOiJkZWZhdWx0X3NpZ25pbmdfa2V5X2lkIiwidHlwIjoidmMrc2Qtand0In0.eyJjbmYiOnsiandrIjp7ImNydiI6IlAtMjU2IiwiZCI6Img4bGx6V0ZkNFNtc3dJVDZXbVNydmh4VzhzbTJzQ3d4TWZEYlhLVzlpZEUiLCJraWQiOiJkZWZhdWx0X3NpZ25pbmdfa2V5X2lkIiwia3R5IjoiRUMiLCJ4IjoienVzQmRGNlFtUkRNWmFoQlJNZDctNXItRjR5ZTl0VlMwUUhNVnNjWEk1cyIsInkiOiJXSzFEdjNXTl9fQmlVYVR0cGh1a2h2TzR6bXFmbGVpWFlfbTNJUnNISmJzIn19LCJjb21wZXRlbnRfaW5zdGl0dXRpb24iOnsiY291bnRyeV9jb2RlIjoiIiwiaW5zdGl0dXRpb25faWQiOiIiLCJpbnN0aXR1dGlvbl9uYW1lIjoiIn0sImRlY2lzaW9uX2xlZ2lzbGF0aW9uX2FwcGxpY2FibGUiOnsiZW5kaW5nX2RhdGUiOiIiLCJtZW1iZXJfc3RhdGVfd2hpY2hfbGVnaXNsYXRpb25fYXBwbGllcyI6IiIsInN0YXJ0aW5nX2RhdGUiOiIiLCJ0cmFuc2l0aW9uYWxfcnVsZV9hcHBseSI6ZmFsc2V9LCJkZXRhaWxzX29mX2VtcGxveW1lbnQiOlt7ImFkZHJlc3MiOnsiY291bnRyeSI6IlNFIiwicG9zdF9jb2RlIjoiMTIzNDUiLCJzdHJlZXQiOiJzdHJlZXQiLCJ0b3duIjoidG93biJ9LCJpZHNfb2ZfZW1wbG95ZXIiOlt7ImVtcGxveWVyX2lkIjoiMTIzIiwidHlwZV9vZl9pZCI6IjAxIn1dLCJuYW1lIjoiQ29ycCBpbmMuIiwidHlwZV9vZl9lbXBsb3ltZW50IjoiMDEifV0sIm5hdGlvbmFsaXR5IjpbIlNFIl0sInBlcnNvbiI6eyJfc2QiOlsiVGQ4cFFtOEpfV000SHhyTmVzOG9FankybzdqZVIxN2NhWEtsM2tFdzdLYyJdLCJkYXRlX29mX2JpcnRoIjoiMTk4MC0wMS0wMSIsImZhbWlseV9uYW1lIjoia2FybHNzb24iLCJvdGhlcl9lbGVtZW50cyI6eyJmYW1pbHlfbmFtZV9hdF9iaXJ0aCI6IiIsImZvcmVuYW1lX2F0X2JpcnRoIjoiIiwic2V4IjoiIn19LCJwbGFjZXNfb2Zfd29yayI6W3siY291bnRyeV93b3JrIjoiU0UiLCJub19maXhlZF9wbGFjZV9vZl93b3JrX2V4aXN0IjpmYWxzZSwicGxhY2Vfb2Zfd29yayI6W3siYWRkcmVzcyI6eyJwb3N0X2NvZGUiOiIxMjM1Iiwic3RyZWV0Ijoic3RyZWV0IiwidG93biI6InRvd24ifSwiY29tcGFueV92ZXNzZWxfbmFtZSI6IiIsImZsYWdfc3RhdGVfaG9tZV9iYXNlIjoiIiwiaWRzX29mX2NvbXBhbnkiOlt7ImNvbXBhbnlfaWQiOiIiLCJ0eXBlX29mX2lkIjoiIn1dfV19XSwic29jaWFsX3NlY3VyaXR5X3BpbiI6IjEyMzQiLCJzdGF0dXNfY29uZmlybWF0aW9uIjoiIiwidW5pcXVlX251bWJlcl9vZl9pc3N1ZWRfZG9jdW1lbnQiOiIifQ.alrFpahQwjgaCpDpsrjwkqr3hPrw-11HTGo7oC4-3GoEh2ehXGObhUPaKDCX3P1OXxSwf7BKRBYOlTQfz7jlBg~",
			want: want{
				header:              "eyJraWQiOiJkZWZhdWx0X3NpZ25pbmdfa2V5X2lkIiwidHlwIjoidmMrc2Qtand0In0",
				body:                "eyJjbmYiOnsiandrIjp7ImNydiI6IlAtMjU2IiwiZCI6Img4bGx6V0ZkNFNtc3dJVDZXbVNydmh4VzhzbTJzQ3d4TWZEYlhLVzlpZEUiLCJraWQiOiJkZWZhdWx0X3NpZ25pbmdfa2V5X2lkIiwia3R5IjoiRUMiLCJ4IjoienVzQmRGNlFtUkRNWmFoQlJNZDctNXItRjR5ZTl0VlMwUUhNVnNjWEk1cyIsInkiOiJXSzFEdjNXTl9fQmlVYVR0cGh1a2h2TzR6bXFmbGVpWFlfbTNJUnNISmJzIn19LCJjb21wZXRlbnRfaW5zdGl0dXRpb24iOnsiY291bnRyeV9jb2RlIjoiIiwiaW5zdGl0dXRpb25faWQiOiIiLCJpbnN0aXR1dGlvbl9uYW1lIjoiIn0sImRlY2lzaW9uX2xlZ2lzbGF0aW9uX2FwcGxpY2FibGUiOnsiZW5kaW5nX2RhdGUiOiIiLCJtZW1iZXJfc3RhdGVfd2hpY2hfbGVnaXNsYXRpb25fYXBwbGllcyI6IiIsInN0YXJ0aW5nX2RhdGUiOiIiLCJ0cmFuc2l0aW9uYWxfcnVsZV9hcHBseSI6ZmFsc2V9LCJkZXRhaWxzX29mX2VtcGxveW1lbnQiOlt7ImFkZHJlc3MiOnsiY291bnRyeSI6IlNFIiwicG9zdF9jb2RlIjoiMTIzNDUiLCJzdHJlZXQiOiJzdHJlZXQiLCJ0b3duIjoidG93biJ9LCJpZHNfb2ZfZW1wbG95ZXIiOlt7ImVtcGxveWVyX2lkIjoiMTIzIiwidHlwZV9vZl9pZCI6IjAxIn1dLCJuYW1lIjoiQ29ycCBpbmMuIiwidHlwZV9vZl9lbXBsb3ltZW50IjoiMDEifV0sIm5hdGlvbmFsaXR5IjpbIlNFIl0sInBlcnNvbiI6eyJfc2QiOlsiVGQ4cFFtOEpfV000SHhyTmVzOG9FankybzdqZVIxN2NhWEtsM2tFdzdLYyJdLCJkYXRlX29mX2JpcnRoIjoiMTk4MC0wMS0wMSIsImZhbWlseV9uYW1lIjoia2FybHNzb24iLCJvdGhlcl9lbGVtZW50cyI6eyJmYW1pbHlfbmFtZV9hdF9iaXJ0aCI6IiIsImZvcmVuYW1lX2F0X2JpcnRoIjoiIiwic2V4IjoiIn19LCJwbGFjZXNfb2Zfd29yayI6W3siY291bnRyeV93b3JrIjoiU0UiLCJub19maXhlZF9wbGFjZV9vZl93b3JrX2V4aXN0IjpmYWxzZSwicGxhY2Vfb2Zfd29yayI6W3siYWRkcmVzcyI6eyJwb3N0X2NvZGUiOiIxMjM1Iiwic3RyZWV0Ijoic3RyZWV0IiwidG93biI6InRvd24ifSwiY29tcGFueV92ZXNzZWxfbmFtZSI6IiIsImZsYWdfc3RhdGVfaG9tZV9iYXNlIjoiIiwiaWRzX29mX2NvbXBhbnkiOlt7ImNvbXBhbnlfaWQiOiIiLCJ0eXBlX29mX2lkIjoiIn1dfV19XSwic29jaWFsX3NlY3VyaXR5X3BpbiI6IjEyMzQiLCJzdGF0dXNfY29uZmlybWF0aW9uIjoiIiwidW5pcXVlX251bWJlcl9vZl9pc3N1ZWRfZG9jdW1lbnQiOiIifQ",
				signature:           "alrFpahQwjgaCpDpsrjwkqr3hPrw-11HTGo7oC4-3GoEh2ehXGObhUPaKDCX3P1OXxSwf7BKRBYOlTQfz7jlBg",
				selectiveDisclosure: []string{},
				err:                 nil,
			},
		},

		{
			name:  "with selective disclosure",
			token: "eyJraWQiOiJkZWZhdWx0X3NpZ25pbmdfa2V5X2lkIiwidHlwIjoidmMrc2Qtand0In0.eyJjbmYiOnsiandrIjp7ImNydiI6IlAtMjU2IiwiZCI6Img4bGx6V0ZkNFNtc3dJVDZXbVNydmh4VzhzbTJzQ3d4TWZEYlhLVzlpZEUiLCJraWQiOiJkZWZhdWx0X3NpZ25pbmdfa2V5X2lkIiwia3R5IjoiRUMiLCJ4IjoienVzQmRGNlFtUkRNWmFoQlJNZDctNXItRjR5ZTl0VlMwUUhNVnNjWEk1cyIsInkiOiJXSzFEdjNXTl9fQmlVYVR0cGh1a2h2TzR6bXFmbGVpWFlfbTNJUnNISmJzIn19LCJjb21wZXRlbnRfaW5zdGl0dXRpb24iOnsiY291bnRyeV9jb2RlIjoiIiwiaW5zdGl0dXRpb25faWQiOiIiLCJpbnN0aXR1dGlvbl9uYW1lIjoiIn0sImRlY2lzaW9uX2xlZ2lzbGF0aW9uX2FwcGxpY2FibGUiOnsiZW5kaW5nX2RhdGUiOiIiLCJtZW1iZXJfc3RhdGVfd2hpY2hfbGVnaXNsYXRpb25fYXBwbGllcyI6IiIsInN0YXJ0aW5nX2RhdGUiOiIiLCJ0cmFuc2l0aW9uYWxfcnVsZV9hcHBseSI6ZmFsc2V9LCJkZXRhaWxzX29mX2VtcGxveW1lbnQiOlt7ImFkZHJlc3MiOnsiY291bnRyeSI6IlNFIiwicG9zdF9jb2RlIjoiMTIzNDUiLCJzdHJlZXQiOiJzdHJlZXQiLCJ0b3duIjoidG93biJ9LCJpZHNfb2ZfZW1wbG95ZXIiOlt7ImVtcGxveWVyX2lkIjoiMTIzIiwidHlwZV9vZl9pZCI6IjAxIn1dLCJuYW1lIjoiQ29ycCBpbmMuIiwidHlwZV9vZl9lbXBsb3ltZW50IjoiMDEifV0sIm5hdGlvbmFsaXR5IjpbIlNFIl0sInBlcnNvbiI6eyJfc2QiOlsiVGQ4cFFtOEpfV000SHhyTmVzOG9FankybzdqZVIxN2NhWEtsM2tFdzdLYyJdLCJkYXRlX29mX2JpcnRoIjoiMTk4MC0wMS0wMSIsImZhbWlseV9uYW1lIjoia2FybHNzb24iLCJvdGhlcl9lbGVtZW50cyI6eyJmYW1pbHlfbmFtZV9hdF9iaXJ0aCI6IiIsImZvcmVuYW1lX2F0X2JpcnRoIjoiIiwic2V4IjoiIn19LCJwbGFjZXNfb2Zfd29yayI6W3siY291bnRyeV93b3JrIjoiU0UiLCJub19maXhlZF9wbGFjZV9vZl93b3JrX2V4aXN0IjpmYWxzZSwicGxhY2Vfb2Zfd29yayI6W3siYWRkcmVzcyI6eyJwb3N0X2NvZGUiOiIxMjM1Iiwic3RyZWV0Ijoic3RyZWV0IiwidG93biI6InRvd24ifSwiY29tcGFueV92ZXNzZWxfbmFtZSI6IiIsImZsYWdfc3RhdGVfaG9tZV9iYXNlIjoiIiwiaWRzX29mX2NvbXBhbnkiOlt7ImNvbXBhbnlfaWQiOiIiLCJ0eXBlX29mX2lkIjoiIn1dfV19XSwic29jaWFsX3NlY3VyaXR5X3BpbiI6IjEyMzQiLCJzdGF0dXNfY29uZmlybWF0aW9uIjoiIiwidW5pcXVlX251bWJlcl9vZl9pc3N1ZWRfZG9jdW1lbnQiOiIifQ.alrFpahQwjgaCpDpsrjwkqr3hPrw-11HTGo7oC4-3GoEh2ehXGObhUPaKDCX3P1OXxSwf7BKRBYOlTQfz7jlBg~WyJ6SXJpcHUwU1N6djlhVlFKT3Y0b3JBIiwiZGF0ZV9vZl9iaXJ0aCIsIjE5ODAtMDEtMDEiXQ~",
			want: want{
				header:              "eyJraWQiOiJkZWZhdWx0X3NpZ25pbmdfa2V5X2lkIiwidHlwIjoidmMrc2Qtand0In0",
				body:                "eyJjbmYiOnsiandrIjp7ImNydiI6IlAtMjU2IiwiZCI6Img4bGx6V0ZkNFNtc3dJVDZXbVNydmh4VzhzbTJzQ3d4TWZEYlhLVzlpZEUiLCJraWQiOiJkZWZhdWx0X3NpZ25pbmdfa2V5X2lkIiwia3R5IjoiRUMiLCJ4IjoienVzQmRGNlFtUkRNWmFoQlJNZDctNXItRjR5ZTl0VlMwUUhNVnNjWEk1cyIsInkiOiJXSzFEdjNXTl9fQmlVYVR0cGh1a2h2TzR6bXFmbGVpWFlfbTNJUnNISmJzIn19LCJjb21wZXRlbnRfaW5zdGl0dXRpb24iOnsiY291bnRyeV9jb2RlIjoiIiwiaW5zdGl0dXRpb25faWQiOiIiLCJpbnN0aXR1dGlvbl9uYW1lIjoiIn0sImRlY2lzaW9uX2xlZ2lzbGF0aW9uX2FwcGxpY2FibGUiOnsiZW5kaW5nX2RhdGUiOiIiLCJtZW1iZXJfc3RhdGVfd2hpY2hfbGVnaXNsYXRpb25fYXBwbGllcyI6IiIsInN0YXJ0aW5nX2RhdGUiOiIiLCJ0cmFuc2l0aW9uYWxfcnVsZV9hcHBseSI6ZmFsc2V9LCJkZXRhaWxzX29mX2VtcGxveW1lbnQiOlt7ImFkZHJlc3MiOnsiY291bnRyeSI6IlNFIiwicG9zdF9jb2RlIjoiMTIzNDUiLCJzdHJlZXQiOiJzdHJlZXQiLCJ0b3duIjoidG93biJ9LCJpZHNfb2ZfZW1wbG95ZXIiOlt7ImVtcGxveWVyX2lkIjoiMTIzIiwidHlwZV9vZl9pZCI6IjAxIn1dLCJuYW1lIjoiQ29ycCBpbmMuIiwidHlwZV9vZl9lbXBsb3ltZW50IjoiMDEifV0sIm5hdGlvbmFsaXR5IjpbIlNFIl0sInBlcnNvbiI6eyJfc2QiOlsiVGQ4cFFtOEpfV000SHhyTmVzOG9FankybzdqZVIxN2NhWEtsM2tFdzdLYyJdLCJkYXRlX29mX2JpcnRoIjoiMTk4MC0wMS0wMSIsImZhbWlseV9uYW1lIjoia2FybHNzb24iLCJvdGhlcl9lbGVtZW50cyI6eyJmYW1pbHlfbmFtZV9hdF9iaXJ0aCI6IiIsImZvcmVuYW1lX2F0X2JpcnRoIjoiIiwic2V4IjoiIn19LCJwbGFjZXNfb2Zfd29yayI6W3siY291bnRyeV93b3JrIjoiU0UiLCJub19maXhlZF9wbGFjZV9vZl93b3JrX2V4aXN0IjpmYWxzZSwicGxhY2Vfb2Zfd29yayI6W3siYWRkcmVzcyI6eyJwb3N0X2NvZGUiOiIxMjM1Iiwic3RyZWV0Ijoic3RyZWV0IiwidG93biI6InRvd24ifSwiY29tcGFueV92ZXNzZWxfbmFtZSI6IiIsImZsYWdfc3RhdGVfaG9tZV9iYXNlIjoiIiwiaWRzX29mX2NvbXBhbnkiOlt7ImNvbXBhbnlfaWQiOiIiLCJ0eXBlX29mX2lkIjoiIn1dfV19XSwic29jaWFsX3NlY3VyaXR5X3BpbiI6IjEyMzQiLCJzdGF0dXNfY29uZmlybWF0aW9uIjoiIiwidW5pcXVlX251bWJlcl9vZl9pc3N1ZWRfZG9jdW1lbnQiOiIifQ",
				signature:           "alrFpahQwjgaCpDpsrjwkqr3hPrw-11HTGo7oC4-3GoEh2ehXGObhUPaKDCX3P1OXxSwf7BKRBYOlTQfz7jlBg",
				selectiveDisclosure: []string{"WyJ6SXJpcHUwU1N6djlhVlFKT3Y0b3JBIiwiZGF0ZV9vZl9iaXJ0aCIsIjE5ODAtMDEtMDEiXQ"},
				err:                 nil,
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			header, body, signature, selectiveDisclosure, err := SplitToken(tt.token)

			if !assert.Equal(t, tt.want.err, err) {
				t.Log("errors do not match")
			}
			if !assert.Equal(t, tt.want.header, header) {
				t.Log("headers do not match")
			}
			if !assert.Equal(t, tt.want.body, body) {
				t.Log("bodies do not match")
			}
			if !assert.Equal(t, tt.want.signature, signature) {
				t.Log("signatures do not match")
			}
			if !assert.Equal(t, tt.want.selectiveDisclosure, selectiveDisclosure) {
				t.Log("selective disclosures do not match")
			}
		})
	}
}

func TestBase64Decode(t *testing.T) {
	type want struct {
		decoded string
		err     error
	}
	tts := []struct {
		name  string
		input string
		want  want
	}{
		{
			name:  "empty",
			input: "",
			want: want{
				decoded: "",
				err:     nil,
			},
		},
		{
			name:  "valid",
			input: "eyJraWQiOiJkZWZhdWx0X3NpZ25pbmdfa2V5X2lkIiwidHlwIjoidmMrc2Qtand0In0",
			want: want{
				decoded: `{"kid":"default_signing_key_id","typ":"vc+sd-jwt"}`,
				err:     nil,
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Base64Decode(tt.input)

			if !assert.Equal(t, tt.want.err, err) {
				t.Log("unexpected error")
			}
			if !assert.Equal(t, tt.want.decoded, got) {
				t.Log("decodings do not match")
			}
		})
	}
}

func TestMarshal(t *testing.T) {
	type want struct {
		m   map[string]any
		err error
	}
	tts := []struct {
		name  string
		input string
		want  want
	}{
		{
			name:  "empty",
			input: "",
			want: want{
				m:   nil,
				err: errors.New("empty input"),
			},
		},
		{
			name:  "valid",
			input: `{"kid":"default_signing_key_id","typ":"vc+sd-jwt"}`,
			want: want{
				m: map[string]any{
					"kid": "default_signing_key_id",
					"typ": "vc+sd-jwt",
				},
				err: nil,
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Unmarshal(tt.input)

			if !assert.Equal(t, tt.want.err, err) {
				t.Log("unexpected error")
			}
			if !assert.Equal(t, tt.want.m, got) {
				t.Log("marshals do not match")
			}
		})
	}
}

func TestSelectiveDisclosureUniq(t *testing.T) {
	tts := []struct {
		name  string
		input []string
		want  bool
	}{
		{
			name:  "empty",
			input: []string{},
			want:  true,
		},
		{
			name:  "valid",
			input: []string{"a", "b", "c"},
			want:  true,
		},
		{
			name:  "invalid",
			input: []string{"a", "b", "a"},
			want:  false,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got := selectiveDisclosureUniq(tt.input)

			assert.Equal(t, tt.want, got)
		})
	}
}
