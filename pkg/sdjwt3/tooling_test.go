package sdjwt3

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"gotest.tools/v3/golden"
)

var (
	mockBody = "eyJjbmYiOnsiandrIjp7ImNydiI6IlAtMjU2IiwiZCI6Img4bGx6V0ZkNFNtc3dJVDZXbVNydmh4VzhzbTJzQ3d4TWZEYlhLVzlpZEUiLCJraWQiOiJkZWZhdWx0X3NpZ25pbmdfa2V5X2lkIiwia3R5IjoiRUMiLCJ4IjoienVzQmRGNlFtUkRNWmFoQlJNZDctNXItRjR5ZTl0VlMwUUhNVnNjWEk1cyIsInkiOiJXSzFEdjNXTl9fQmlVYVR0cGh1a2h2TzR6bXFmbGVpWFlfbTNJUnNISmJzIn19LCJjb21wZXRlbnRfaW5zdGl0dXRpb24iOnsiY291bnRyeV9jb2RlIjoiIiwiaW5zdGl0dXRpb25faWQiOiIiLCJpbnN0aXR1dGlvbl9uYW1lIjoiIn0sImRlY2lzaW9uX2xlZ2lzbGF0aW9uX2FwcGxpY2FibGUiOnsiZW5kaW5nX2RhdGUiOiIiLCJtZW1iZXJfc3RhdGVfd2hpY2hfbGVnaXNsYXRpb25fYXBwbGllcyI6IiIsInN0YXJ0aW5nX2RhdGUiOiIiLCJ0cmFuc2l0aW9uYWxfcnVsZV9hcHBseSI6ZmFsc2V9LCJkZXRhaWxzX29mX2VtcGxveW1lbnQiOlt7ImFkZHJlc3MiOnsiY291bnRyeSI6IlNFIiwicG9zdF9jb2RlIjoiMTIzNDUiLCJzdHJlZXQiOiJzdHJlZXQiLCJ0b3duIjoidG93biJ9LCJpZHNfb2ZfZW1wbG95ZXIiOlt7ImVtcGxveWVyX2lkIjoiMTIzIiwidHlwZV9vZl9pZCI6IjAxIn1dLCJuYW1lIjoiQ29ycCBpbmMuIiwidHlwZV9vZl9lbXBsb3ltZW50IjoiMDEifV0sIm5hdGlvbmFsaXR5IjpbIlNFIl0sInBlcnNvbiI6eyJfc2QiOlsiVGQ4cFFtOEpfV000SHhyTmVzOG9FankybzdqZVIxN2NhWEtsM2tFdzdLYyJdLCJkYXRlX29mX2JpcnRoIjoiMTk4MC0wMS0wMSIsImZhbWlseV9uYW1lIjoia2FybHNzb24iLCJvdGhlcl9lbGVtZW50cyI6eyJmYW1pbHlfbmFtZV9hdF9iaXJ0aCI6IiIsImZvcmVuYW1lX2F0X2JpcnRoIjoiIiwic2V4IjoiIn19LCJwbGFjZXNfb2Zfd29yayI6W3siY291bnRyeV93b3JrIjoiU0UiLCJub19maXhlZF9wbGFjZV9vZl93b3JrX2V4aXN0IjpmYWxzZSwicGxhY2Vfb2Zfd29yayI6W3siYWRkcmVzcyI6eyJwb3N0X2NvZGUiOiIxMjM1Iiwic3RyZWV0Ijoic3RyZWV0IiwidG93biI6InRvd24ifSwiY29tcGFueV92ZXNzZWxfbmFtZSI6IiIsImZsYWdfc3RhdGVfaG9tZV9iYXNlIjoiIiwiaWRzX29mX2NvbXBhbnkiOlt7ImNvbXBhbnlfaWQiOiIiLCJ0eXBlX29mX2lkIjoiIn1dfV19XSwic29jaWFsX3NlY3VyaXR5X3BpbiI6IjEyMzQiLCJzdGF0dXNfY29uZmlybWF0aW9uIjoiIiwidW5pcXVlX251bWJlcl9vZl9pc3N1ZWRfZG9jdW1lbnQiOiIifQ"

	// #nosec G101
	mockToken               = "eyJraWQiOiJkZWZhdWx0X3NpZ25pbmdfa2V5X2lkIiwidHlwIjoidmMrc2Qtand0In0.eyJjbmYiOnsiandrIjp7ImNydiI6IlAtMjU2IiwiZCI6Img4bGx6V0ZkNFNtc3dJVDZXbVNydmh4VzhzbTJzQ3d4TWZEYlhLVzlpZEUiLCJraWQiOiJkZWZhdWx0X3NpZ25pbmdfa2V5X2lkIiwia3R5IjoiRUMiLCJ4IjoienVzQmRGNlFtUkRNWmFoQlJNZDctNXItRjR5ZTl0VlMwUUhNVnNjWEk1cyIsInkiOiJXSzFEdjNXTl9fQmlVYVR0cGh1a2h2TzR6bXFmbGVpWFlfbTNJUnNISmJzIn19LCJjb21wZXRlbnRfaW5zdGl0dXRpb24iOnsiY291bnRyeV9jb2RlIjoiIiwiaW5zdGl0dXRpb25faWQiOiIiLCJpbnN0aXR1dGlvbl9uYW1lIjoiIn0sImRlY2lzaW9uX2xlZ2lzbGF0aW9uX2FwcGxpY2FibGUiOnsiZW5kaW5nX2RhdGUiOiIiLCJtZW1iZXJfc3RhdGVfd2hpY2hfbGVnaXNsYXRpb25fYXBwbGllcyI6IiIsInN0YXJ0aW5nX2RhdGUiOiIiLCJ0cmFuc2l0aW9uYWxfcnVsZV9hcHBseSI6ZmFsc2V9LCJkZXRhaWxzX29mX2VtcGxveW1lbnQiOlt7ImFkZHJlc3MiOnsiY291bnRyeSI6IlNFIiwicG9zdF9jb2RlIjoiMTIzNDUiLCJzdHJlZXQiOiJzdHJlZXQiLCJ0b3duIjoidG93biJ9LCJpZHNfb2ZfZW1wbG95ZXIiOlt7ImVtcGxveWVyX2lkIjoiMTIzIiwidHlwZV9vZl9pZCI6IjAxIn1dLCJuYW1lIjoiQ29ycCBpbmMuIiwidHlwZV9vZl9lbXBsb3ltZW50IjoiMDEifV0sIm5hdGlvbmFsaXR5IjpbIlNFIl0sInBlcnNvbiI6eyJfc2QiOlsiVGQ4cFFtOEpfV000SHhyTmVzOG9FankybzdqZVIxN2NhWEtsM2tFdzdLYyJdLCJkYXRlX29mX2JpcnRoIjoiMTk4MC0wMS0wMSIsImZhbWlseV9uYW1lIjoia2FybHNzb24iLCJvdGhlcl9lbGVtZW50cyI6eyJmYW1pbHlfbmFtZV9hdF9iaXJ0aCI6IiIsImZvcmVuYW1lX2F0X2JpcnRoIjoiIiwic2V4IjoiIn19LCJwbGFjZXNfb2Zfd29yayI6W3siY291bnRyeV93b3JrIjoiU0UiLCJub19maXhlZF9wbGFjZV9vZl93b3JrX2V4aXN0IjpmYWxzZSwicGxhY2Vfb2Zfd29yayI6W3siYWRkcmVzcyI6eyJwb3N0X2NvZGUiOiIxMjM1Iiwic3RyZWV0Ijoic3RyZWV0IiwidG93biI6InRvd24ifSwiY29tcGFueV92ZXNzZWxfbmFtZSI6IiIsImZsYWdfc3RhdGVfaG9tZV9iYXNlIjoiIiwiaWRzX29mX2NvbXBhbnkiOlt7ImNvbXBhbnlfaWQiOiIiLCJ0eXBlX29mX2lkIjoiIn1dfV19XSwic29jaWFsX3NlY3VyaXR5X3BpbiI6IjEyMzQiLCJzdGF0dXNfY29uZmlybWF0aW9uIjoiIiwidW5pcXVlX251bWJlcl9vZl9pc3N1ZWRfZG9jdW1lbnQiOiIifQ.alrFpahQwjgaCpDpsrjwkqr3hPrw-11HTGo7oC4-3GoEh2ehXGObhUPaKDCX3P1OXxSwf7BKRBYOlTQfz7jlBg~"
	mockSelectiveDisclosure = "WyJ6SXJpcHUwU1N6djlhVlFKT3Y0b3JBIiwiZGF0ZV9vZl9iaXJ0aCIsIjE5ODAtMDEtMDEiXQ"
	mockKB                  = "eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJub25jZSI6Img5eVdScldFaGFrU3dvdkNORVJhYzktaWFFYmcySFpuS1NkX2tIYjFaVFk9IiwiYXVkIjoiMTAwMyIsInNkX2hhc2giOiJmUUVDeVhNemVDeHlWS2gxRDRQOVhIZzVnYTZpVENwaXhZT19IM2FZeDdjIiwiaWF0IjxNzUxNDQzMTY1fQ.FdefGwmNKxGSlOcAn-U1hBmr-NS90qq10Z7klmfJEQq3YSkC-iK7fiIE-Rp5u9fJWOE3BLX4Uav1ZmmhlWxCww"
)

var (
	mockTokenWithselectiveDisclosure       = mockToken + mockSelectiveDisclosure + "~"
	mockTokenWithselectiveDisclosureWithKB = mockTokenWithselectiveDisclosure + mockKB
)

func TestSplitToken(t *testing.T) {
	type want struct {
		header, body, signature string
		selectiveDisclosure     []string
		keybinding              []string
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
				keybinding:          nil,
				selectiveDisclosure: nil,
				err:                 errors.New("empty token"),
			},
		},
		{
			name:  "without selective disclosure",
			token: mockToken,
			want: want{
				header:              "eyJraWQiOiJkZWZhdWx0X3NpZ25pbmdfa2V5X2lkIiwidHlwIjoidmMrc2Qtand0In0",
				body:                "eyJjbmYiOnsiandrIjp7ImNydiI6IlAtMjU2IiwiZCI6Img4bGx6V0ZkNFNtc3dJVDZXbVNydmh4VzhzbTJzQ3d4TWZEYlhLVzlpZEUiLCJraWQiOiJkZWZhdWx0X3NpZ25pbmdfa2V5X2lkIiwia3R5IjoiRUMiLCJ4IjoienVzQmRGNlFtUkRNWmFoQlJNZDctNXItRjR5ZTl0VlMwUUhNVnNjWEk1cyIsInkiOiJXSzFEdjNXTl9fQmlVYVR0cGh1a2h2TzR6bXFmbGVpWFlfbTNJUnNISmJzIn19LCJjb21wZXRlbnRfaW5zdGl0dXRpb24iOnsiY291bnRyeV9jb2RlIjoiIiwiaW5zdGl0dXRpb25faWQiOiIiLCJpbnN0aXR1dGlvbl9uYW1lIjoiIn0sImRlY2lzaW9uX2xlZ2lzbGF0aW9uX2FwcGxpY2FibGUiOnsiZW5kaW5nX2RhdGUiOiIiLCJtZW1iZXJfc3RhdGVfd2hpY2hfbGVnaXNsYXRpb25fYXBwbGllcyI6IiIsInN0YXJ0aW5nX2RhdGUiOiIiLCJ0cmFuc2l0aW9uYWxfcnVsZV9hcHBseSI6ZmFsc2V9LCJkZXRhaWxzX29mX2VtcGxveW1lbnQiOlt7ImFkZHJlc3MiOnsiY291bnRyeSI6IlNFIiwicG9zdF9jb2RlIjoiMTIzNDUiLCJzdHJlZXQiOiJzdHJlZXQiLCJ0b3duIjoidG93biJ9LCJpZHNfb2ZfZW1wbG95ZXIiOlt7ImVtcGxveWVyX2lkIjoiMTIzIiwidHlwZV9vZl9pZCI6IjAxIn1dLCJuYW1lIjoiQ29ycCBpbmMuIiwidHlwZV9vZl9lbXBsb3ltZW50IjoiMDEifV0sIm5hdGlvbmFsaXR5IjpbIlNFIl0sInBlcnNvbiI6eyJfc2QiOlsiVGQ4cFFtOEpfV000SHhyTmVzOG9FankybzdqZVIxN2NhWEtsM2tFdzdLYyJdLCJkYXRlX29mX2JpcnRoIjoiMTk4MC0wMS0wMSIsImZhbWlseV9uYW1lIjoia2FybHNzb24iLCJvdGhlcl9lbGVtZW50cyI6eyJmYW1pbHlfbmFtZV9hdF9iaXJ0aCI6IiIsImZvcmVuYW1lX2F0X2JpcnRoIjoiIiwic2V4IjoiIn19LCJwbGFjZXNfb2Zfd29yayI6W3siY291bnRyeV93b3JrIjoiU0UiLCJub19maXhlZF9wbGFjZV9vZl93b3JrX2V4aXN0IjpmYWxzZSwicGxhY2Vfb2Zfd29yayI6W3siYWRkcmVzcyI6eyJwb3N0X2NvZGUiOiIxMjM1Iiwic3RyZWV0Ijoic3RyZWV0IiwidG93biI6InRvd24ifSwiY29tcGFueV92ZXNzZWxfbmFtZSI6IiIsImZsYWdfc3RhdGVfaG9tZV9iYXNlIjoiIiwiaWRzX29mX2NvbXBhbnkiOlt7ImNvbXBhbnlfaWQiOiIiLCJ0eXBlX29mX2lkIjoiIn1dfV19XSwic29jaWFsX3NlY3VyaXR5X3BpbiI6IjEyMzQiLCJzdGF0dXNfY29uZmlybWF0aW9uIjoiIiwidW5pcXVlX251bWJlcl9vZl9pc3N1ZWRfZG9jdW1lbnQiOiIifQ",
				signature:           "alrFpahQwjgaCpDpsrjwkqr3hPrw-11HTGo7oC4-3GoEh2ehXGObhUPaKDCX3P1OXxSwf7BKRBYOlTQfz7jlBg",
				selectiveDisclosure: []string{},
				keybinding:          nil,
				err:                 nil,
			},
		},

		{
			name:  "with selective disclosure",
			token: mockTokenWithselectiveDisclosure,
			want: want{
				header:              "eyJraWQiOiJkZWZhdWx0X3NpZ25pbmdfa2V5X2lkIiwidHlwIjoidmMrc2Qtand0In0",
				body:                "eyJjbmYiOnsiandrIjp7ImNydiI6IlAtMjU2IiwiZCI6Img4bGx6V0ZkNFNtc3dJVDZXbVNydmh4VzhzbTJzQ3d4TWZEYlhLVzlpZEUiLCJraWQiOiJkZWZhdWx0X3NpZ25pbmdfa2V5X2lkIiwia3R5IjoiRUMiLCJ4IjoienVzQmRGNlFtUkRNWmFoQlJNZDctNXItRjR5ZTl0VlMwUUhNVnNjWEk1cyIsInkiOiJXSzFEdjNXTl9fQmlVYVR0cGh1a2h2TzR6bXFmbGVpWFlfbTNJUnNISmJzIn19LCJjb21wZXRlbnRfaW5zdGl0dXRpb24iOnsiY291bnRyeV9jb2RlIjoiIiwiaW5zdGl0dXRpb25faWQiOiIiLCJpbnN0aXR1dGlvbl9uYW1lIjoiIn0sImRlY2lzaW9uX2xlZ2lzbGF0aW9uX2FwcGxpY2FibGUiOnsiZW5kaW5nX2RhdGUiOiIiLCJtZW1iZXJfc3RhdGVfd2hpY2hfbGVnaXNsYXRpb25fYXBwbGllcyI6IiIsInN0YXJ0aW5nX2RhdGUiOiIiLCJ0cmFuc2l0aW9uYWxfcnVsZV9hcHBseSI6ZmFsc2V9LCJkZXRhaWxzX29mX2VtcGxveW1lbnQiOlt7ImFkZHJlc3MiOnsiY291bnRyeSI6IlNFIiwicG9zdF9jb2RlIjoiMTIzNDUiLCJzdHJlZXQiOiJzdHJlZXQiLCJ0b3duIjoidG93biJ9LCJpZHNfb2ZfZW1wbG95ZXIiOlt7ImVtcGxveWVyX2lkIjoiMTIzIiwidHlwZV9vZl9pZCI6IjAxIn1dLCJuYW1lIjoiQ29ycCBpbmMuIiwidHlwZV9vZl9lbXBsb3ltZW50IjoiMDEifV0sIm5hdGlvbmFsaXR5IjpbIlNFIl0sInBlcnNvbiI6eyJfc2QiOlsiVGQ4cFFtOEpfV000SHhyTmVzOG9FankybzdqZVIxN2NhWEtsM2tFdzdLYyJdLCJkYXRlX29mX2JpcnRoIjoiMTk4MC0wMS0wMSIsImZhbWlseV9uYW1lIjoia2FybHNzb24iLCJvdGhlcl9lbGVtZW50cyI6eyJmYW1pbHlfbmFtZV9hdF9iaXJ0aCI6IiIsImZvcmVuYW1lX2F0X2JpcnRoIjoiIiwic2V4IjoiIn19LCJwbGFjZXNfb2Zfd29yayI6W3siY291bnRyeV93b3JrIjoiU0UiLCJub19maXhlZF9wbGFjZV9vZl93b3JrX2V4aXN0IjpmYWxzZSwicGxhY2Vfb2Zfd29yayI6W3siYWRkcmVzcyI6eyJwb3N0X2NvZGUiOiIxMjM1Iiwic3RyZWV0Ijoic3RyZWV0IiwidG93biI6InRvd24ifSwiY29tcGFueV92ZXNzZWxfbmFtZSI6IiIsImZsYWdfc3RhdGVfaG9tZV9iYXNlIjoiIiwiaWRzX29mX2NvbXBhbnkiOlt7ImNvbXBhbnlfaWQiOiIiLCJ0eXBlX29mX2lkIjoiIn1dfV19XSwic29jaWFsX3NlY3VyaXR5X3BpbiI6IjEyMzQiLCJzdGF0dXNfY29uZmlybWF0aW9uIjoiIiwidW5pcXVlX251bWJlcl9vZl9pc3N1ZWRfZG9jdW1lbnQiOiIifQ",
				signature:           "alrFpahQwjgaCpDpsrjwkqr3hPrw-11HTGo7oC4-3GoEh2ehXGObhUPaKDCX3P1OXxSwf7BKRBYOlTQfz7jlBg",
				selectiveDisclosure: []string{mockSelectiveDisclosure},
				keybinding:          nil,
				err:                 nil,
			},
		},
		{
			name:  "with selective disclosure with keybinding",
			token: mockTokenWithselectiveDisclosureWithKB,
			want: want{
				header:              "eyJraWQiOiJkZWZhdWx0X3NpZ25pbmdfa2V5X2lkIiwidHlwIjoidmMrc2Qtand0In0",
				body:                "eyJjbmYiOnsiandrIjp7ImNydiI6IlAtMjU2IiwiZCI6Img4bGx6V0ZkNFNtc3dJVDZXbVNydmh4VzhzbTJzQ3d4TWZEYlhLVzlpZEUiLCJraWQiOiJkZWZhdWx0X3NpZ25pbmdfa2V5X2lkIiwia3R5IjoiRUMiLCJ4IjoienVzQmRGNlFtUkRNWmFoQlJNZDctNXItRjR5ZTl0VlMwUUhNVnNjWEk1cyIsInkiOiJXSzFEdjNXTl9fQmlVYVR0cGh1a2h2TzR6bXFmbGVpWFlfbTNJUnNISmJzIn19LCJjb21wZXRlbnRfaW5zdGl0dXRpb24iOnsiY291bnRyeV9jb2RlIjoiIiwiaW5zdGl0dXRpb25faWQiOiIiLCJpbnN0aXR1dGlvbl9uYW1lIjoiIn0sImRlY2lzaW9uX2xlZ2lzbGF0aW9uX2FwcGxpY2FibGUiOnsiZW5kaW5nX2RhdGUiOiIiLCJtZW1iZXJfc3RhdGVfd2hpY2hfbGVnaXNsYXRpb25fYXBwbGllcyI6IiIsInN0YXJ0aW5nX2RhdGUiOiIiLCJ0cmFuc2l0aW9uYWxfcnVsZV9hcHBseSI6ZmFsc2V9LCJkZXRhaWxzX29mX2VtcGxveW1lbnQiOlt7ImFkZHJlc3MiOnsiY291bnRyeSI6IlNFIiwicG9zdF9jb2RlIjoiMTIzNDUiLCJzdHJlZXQiOiJzdHJlZXQiLCJ0b3duIjoidG93biJ9LCJpZHNfb2ZfZW1wbG95ZXIiOlt7ImVtcGxveWVyX2lkIjoiMTIzIiwidHlwZV9vZl9pZCI6IjAxIn1dLCJuYW1lIjoiQ29ycCBpbmMuIiwidHlwZV9vZl9lbXBsb3ltZW50IjoiMDEifV0sIm5hdGlvbmFsaXR5IjpbIlNFIl0sInBlcnNvbiI6eyJfc2QiOlsiVGQ4cFFtOEpfV000SHhyTmVzOG9FankybzdqZVIxN2NhWEtsM2tFdzdLYyJdLCJkYXRlX29mX2JpcnRoIjoiMTk4MC0wMS0wMSIsImZhbWlseV9uYW1lIjoia2FybHNzb24iLCJvdGhlcl9lbGVtZW50cyI6eyJmYW1pbHlfbmFtZV9hdF9iaXJ0aCI6IiIsImZvcmVuYW1lX2F0X2JpcnRoIjoiIiwic2V4IjoiIn19LCJwbGFjZXNfb2Zfd29yayI6W3siY291bnRyeV93b3JrIjoiU0UiLCJub19maXhlZF9wbGFjZV9vZl93b3JrX2V4aXN0IjpmYWxzZSwicGxhY2Vfb2Zfd29yayI6W3siYWRkcmVzcyI6eyJwb3N0X2NvZGUiOiIxMjM1Iiwic3RyZWV0Ijoic3RyZWV0IiwidG93biI6InRvd24ifSwiY29tcGFueV92ZXNzZWxfbmFtZSI6IiIsImZsYWdfc3RhdGVfaG9tZV9iYXNlIjoiIiwiaWRzX29mX2NvbXBhbnkiOlt7ImNvbXBhbnlfaWQiOiIiLCJ0eXBlX29mX2lkIjoiIn1dfV19XSwic29jaWFsX3NlY3VyaXR5X3BpbiI6IjEyMzQiLCJzdGF0dXNfY29uZmlybWF0aW9uIjoiIiwidW5pcXVlX251bWJlcl9vZl9pc3N1ZWRfZG9jdW1lbnQiOiIifQ",
				signature:           "alrFpahQwjgaCpDpsrjwkqr3hPrw-11HTGo7oC4-3GoEh2ehXGObhUPaKDCX3P1OXxSwf7BKRBYOlTQfz7jlBg",
				selectiveDisclosure: []string{mockSelectiveDisclosure},
				keybinding: []string{
					"eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9",
					"eyJub25jZSI6Img5eVdScldFaGFrU3dvdkNORVJhYzktaWFFYmcySFpuS1NkX2tIYjFaVFk9IiwiYXVkIjoiMTAwMyIsInNkX2hhc2giOiJmUUVDeVhNemVDeHlWS2gxRDRQOVhIZzVnYTZpVENwaXhZT19IM2FZeDdjIiwiaWF0IjxNzUxNDQzMTY1fQ",
					"FdefGwmNKxGSlOcAn-U1hBmr-NS90qq10Z7klmfJEQq3YSkC-iK7fiIE-Rp5u9fJWOE3BLX4Uav1ZmmhlWxCww",
				},
				err: nil,
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			header, body, signature, selectiveDisclosure, keyBinding, err := SplitToken(tt.token)

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
			if !assert.Equal(t, tt.want.keybinding, keyBinding) {
				t.Log("keybindings do not match")
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

func TestConstruct(t *testing.T) {
	tts := []struct {
		name  string
		token string
		sd    []string
		want  map[string]any
	}{
		{
			name:  "empty",
			token: mockBody,
			want: map[string]any{
				"_sd": []any{
					"8-6ocBCm_wKShqKH1K-tNZ7uatfhuZ_m-4lbctNm8Es",
					"HL2rCebrsfu8zceQaVsPjNGG4sDqPKWWQs_b3wJAy4k",
					"gVI455Eu7veIUMAeBQjBv3JbJxyF-P89gdnmDkhaR-s",
					"s8TDppzc9jiSm6-z_VAERB4K6r3hjMlYx7lRrdhG90w",
					"y2IBSojcg7acn-_PPJDJ8oODFyH93FlKg4Rk_kTltNs",
					"uNA0RiRM50aR3YpE1Gx550UllnecRbFnIKUPpr-8mEE",
					"f4R11Ho330Ya8Yk-DRCGvrAGENM5jFe9QnP4jNG6iJg",
					"WPmZWG4vg_DrSb3mz-UNuX-Wcia1vcGBxKsDZfokq5M",
					"FoemAME-2zylWaTeGOPJejtW2FePZalWzlfzYyAyII0",
					"zEJ0QwYumAHM4CJgV3fXa2xx63SCFkWDK9ZNLgWUUQI",
					"MaiSPQY_LScquBC4m1pQ8ss86CqqoB6gBQ2o9IWmYwg",
					"FKXtHQ8ecZMVq4WUuCH-SDdvSOpa6Xx-GU1yi9MilHw",
					"mOGUpoT8eH6yeh-jahP4FjxbgzqNgVTN6kswatFzTdQ",
					"CoJ_JfBF1v-L2fTkLJG7yKoMPsGMWthhriil41NVicg",
					"tIBcL8MPk8Mx5Ukkgs6QhbML2N0Wg8I5v5MS7UwECe0",
					"HgYkmvhmto_DbzASKphqhaM-_OZatAEpzDc7HQSzc2Q",
					"B-ygWJ4qAVdhbrFVdb_uZB1dH4o5QVcOSKCiZi87rcE",
					"PjFstdGhywb1ZmoJY92vYhwV7cvuevgWvUjNRna8bkY",
					"vQ8mDmcIhijcaHPDIoSS7X5e9HdppX6qYnPdQ94xD7E",
					"LdidnJg4lV7jrdl6-izq1WzetQHHz3r6As11FcYH1lk",
					"dFKROOcSRjK3f-nroZrjohkJA_p8vkOM0u8dhV5A8Xk",
					"BVxHFhKfWYwX16xtHIRu1y_uKfN5cLXR4HIQUyo82LU",
					"YOvphs3yIgKlh-JLzo1DxiNZd-LMvV4dUO0tdyXOPZs",
					"bln6qDUPAEhY4RFhEvuoJIOnPHHIui-JgCU3I5Db93c",
					"49AxzE-RmPPJNrtO0S9yq7eUAcdpcM3Tiok6a6agmrY",
					"zYI_3v0rguQ8UfG0edJ2exxpdZqzx1agk74I7e_0PWA",
				},
				"_sd_alg":                    "sha-256",
				"authentic_source_person_id": "authentic_source_person_id_102",
				"cnf": map[string]any{
					"jwk": map[string]any{
						"crv":     "P-256",
						"ext":     true,
						"key_ops": []any{"verify"},
						"kty":     "EC",
						"x":       "bGvPcUX4XTSKWy-U6qPVNU52iSOj6ngjjJx6HShwFsM",
						"y":       "pYUxXgTHcE3vAghOnufSYTOjPYSFJDUkusgW8D2lH2Q",
					},
				},
				"exp":               1.782910597e+09,
				"expiry_date":       "2033-01-01",
				"iss":               "https://vc-interop-3.sunet.se",
				"issuing_authority": "SUNET",
				"issuing_country":   "SE",
				"given_name":        "Gary",
				"family_name":       "Oldman",
				"nbf":               1.751374597e+09,
				"schema": map[string]any{
					"name": "DefaultSchema",
				},
				"vct": "urn:eudi:pid:1",
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			have := golden.Get(t, "vp_token_2.golden")
			got, err := Construct(string(have))
			assert.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}
