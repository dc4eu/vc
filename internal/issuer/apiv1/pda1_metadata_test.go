package apiv1

import (
	"context"
	"testing"
	"vc/pkg/logger"

	"github.com/stretchr/testify/assert"
)

func TestPDA1Metadata(t *testing.T) {
	tts := []struct {
		name string
		want []string
	}{
		{
			name: "OK",
			want: []string{
				"eyJ2Y3QiOiJodHRwczovL3Rlc3QtaXNzdWVyLnN1bmV0LnNlIiwibmFtZSI6IlBEQTEiLCJkZXNjcmlwdGlvbiI6IlRoaXMgaXMgYSBQREExIGRvY3VtZW50IGlzc3VlZCBieSB0aGUgd2VsbCBrbm93biBQREExIElzc3VlciIsImRpc3BsYXkiOlt7ImxhbmciOiJlbi1VUyIsIm5hbWUiOiJQREExIiwicmVuZGVyaW5nIjp7InNpbXBsZSI6eyJsb2dvIjp7InVyaSI6Imh0dHBzOi8vdGVzdC1pc3N1ZXIuc3VuZXQuc2UvcGRhMS5wbmciLCJ1cmkjaW50ZWdyaXR5Ijoic2hhMjU2LTk0NDQ1YjJjYTcyZTkxNTUyNjBjOGI0ODc5MTEyZGY3Njc3ZThiM2RmM2RjZWU5Yjk3MGI0MDUzNGUyNmQ0YWIiLCJhbHRfdGV4dCI6IlBEQTEgQ2FyZCJ9LCJiYWNrZ3JvdW5kX2NvbG9yIjoiIzhlYmVlYiIsInRleHRfY29sb3IiOiIjZmZmZmZmIn0sInN2Z190ZW1wbGF0ZXMiOlt7InVyaSI6Imh0dHBzOi8vdGVzdC1pc3N1ZXIuc3VuZXQuc2UvcGRhMVRlbXBsYXRlLnN2ZyIsInVyaSNpbnRlZ3JpdHkiOiIiLCJwcm9wZXJ0aWVzIjp7Im9yaWVudGF0aW9uIjoiIiwiY29sb3Jfc2NoZW1lIjoiIiwiY29udHJhc3QiOiIifX1dfX1dLCJjbGFpbXMiOlt7InBhdGgiOlsic29jaWFsX3NlY3VyaXR5X3BpbiJdLCJkaXNwbGF5IjpbeyJsYW5nIjoiZW4tVVMiLCJsYWJlbCI6IlNvY2lhbCBTZWN1cml0eSBOdW1iZXIiLCJkZXNjcmlwdGlvbiI6IlRoZSBzb2NpYWwgc2VjdXJpdHkgbnVtYmVyIG9mIHRoZSBQREExIGhvbGRlciJ9XSwic2QiOiIiLCJzdmdfaWQiOiJzb2NpYWxfc2VjdXJpdHlfcGluIn0seyJwYXRoIjpbImRlY2lzaW9uX2xlZ2lzbGF0aW9uX2FwcGxpY2FibGUiLCJlbmRpbmdfZGF0ZSJdLCJkaXNwbGF5IjpbeyJsYW5nIjoiZW4tVVMiLCJsYWJlbCI6IkV4cGlyeSBEYXRlIiwiZGVzY3JpcHRpb24iOiJUaGUgZGF0ZSBhbmQgdGltZSBleHBpcmVkIHRoaXMgY3JlZGVudGlhbCJ9XSwic2QiOiIiLCJzdmdfaWQiOiJleHBpcnlfZGF0ZSJ9XSwic2NoZW1hX3VybCI6IiIsInNjaGVtYV91cmwjaW50ZWdyaXR5IjoiIiwiZXh0ZW5kcyI6IiIsImV4dGVuZHMjaW50ZWdyaXR5IjoiIn0=",
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			client := mockNewClient(ctx, t, "ecdsa", logger.NewSimple("test"))

			got, err := client.pda1Client.MetadataClaim("https://test-issuer.sunet.se")
			assert.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}
