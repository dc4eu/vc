package apiv1

import (
	"context"
	"testing"
	"vc/pkg/logger"

	"github.com/stretchr/testify/assert"
)

func TestEhicMetadata(t *testing.T) {
	tts := []struct {
		name string
		want []string
	}{
		{
			name: "OK",
			want: []string{
				"eyJ2Y3QiOiJodHRwczovL3Rlc3QtaXNzdWVyLnN1bmV0LnNlIiwibmFtZSI6IkVISUMiLCJkZXNjcmlwdGlvbiI6IlRoaXMgaXMgYW4gRUhJQyBkb2N1bWVudCBpc3N1ZWQgYnkgdGhlIHdlbGwga25vd24gRUhJQyBJc3N1ZXIiLCJkaXNwbGF5IjpbeyJsYW5nIjoiZW4tVVMiLCJuYW1lIjoiRUhJQyIsInJlbmRlcmluZyI6eyJzaW1wbGUiOnsibG9nbyI6eyJ1cmkiOiJodHRwczovL3Rlc3QtaXNzdWVyLnN1bmV0LnNlL2VoaWNDYXJkLnBuZyIsInVyaSNpbnRlZ3JpdHkiOiJzaGEyNTYtOTQ0NDViMmNhNzJlOTE1NTI2MGM4YjQ4NzkxMTJkZjc2NzdlOGIzZGYzZGNlZTliOTcwYjQwNTM0ZTI2ZDRhYiIsImFsdF90ZXh0IjoiRUhJQyBDYXJkIn0sImJhY2tncm91bmRfY29sb3IiOiIjMTIxMDdjIiwidGV4dF9jb2xvciI6IiNGRkZGRkYifSwic3ZnX3RlbXBsYXRlcyI6W3sidXJpIjoiaHR0cHM6Ly90ZXN0LWlzc3Vlci5zdW5ldC5zZS9laGljVGVtcGxhdGUucG5nIiwidXJpI2ludGVncml0eSI6IiIsInByb3BlcnRpZXMiOnsib3JpZW50YXRpb24iOiIiLCJjb2xvcl9zY2hlbWUiOiIiLCJjb250cmFzdCI6IiJ9fV19fV0sImNsYWltcyI6W3sicGF0aCI6WyJzb2NpYWxfc2VjdXJpdHlfcGluIl0sImRpc3BsYXkiOlt7ImxhbmciOiJlbi1VUyIsImxhYmVsIjoiU29jaWFsIFNlY3VyaXR5IE51bWJlciIsImRlc2NyaXB0aW9uIjoiVGhlIHNvY2lhbCBzZWN1cml0eSBudW1iZXIgb2YgdGhlIEVISUMgaG9sZGVyIn1dLCJzZCI6IiIsInN2Z19pZCI6InNvY2lhbF9zZWN1cml0eV9waW4ifSx7InBhdGgiOlsiY29tcGV0ZW50X2luc3RpdHV0aW9uIiwiaW5zdGl0dXRpb25fY291bnRyeSJdLCJkaXNwbGF5IjpbeyJsYW5nIjoiZW4tVVMiLCJsYWJlbCI6Iklzc3VlciBDb3VudHJ5IiwiZGVzY3JpcHRpb24iOiJUaGUgaXNzdWVyIGNvdW50cnkgb2YgdGhlIEVISUMgaG9sZGVyIn1dLCJzZCI6IiIsInN2Z19pZCI6Imlzc3Vlcl9jb3VudHJ5In0seyJwYXRoIjpbImNvbXBldGVudF9pbnN0aXR1dGlvbiIsImluc3RpdHV0aW9uX2lkIl0sImRpc3BsYXkiOlt7ImxhbmciOiJlbi1VUyIsImxhYmVsIjoiSXNzdWVyIEluc3RpdHV0aW9uIENvZGUiLCJkZXNjcmlwdGlvbiI6IlRoZSBpc3N1ZXIgaW5zdGl0dXRpb24gY29kZSBvZiB0aGUgRUhJQyBob2xkZXIifV0sInNkIjoiIiwic3ZnX2lkIjoiaXNzdWVyX2luc3RpdHV0aW9uX2NvZGUifSx7InBhdGgiOlsiZG9jdW1lbnRfaWQiXSwiZGlzcGxheSI6W3sibGFuZyI6ImVuLVVTIiwibGFiZWwiOiJJZGVudGlmaWNhdGlvbiBjYXJkIG51bWJlciIsImRlc2NyaXB0aW9uIjoiVGhlIElkZW50aWZpY2F0aW9uIGNhcmQgbnVtYmVyIG9mIHRoZSBFSElDIGhvbGRlciJ9XSwic2QiOiIiLCJzdmdfaWQiOiJpZGVudGlmaWNhdGlvbl9udW1iZXJfY2FyZCJ9LHsicGF0aCI6WyJwZXJpb2RfZW50aXRsZW1lbnQiLCJlbmRpbmdfZGF0ZSJdLCJkaXNwbGF5IjpbeyJsYW5nIjoiZW4tVVMiLCJsYWJlbCI6IkV4cGlyeSBEYXRlIiwiZGVzY3JpcHRpb24iOiJUaGUgZGF0ZSBhbmQgdGltZSBleHBpcmVkIHRoaXMgY3JlZGVudGlhbCJ9XSwic2QiOiIiLCJzdmdfaWQiOiJleHBpcnlfZGF0ZSJ9XSwic2NoZW1hX3VybCI6IiIsInNjaGVtYV91cmwjaW50ZWdyaXR5IjoiIiwiZXh0ZW5kcyI6IiIsImV4dGVuZHMjaW50ZWdyaXR5IjoiIn0=",
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			client := mockNewClient(ctx, t, "ecdsa", logger.NewSimple("test"))

			got, err := client.ehicClient.MetadataClaim("https://test-issuer.sunet.se")
			assert.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}
