package sdjwt3

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidate(t *testing.T) {
	var (
		sdjwt          = `eyJhbGciOiJFUzI1NiIsImtpZCI6ImRlZmF1bHRfc2lnbmluZ19rZXlfaWQiLCJ0eXAiOiJ2YytzZC1qd3QifQ.eyJfc2QiOlsid2ozUWRramU5ZTZ5UzdmSUVjVXlhYTRGSHc2UmppcS1SSUxKN0hpRjdZYyIsIlVyRFFRYzZudU41Z213ZGVBSjBnVWdnMzZiOTJ4UEFDX0t2QWxoV050bmsiLCJHUjZybVNtakFPVU42UGxVakFVcU4zZjBuQkRZX2QteVg1SlN6T1FtZU1ZIiwicDN2ZXhlMWJ4ZjM0Tmw3LXdCRTN1cmlIdnhqaHNnUmRnRXg1OEVuY1M1YyIsIkNaVk9sXzNnZzhrcndGb0lCelpGYmJIcnk2VmhXTjNjc1FvQkE1ZXNnZ2MiLCJQU21EUVFmMDdTT2FDS09weVZiM0kyMS1VcFFxamczT2RHWTZmN0VidElRIiwiRkFkb2xjcWtlc3JVeWI4UGYzSjg5dEN5Y2xUVXNuUURKckVEaXdFUUUydyIsInNKYUlxRldDcW43aTRCYUV5MnFQV2hxd3BFVWNRQXVwYTROaU12czJrODQiLCJranYwOU96aEd3ZkItTm4zQW1BU0ZaXzkzSzFQQ0lRS2lyWlZ1eTUtVmFVIl0sIl9zZF9hbGciOiJzaGEtMjU2IiwiY25mIjp7Imp3ayI6eyJjcnYiOiJQLTI1NiIsImQiOiJNVEl6TkRVMk56ZzVNREV5TXpRMU5qYzRPVEF4TWpNME5UWTNPRGt3TVRJIiwia2lkIjoiZGVmYXVsdF9zaWduaW5nX2tleV9pZCIsImt0eSI6IkVDIiwieCI6IllpUGxYSXEzVkFmR01Nb1Z6QUtCMndZTHkwZTVuOW5Za2ptQWJCQ0lkQnMiLCJ5IjoiZDJQOFR5VWxtTTFqb3AxeVVILWZIQllYZ2JpakYwSVk0ZlBBN2JRWnVERSJ9fSwiZXhwIjoxNzYyNTEyMDA4LCJpc3MiOiJTVU5FVCIsIm5iZiI6MTczMDk3NjAwOH0.C9VXpRk6t9u80BEPZJbhRw0aKdu5DwMLhdiYN9gTtbx5VHFASfS3NUd-Ghg9gDJmSNRYWyON14KfBn0Oy64Kpw~WyJzYWx0IiwicGxhY2VzX29mX3dvcmsiLFt7ImNvdW50cnlfd29yayI6IlNFIiwibm9fZml4ZWRfcGxhY2Vfb2Zfd29ya19leGlzdCI6ZmFsc2UsInBsYWNlX29mX3dvcmsiOlt7ImFkZHJlc3MiOnsicG9zdF9jb2RlIjoiMTIzNSIsInN0cmVldCI6InN0cmVldCIsInRvd24iOiJ0b3duIn0sImNvbXBhbnlfdmVzc2VsX25hbWUiOiIiLCJmbGFnX3N0YXRlX2hvbWVfYmFzZSI6IiIsImlkc19vZl9jb21wYW55IjpbeyJjb21wYW55X2lkIjoiIiwidHlwZV9vZl9pZCI6IiJ9XX1dfV1d~WyJzYWx0Iiwic29jaWFsX3NlY3VyaXR5X3BpbiIsIjEyMzQiXQ~WyJzYWx0IiwibmF0aW9uYWxpdHkiLFsiU0UiXV0~WyJzYWx0IiwiZGV0YWlsc19vZl9lbXBsb3ltZW50IixbeyJhZGRyZXNzIjp7ImNvdW50cnkiOiJTRSIsInBvc3RfY29kZSI6IjEyMzQ1Iiwic3RyZWV0Ijoic3RyZWV0IiwidG93biI6InRvd24ifSwiaWRzX29mX2VtcGxveWVyIjpbeyJlbXBsb3llcl9pZCI6IjEyMyIsInR5cGVfb2ZfaWQiOiIwMSJ9XSwibmFtZSI6IkNvcnAgaW5jLiIsInR5cGVfb2ZfZW1wbG95bWVudCI6IjAxIn1dXQ~WyJzYWx0IiwiZGVjaXNpb25fbGVnaXNsYXRpb25fYXBwbGljYWJsZSIseyJlbmRpbmdfZGF0ZSI6IiIsIm1lbWJlcl9zdGF0ZV93aGljaF9sZWdpc2xhdGlvbl9hcHBsaWVzIjoiIiwic3RhcnRpbmdfZGF0ZSI6IiIsInRyYW5zaXRpb25hbF9ydWxlX2FwcGx5IjpmYWxzZX1d~WyJzYWx0Iiwic3RhdHVzX2NvbmZpcm1hdGlvbiIsIiJd~WyJzYWx0IiwidW5pcXVlX251bWJlcl9vZl9pc3N1ZWRfZG9jdW1lbnQiLCIiXQ~WyJzYWx0IiwiY29tcGV0ZW50X2luc3RpdHV0aW9uIix7ImNvdW50cnlfY29kZSI6IiIsImluc3RpdHV0aW9uX2lkIjoiIiwiaW5zdGl0dXRpb25fbmFtZSI6IiJ9XQ~WyJzYWx0IiwicGVyc29uIix7ImRhdGVfb2ZfYmlydGgiOiIxOTgwLTAxLTAxIiwiZmFtaWx5X25hbWUiOiJrYXJsc3NvbiIsImZvcmVuYW1lIjoia2FsbGUiLCJvdGhlcl9lbGVtZW50cyI6eyJmYW1pbHlfbmFtZV9hdF9iaXJ0aCI6IiIsImZvcmVuYW1lX2F0X2JpcnRoIjoiIiwic2V4IjoiIn19XQ~`
		validPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYiPlXIq3VAfGMMoVzAKB2wYLy0e5
n9nYkjmAbBCIdBt3Y/xPJSWYzWOinXJQf58cFheBuKMXQhjh88DttBm4MQ==
-----END PUBLIC KEY-----`
		invalidPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcyViIENmqo4D2CVOc2uGZbe5a8Nh
eCyvN9CsF7ui3tlcDSVVeCOBnMVMPCSd1kSj7NWv2J47atj0caKJpoBKiA==
-----END PUBLIC KEY-----`
	)

	t.Run("valid public key", func(t *testing.T) {
		decoded, _ := pem.Decode([]byte(validPublicKey))

		pub, err := x509.ParsePKIXPublicKey(decoded.Bytes)
		assert.NoError(t, err)

		valid, err := Validate(sdjwt, pub.(*ecdsa.PublicKey))
		assert.NoError(t, err)

		assert.True(t, valid)
	})

	t.Run("invalid public key", func(t *testing.T) {
		decoded, _ := pem.Decode([]byte(invalidPublicKey))

		pub, err := x509.ParsePKIXPublicKey(decoded.Bytes)
		assert.NoError(t, err)

		valid, err := Validate(sdjwt, pub.(*ecdsa.PublicKey))
		assert.Equal(t, "token signature is invalid: crypto/ecdsa: verification error", err.Error())

		assert.False(t, valid)
	})

	t.Run("duplicate selective disclouser", func(t *testing.T) {
		sdjwt = fmt.Sprintf("%s%s~", sdjwt, "WyJzYWx0Iiwic29jaWFsX3NlY3VyaXR5X3BpbiIsIjEyMzQiXQ")
		fmt.Println(sdjwt)
		decoded, _ := pem.Decode([]byte(validPublicKey))

		pub, err := x509.ParsePKIXPublicKey(decoded.Bytes)
		assert.NoError(t, err)

		valid, err := Validate(sdjwt, pub.(*ecdsa.PublicKey))
		assert.Equal(t, "duplicate selective disclosure", err.Error())

		assert.False(t, valid)
	})
}
