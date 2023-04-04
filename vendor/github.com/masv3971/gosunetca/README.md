# goladok3

[![Go Reference](https://pkg.go.dev/badge/github.com/masv3971/gosunetca.svg)](https://pkg.go.dev/github.com/masv3971/gosunetca)

## Installation

```
go get github.com/masv3971/gosunetca
 ```

## Examples

### Signing documents

 ```go
 package main

import (
    "github.com/masv3971/gosunetca"
)

func main() {
    client, err := New(Config{
        ServerURL: "https://ca.example.com",
        Token:     "d0f2a35a-b8d2-11ed-a74f-a7526ac1d573",
        UserAgent: "blackbox-app/1.0",
    })
    if err != nil {
        panic(err)
    }
    signedDocuments, _, err := client.Sign.Documents(context.Background(), &types.SignRequest{
        Meta: types.SignMetaRequest{
            Version:  1,
            KeyLabel: "Ladok-sign-v1",
            Encoding: "base64",
            KeyType:  "secp256r1",
        },
        Documents: []types.UnsignedDocument{
            {
                ID:   "64d06fbc-b8d3-11ed-a4ed-9b1b4d858581",
                Data: "ZXR0IGRva3VtZW50IGF0dCBzaWduZXJh",
            },
        },
    })
    if err != nil {
        panic(err)
    }

    for _, doc := range signedDocuments.SignatureValues {
        fmt.Println(doc.ID, doc.Signature)
    }
}
```
