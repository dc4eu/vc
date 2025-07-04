# vp_token

## Standard JWT

### Header

```text
eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCIsICJraWQiOiAiZG9jLXNpZ25lci0wNS0yNS0yMDIyIn0
```

```json
{"alg": "ES256", "typ": "dc+sd-jwt", "kid": "doc-signer-05-25-2022"}
```

### Body

```text
eyJfc2QiOiBbIjNvVUNuYUt0N3dxREt1eWgtTGdRb3p6ZmhnYjhnTzVOaS1SQ1dzV1cydkEiLCAiOHo4ejlYOWpVdGI5OWdqZWpDd0ZBR3o0YXFsSGYtc0NxUTZlTV9xbXBVUSIsICJDeHE0ODcyVVhYbmdHVUxUX2tsOGZkd1ZGa3lLNkFKZlBaTHk3TDVfMGtJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpnbGhRRzBEcGZheVF3TFVLNCIsICJzRmNWaUhOLUpHM2VUVXlCbVU0Zmt3dXN5NUkxU0xCaGUxak52S3hQNXhNIiwgInRpVG5ncDlfamhDMzg5VVA4X2s2N01YcW9TZmlIcTNpSzZvOXVuNHdlX1kiLCAieHNLa0dKWEQxLWUzSTl6ajBZeUtOdi1sVTVZcWhzRUFGOU5oT3I4eGdhNCJdLCAiaXNzIjogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAidmN0IjogImh0dHBzOi8vY3JlZGVudGlhbHMuZXhhbXBsZS5jb20vaWRlbnRpdHlfY3JlZGVudGlhbCIsICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlGMkhaUSJ9fX0
```

```json
{
    "_sd": [
        "3oUCnaKt7wqDKuyh-LgQozzfhgb8gO5Ni-RCWsWW2vA",
        "8z8z9X9jUtb99gjejCwFAGz4aqlHf-sCqQ6eM_qmpUQ",
        "Cxq4872UXXngGULT_kl8fdwVFkyK6AJfPZLy7L5_0kI",
        "TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo",
        "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4",
        "sFcViHN-JG3eTUyBmU4fkwusy5I1SLBhe1jNvKxP5xM",
        "tiTngp9_jhC389UP8_k67MXqoSfiHq3iK6o9un4we_Y",
        "xsKkGJXD1-e3I9zj0YyKNv-lU5YqhsEAF9NhOr8xga4"
    ],
    "iss": "https://example.com/issuer",
    "iat": 1683000000,
    "exp": 1883000000,
    "vct": "https://credentials.example.com/identity_credential",
    "_sd_alg": "sha-256",
    "cnf": {
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
            "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
        }
    }
}
```

### Signature

```text
8eHLENOFGlZ7dcHSOCYzTu6BuBN8PqYnJCcPgGUh6XoxF6U6S5NVZq40cuLyvJqHZ56xDGeQch0lBjLRKvS4Rw
```

## SD-JWT additions

### Selective Disclosers

```text
~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd
```

```json
["eluV5Og3gSNII8EYnsxA_A", "family_name", "Doe"]
```

```text
~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd
```

```json
["2GLC42sKQveCfGfryNRN9w", "given_name", "John"]
```

## Keybinding

### header

```text
~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.
```

```json
{"alg": "ES256", "typ": "kb+jwt"}
```

### body

```text
eyJub25jZSI6ICJuLTBTNl9XekEyTWoiLCAiYXVkIjogImh0dHBzOi8vZXhhbXBsZS5jb20vdmVyaWZpZXIiLCAiaWF0IjogMTcwOTgzODYwNCwgInNkX2hhc2giOiAiRHktUll3WmZhYW9DM2luSmJMc2xnUHZNcDA5YkgtY2xZUF8zcWJScXRXNCJ9
```

```json
{"nonce": "n-0S6_WzA2Mj", "aud": "https://example.com/verifier", "iat": 1709838604, "sd_hash": "Dy-RYwZfaaoC3inJbLslgPvMp09bH-clYP_3qbRqtW4"}
```

### signature

```text
.RmgIhqCHYWerxbDboMuB0lli63HPJHI9Vl2ZNOGh20C7_6p7nf3Wkd2wkx5WlmwTwtHKc87MBY2nuRLoeduQMA
```
