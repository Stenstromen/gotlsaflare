# GoTLSAFlare

## Generate DANE-EE Publickey SHA256 (3 1 1) TLSA Record
```
openssl x509 -noout -pubkey -in fullchain.pem | openssl rsa -pubin -outform DER 2>/dev/null | sha256sum
```

## POST TSLA UPDATE
```
https://api.cloudflare.com/client/v4/zones/:identifier/dns_records

{
    "type":"TLSA",
    "name":"_25._tcp.test",
    "data":
        {
        "usage":3,
        "selector":1,
        "matching_type":1,
        "certificate":"SHA256SUM"
        },
    "ttl":3600,
    "priority":10,
    "proxied":false,
    "comment":"This is a comment"
}
```