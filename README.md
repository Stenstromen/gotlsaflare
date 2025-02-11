# GoTLSAFlare

Go binary for updating TLSA DANE record on cloudflare from x509 Certificate

## Generate Cloudflare API Token

1. Visit [https://dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)
2. Create Token
3. "Edit Zone DNS" Template
4. "Zone Resources" Include > Specific Zone > example.com

## Installation via Homebrew (MacOS/Linux - x86_64/arm64)

```bash
brew install stenstromen/tap/gotlsaflare
```

## Download and Run Binary

* For **MacOS** and **Linux**: Checkout and download the latest binary from [Releases page](https://github.com/Stenstromen/gotlsaflare/releases/latest/)
* For **Windows**: Build the binary yourself.

## Build and Run Binary

```bash
go build
./gotlsaflare
```

## Example Usage

```bash
- GoTLSAFlare Example Usage

- Create TLSA Record
export TOKEN="# Cloudflare API TOKEN"
./gotlsaflare create --url example.com --subdomain email --tcp25 --cert path/to/certificate.pem

- Update TLSA Record
export TOKEN="# Cloudflare API TOKEN"
./gotlsaflare update --url example.com --subdomain email --tcp25 --cert path/to/certificate.pem

Usage of ./gotlsaflare
Go binary for updating TLSA DANE record on cloudflare from x509 Certificate.

Usage:
  gotlsaflare [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  create      Create TLSA DNS Record
  help        Help about any command
  update      Update TLSA DNS Record

Flags:
  -h, --help   help for gotlsaflare

Use "gotlsaflare [command] --help" for more information about a command.
```

# Random Notes

## Generate DANE-EE Publickey SHA256 (3 1 1) TLSA Record

```bash
openssl x509 -noout -pubkey -in fullchain.pem | openssl rsa -pubin -outform DER 2>/dev/null | sha256sum
```

## POST TLSA UPDATE

```json
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
