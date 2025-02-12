# GoTLSAFlare

![GoTLSAFlare](./gotlsaflare.webp)

- [GoTLSAFlare](#gotlsaflare)
  - [Description](#description)
  - [Generate Cloudflare API Token](#generate-cloudflare-api-token)
  - [Installation via Homebrew (MacOS/Linux - x86\_64/arm64)](#installation-via-homebrew-macoslinux---x86_64arm64)
  - [Download and Run Binary](#download-and-run-binary)
  - [Build and Run Binary](#build-and-run-binary)
  - [Example Usage](#example-usage)
  - [Random Notes](#random-notes)
    - [Generate DANE-EE Publickey SHA256 (3 1 1) TLSA Record](#generate-dane-ee-publickey-sha256-3-1-1-tlsa-record)
    - [POST TLSA UPDATE](#post-tlsa-update)

## Description

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

- For **MacOS** and **Linux**: Checkout and download the latest binary from [Releases page](https://github.com/Stenstromen/gotlsaflare/releases/latest/)
- For **Windows**: Build the binary yourself.

## Build and Run Binary

```bash
go build
./gotlsaflare
```

## Example Usage

```bash
# Set Cloudflare API TOKEN
export TOKEN="# Cloudflare API TOKEN"

# Create TLSA Record, DANE-EE (3 1 1)
./gotlsaflare create --url example.com --subdomain email --tcp25 --cert path/to/certificate.pem

# Update TLSA Record, DANE-EE (3 1 1)
./gotlsaflare update --url example.com --subdomain email --tcp25 --cert path/to/certificate.pem

# Create TLSA Record, DANE-EE (3 1 1) and DANE-TA (2 1 1)
./gotlsaflare create --url example.com --subdomain email --tcp25 --dane-ta --cert path/to/fullchain.pem

# Update TLSA Record, DANE-EE (3 1 1) and DANE-TA (2 1 1)
./gotlsaflare update --url example.com --subdomain email --tcp25 --dane-ta --cert path/to/fullchain.pem
```

```bash
Usage of ./gotlsaflare
Go binary for updating TLSA DANE record on Cloudflare from x509 Certificate.

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

## Random Notes

### Generate DANE-EE Publickey SHA256 (3 1 1) TLSA Record

```bash
openssl x509 -noout -pubkey -in fullchain.pem | openssl rsa -pubin -outform DER 2>/dev/null | sha256sum
```

### POST TLSA UPDATE

`https://api.cloudflare.com/client/v4/zones/:identifier/dns_records`

```json
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
