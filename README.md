<!-- markdownlint-disable MD051 -->
# GoTLSAFlare

![GoTLSAFlare](./gotlsaflare.webp)

- [GoTLSAFlare](#gotlsaflare)
  - [Description](#description)
  - [Generate Cloudflare API Token](#generate-cloudflare-api-token)
  - [Installation via Homebrew (MacOS/Linux - x86\_64/arm64)](#installation-via-homebrew-macoslinux---x86_64arm64)
  - [Download and Run Binary](#download-and-run-binary)
  - [Build and Run Binary](#build-and-run-binary)
  - [Example Usage](#example-usage)
  - [Practical Usage](#practical-usage)
    - [Create TLSA Record, DANE-EE (3 1 1) and DANE-TA (2 0 1)](#create-tlsa-record-dane-ee-3-1-1-and-dane-ta-2-0-1)
    - [Create TLSA Record, DANE-TA (2 0 1) only](#create-tlsa-record-dane-ta-2-0-1-only)
    - [Create TLSA Record, DANE-EE (3 1 1) only (default)](#create-tlsa-record-dane-ee-3-1-1-only-default)
    - [Create TLSA Record with SHA2-512 matching type](#create-tlsa-record-with-sha2-512-matching-type)
    - [Create TLSA Record with SHA2-512 matching type for both DANE-EE and DANE-TA](#create-tlsa-record-with-sha2-512-matching-type-for-both-dane-ee-and-dane-ta)
    - [LetsEncrypt Certbot renewal hook](#letsencrypt-certbot-renewal-hook)
    - [LetsEncrypt Certbot renewal hook with rolling update](#letsencrypt-certbot-renewal-hook-with-rolling-update)
  - [Random Notes](#random-notes)
    - [Generate DANE-EE Publickey SHA256 (3 1 1) TLSA Record](#generate-dane-ee-publickey-sha256-3-1-1-tlsa-record)
    - [Generate DANE-EE Publickey SHA512 (3 1 2) TLSA Record](#generate-dane-ee-publickey-sha512-3-1-2-tlsa-record)
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

# Create TLSA Record, DANE-TA (2 0 1) only
./gotlsaflare create --url example.com --subdomain email --tcp25 --dane-ta --no-dane-ee --cert path/to/fullchain.pem

# Create TLSA Record, both DANE-EE (3 1 1) and DANE-TA (2 0 1)
./gotlsaflare create --url example.com --subdomain email --tcp25 --dane-ta --cert path/to/fullchain.pem

# Create TLSA Record, DANE-EE (3 1 1) only (default)
./gotlsaflare create --url example.com --subdomain email --tcp25 --no-dane-ta --cert path/to/certificate.pem

# Update TLSA Record, both DANE-EE (3 1 1) and DANE-TA (2 0 1)
./gotlsaflare update --url example.com --subdomain email --tcp25 --dane-ta --cert path/to/fullchain.pem

# Update TLSA Record, both DANE-EE (3 1 1) and DANE-TA (2 0 1) with rolling update (keeps old record for TTL seconds, then deletes it)
./gotlsaflare update --url example.com --subdomain email --tcp25 --dane-ta --cert path/to/fullchain.pem --rollover

# Update TLSA Record, both DANE-EE (3 1 1) and DANE-TA (2 0 1) with custom TCP port
./gotlsaflare update --url example.com --subdomain www --tcp-port 443 --dane-ta --cert path/to/fullchain.pem

# Create TLSA Record with explicit selector (overrides defaults)
./gotlsaflare create --url example.com --subdomain email --tcp25 --cert path/to/certificate.pem --selector 0

# Create TLSA Record with explicit selector for both DANE-EE and DANE-TA (overrides defaults)
./gotlsaflare create --url example.com --subdomain email --tcp25 --dane-ta --cert path/to/certificate.pem --selector 0

# Create TLSA Record with SHA2-512 matching type (default is SHA2-256)
./gotlsaflare create --url example.com --subdomain email --tcp25 --cert path/to/certificate.pem --matching-type 2

# Create TLSA Record with SHA2-512 matching type for both DANE-EE and DANE-TA
./gotlsaflare create --url example.com --subdomain email --tcp25 --dane-ta --cert path/to/certificate.pem --matching-type 2
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

## Practical Usage

### Create TLSA Record, DANE-EE (3 1 1) and DANE-TA (2 0 1)

```bash
export TOKEN="# Cloudflare API TOKEN"
gotlsaflare create --url example.com --subdomain email --tcp25 --dane-ta --cert path/to/fullchain.pem
```

### Create TLSA Record, DANE-TA (2 0 1) only

```bash
export TOKEN="# Cloudflare API TOKEN"
gotlsaflare create --url example.com --subdomain email --tcp25 --dane-ta --no-dane-ee --cert path/to/fullchain.pem
```

### Create TLSA Record, DANE-EE (3 1 1) only (default)

```bash
export TOKEN="# Cloudflare API TOKEN"
gotlsaflare create --url example.com --subdomain email --tcp25 --cert path/to/certificate.pem
```

### Create TLSA Record with SHA2-512 matching type

```bash
export TOKEN="# Cloudflare API TOKEN"
gotlsaflare create --url example.com --subdomain email --tcp25 --cert path/to/certificate.pem --matching-type 2
```

### Create TLSA Record with SHA2-512 matching type for both DANE-EE and DANE-TA

```bash
export TOKEN="# Cloudflare API TOKEN"
gotlsaflare create --url example.com --subdomain email --tcp25 --dane-ta --cert path/to/fullchain.pem --matching-type 2
```

### LetsEncrypt Certbot renewal hook

```bash
# Update TLSA Record, DANE-EE (3 1 1)
echo "TOKEN='Cloudflare API TOKEN' gotlsaflare update --url example.com --subdomain email --tcp25 --cert path/to/fullchain.pem" >> /etc/letsencrypt/renewal-hooks/post/update-tlsa.sh

# Restart Postfix service
echo 'systemctl restart postfix.service' >> /etc/letsencrypt/renewal-hooks/post/update-tlsa.sh

# Make script executable
chmod +x /etc/letsencrypt/renewal-hooks/post/update-tlsa.sh

# Restart Certbot service
systemctl restart certbot.service
```

### LetsEncrypt Certbot renewal hook with rolling update

```bash
# Update TLSA Record, DANE-EE (3 1 1)  with rolling update
echo "TOKEN='Cloudflare API TOKEN' gotlsaflare update --url example.com --subdomain email --tcp25 --dane-ta --cert path/to/fullchain.pem --rollover" >> /etc/letsencrypt/renewal-hooks/post/update-tlsa.sh

# Restart Postfix service
echo 'systemctl restart postfix.service' >> /etc/letsencrypt/renewal-hooks/post/update-tlsa.sh

# Make script executable
chmod +x /etc/letsencrypt/renewal-hooks/post/update-tlsa.sh

# Restart Certbot service
systemctl restart certbot.service
```

## Random Notes

### Generate DANE-EE Publickey SHA256 (3 1 1) TLSA Record

```bash
openssl x509 -noout -pubkey -in fullchain.pem | openssl rsa -pubin -outform DER 2>/dev/null | sha256sum
```

### Generate DANE-EE Publickey SHA512 (3 1 2) TLSA Record

```bash
openssl x509 -noout -pubkey -in fullchain.pem | openssl rsa -pubin -outform DER 2>/dev/null | sha512sum
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

Example with SHA2-512:

```json
{
    "type":"TLSA",
    "name":"_25._tcp.test",
    "data":
        {
        "usage":3,
        "selector":1,
        "matching_type":2,
        "certificate":"SHA512SUM"
        },
    "ttl":3600,
    "priority":10,
    "proxied":false,
    "comment":"This is a comment"
}
```
