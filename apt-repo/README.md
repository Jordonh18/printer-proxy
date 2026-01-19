# Printer Proxy APT Repository

This directory contains the APT repository for Printer Proxy, hosted via GitHub Pages.

## Repository URL

```
https://jordonh18.github.io/printer-proxy
```

## Installation

```bash
# Add the GPG signing key
curl -fsSL https://jordonh18.github.io/printer-proxy/gpg-key.asc | sudo gpg --dearmor -o /usr/share/keyrings/printer-proxy.gpg

# Add the repository
echo "deb [signed-by=/usr/share/keyrings/printer-proxy.gpg] https://jordonh18.github.io/printer-proxy stable main" | sudo tee /etc/apt/sources.list.d/printer-proxy.list

# Install
sudo apt update
sudo apt install printer-proxy
```

## Structure

```
apt-repo/
├── index.html              # Landing page
├── gpg-key.asc            # GPG public key for verification
├── dists/
│   └── stable/
│       ├── Release         # Repository metadata
│       ├── Release.gpg     # Detached GPG signature
│       ├── InRelease       # Inline signed Release
│       └── main/
│           └── binary-all/
│               ├── Packages      # Package index
│               └── Packages.gz   # Compressed package index
└── pool/
    └── main/
        └── printer-proxy_*.deb  # Package files
```

## GPG Signing

Packages are signed with GPG for security verification. The workflow automatically:

1. Signs the `Release` file with a detached signature (`Release.gpg`)
2. Creates an inline-signed `InRelease` file
3. Exports the public key to `gpg-key.asc`

## Required Secrets

The GitHub Actions workflow requires these secrets:

- `GPG_PRIVATE_KEY`: The ASCII-armored private GPG key
- `GPG_PASSPHRASE`: The passphrase for the GPG key

### Generating a GPG Key

```bash
# Generate a new key (use RSA 4096, no expiration for repo signing)
gpg --full-generate-key

# Export private key (add to GPG_PRIVATE_KEY secret)
gpg --armor --export-secret-keys YOUR_KEY_ID

# Export public key (for verification)
gpg --armor --export YOUR_KEY_ID
```
