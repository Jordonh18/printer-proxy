# Printer Proxy APT Repository

This directory contains the APT repository for Printer Proxy, hosted via GitHub Pages.

## Repository URL

```
[https://apt.jordonh.me](https://apt.jordonh.me)
```

## Installation

```bash
# Add the GPG signing key
curl -fsSL https://apt.jordonh.me/gpg-key.asc | sudo gpg --dearmor -o /usr/share/keyrings/printer-proxy.gpg

# Add the repository
echo "deb [signed-by=/usr/share/keyrings/printer-proxy.gpg] https://apt.jordonh.me stable main" | sudo tee /etc/apt/sources.list.d/printer-proxy.list

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
