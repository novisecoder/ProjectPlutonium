# Cloudflare SSL Certificates

This directory contains Certificate Signing Requests (CSRs) and private keys for Cloudflare SSL certificates.

## Files

- **origin.csr** - Certificate Signing Request for Cloudflare Origin Certificate
  - **origin-key.pem** - Private key (keep secure)

- **edge.csr** - Certificate Signing Request for Cloudflare Edge Certificate
  - **edge-key.pem** - Private key (keep secure)

- **client.csr** - Certificate Signing Request for Cloudflare Client Certificate
  - **client-key.pem** - Private key (keep secure)

## Usage

1. **Submit CSRs to Cloudflare:**
   - Go to your Cloudflare dashboard
   - Navigate to SSL/TLS > Client Certificates (for client cert) or Origin Server (for origin cert)
   - Upload the corresponding .csr file
   - Cloudflare will return the signed certificate

2. **After receiving certificates from Cloudflare:**
   - Save certificates as:
     - `origin-cert.pem` (origin certificate)
     - `edge-cert.pem` (edge certificate)
     - `client-cert.pem` (client certificate)

3. **Update nginx.conf:**
   - The nginx configuration will use these certificates for SSL/TLS

## Security Notes

⚠️ **Important:**
- Keep all `.pem` key files private and never commit to version control
- Add `*.pem` to `.gitignore`
- The private keys are needed to use the signed certificates
- Keep a backup of the private keys in a secure location

## Testing with Self-Signed Certs

For local testing without Cloudflare, you can generate self-signed certificates:

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout cert-key.pem \
  -out cert.pem \
  -subj "/C=US/ST=State/L=City/O=ProjectPlutonium/CN=localhost"
```
