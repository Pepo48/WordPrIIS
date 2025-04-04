# Using Cloudflare Origin Certificates with WordPrIIS

This guide explains how to set up Cloudflare Origin Certificates to secure the connection between Cloudflare and your WordPress server.

## Overview

Cloudflare Origin Certificates provide encryption between Cloudflare and your origin server without the need for a publicly trusted certificate. This is ideal when your server is behind Cloudflare's proxy and you want to ensure end-to-end encryption.

## Prerequisites

- A domain registered and activated in Cloudflare
- Cloudflare's proxy enabled for your domain (orange cloud icon)
- WordPress installed using WordPrIIS

## Steps to Generate and Use Cloudflare Origin Certificates

### 1. Generate the Certificate in Cloudflare Dashboard

1. Log in to your Cloudflare dashboard
2. Select your domain
3. Go to **SSL/TLS > Origin Server**
4. Click **Create Certificate**
5. Configure certificate options:
   - Hostnames: Include your root domain and a wildcard (e.g., `example.com`, `*.example.com`)
   - Private key type: RSA (2048)
   - Validity: Choose between 1 year, 5 years, or 15 years
6. Click **Create**
7. Download both the **Origin Certificate** and **Private Key** files
   - The files will be in PEM format (`.pem` extension)
   - Save them to a secure location on your server

### 2. Install Certificates Using WordPrIIS

If you're running WordPrIIS for the first time:

1. When prompted for SSL configuration, choose option 3 (Cloudflare Origin Certificate)
2. Provide the full paths to both the certificate and private key files

If you're updating an existing WordPress installation:

1. Run the script again
2. Select "Yes" when asked to configure HTTPS
3. Choose option 3 for Cloudflare Origin Certificates
4. Provide the paths to your certificate and key files

### 3. Verify the Configuration

1. Check that HTTPS is working by visiting your site with `https://`
2. In Cloudflare, ensure the SSL/TLS encryption mode is set to "Full (strict)" under **SSL/TLS > Overview**

### 4. Troubleshooting

If you encounter issues:

- Verify the certificate paths are correct
- Check that the certificate and key match each other
- Ensure Cloudflare's proxy is enabled (orange cloud) for relevant DNS records
- Confirm the SSL/TLS encryption mode is set to "Full" or "Full (strict)"

### 5. Certificate Renewal

Cloudflare Origin Certificates must be renewed before they expire. The process is:

1. Generate a new certificate in Cloudflare dashboard
2. Run WordPrIIS again, selecting the Cloudflare certificate option
3. Provide the paths to the new certificate files

You can also manually import them using the IIS Manager:

1. Open IIS Manager
2. Select your server
3. Double-click "Server Certificates"
4. Use the "Import..." option to import your new certificate
5. Bind the new certificate to your site

### Security Notes

- Keep your private key secure; anyone with this key can impersonate your server
- Cloudflare Origin Certificates are trusted only by Cloudflare, not by browsers directly
- Always use "Full (strict)" mode in Cloudflare for best security
