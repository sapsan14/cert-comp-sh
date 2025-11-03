# Certificate Processing and Comparison Tool

A bash script tool for extracting, processing, and comparing X.509 certificates, specifically designed for Estonian eID (ESTEID2025) certificates from UAT and Production environments.

## Overview

This project provides a comprehensive solution for:
- Extracting detailed information from X.509 certificate files
- Comparing certificates between UAT (test) and Production environments
- Generating detailed markdown comparison reports
- Validating certificate structure and configuration

## Features

- **Certificate Extraction**: Converts `.crt` files to human-readable text format using OpenSSL
- **Detailed Comparison**: Compares UAT and PROD certificates side-by-side
- **Comprehensive Reports**: Generates markdown reports with:
  - Common characteristics
  - Detailed differences
  - Analysis and validation
  - Summary and conclusions
- **Support for Multiple Certificate Types**: Handles both authentication and signature certificates
- **Automatic Detection**: Identifies UAT vs PROD certificates automatically
- **Error Handling**: Robust error checking and colored output for better visibility

## Requirements

- **Bash** (version 4.0 or higher)
- **OpenSSL** (for certificate processing)
- **Linux/Unix environment** (tested on WSL2)

## Installation

No installation required. Simply ensure you have the required dependencies:

```bash
# Check if OpenSSL is installed
openssl version

# If not installed (Ubuntu/Debian):
sudo apt-get update
sudo apt-get install openssl
```

## Usage

### Basic Usage

Process all certificates and generate comparison report:

```bash
./process_certificates.sh
```

Or:

```bash
./process_certificates.sh all
```

### Extract Certificate Information

Extract information from a specific certificate file:

```bash
./process_certificates.sh extract <certificate_file.crt>
```

Example:
```bash
./process_certificates.sh extract auth-00000000007.crt
```

This creates a corresponding `.txt` file with detailed certificate information.

### Generate Comparison Report Only

If certificates are already extracted, generate just the comparison report:

```bash
./process_certificates.sh compare
```

## File Structure

```
cert-comp-sh/
├── process_certificates.sh          # Main processing script
├── README.md                         # This file
├── certificate_comparison_report.md  # Generated comparison report
│
├── auth-00000000007.crt             # UAT authentication certificate
├── auth-00000000007.txt             # Extracted UAT auth certificate info
├── sign-00000000007.crt             # UAT signature certificate
├── sign-00000000007.txt             # Extracted UAT signature cert info
│
├── auth-PROD-CERT-ID.crt             # PROD authentication certificate
├── auth-PROD-CERT-ID.txt             # Extracted PROD auth certificate info
├── sign-PROD-CERT-ID.crt             # PROD signature certificate
└── sign-PROD-CERT-ID.txt             # Extracted PROD signature cert info
```

## How It Works

1. **Certificate Extraction**: The script uses OpenSSL to extract detailed information from certificate files and saves it to text files.

2. **Field Extraction**: The script parses certificate text files to extract specific fields:
   - Serial number
   - Issuer information
   - Subject information
   - Validity periods
   - Key algorithms and sizes
   - Extended key usage
   - Certificate policies
   - URLs (CA Issuers, OCSP, CRL)
   - And more

3. **Comparison**: For each certificate type (authentication and signature), the script:
   - Identifies UAT and PROD certificate pairs
   - Compares common characteristics
   - Lists differences in a structured table
   - Provides analysis and validation

4. **Report Generation**: Creates a comprehensive markdown report (`certificate_comparison_report.md`) with:
   - Overview section
   - Detailed comparisons for each certificate type
   - Summary of differences
   - Conclusions

## Certificate Types

The script handles two types of certificates:

### Authentication Certificates
- **Purpose**: TLS Web Client Authentication and E-mail Protection
- **Extended Key Usage**: TLS Web Client Authentication, E-mail Protection
- **Key Usage**: Digital Signature, Key Agreement
- **Subject Alternative Name**: Contains email address

### Signature Certificates
- **Purpose**: Digital signatures with non-repudiation
- **Key Usage**: Non Repudiation
- **Extended Key Usage**: Not present (as expected)
- **Subject Alternative Name**: Not present (as expected)

## UAT vs PROD Differences

The script validates expected differences between UAT and PROD environments:

### Expected Configuration Differences
- **Issuer Names**: UAT certificates have "UAT ESTEID2025" prefix
- **URLs**: UAT URLs contain `-uat` suffix or `uat` prefix:
  - CA Issuers: `crt-uat.eidpki.ee` vs `crt.eidpki.ee`
  - OCSP: `ocsp-uat.eidpki.ee` vs `ocsp.eidpki.ee`
  - CRL: `crl-uat.eidpki.ee` vs `crl.eidpki.ee`
  - Repository: `repository-uat.eidpki.ee` vs `repository.eidpki.ee`
- **Certificate Policies**: UAT uses test policy OID `2.999.1.3.6.1.4.1.51455.2.1.1` vs production `1.3.6.1.4.1.51455.2.1.1`

### Expected Unique Values (OK)
- Serial numbers
- Subjects
- Validity periods
- Public keys
- Signature values
- Key identifiers

## Output Example

The generated report includes:

```markdown
# Certificate Comparison Report

## 1. Authentication Certificates Comparison
### Common Characteristics
- Signature Algorithm: ecdsa-with-SHA384
- Key Size: 384-bit (secp384r1 / P-384 curve)
- ...

### Differences
| Field | UAT | PROD |
|-------|-----|------|
| Serial Number | ... | ... |
| Issuer | CN = UAT ESTEID2025 | CN = ESTEID2025 |
| ...

### Analysis
- ✅ Structure Match
- ⚠️ Policy Difference
- ✅ URL Pattern
...
```

## Error Handling

The script includes error handling for:
- Missing certificate files
- Invalid certificate formats
- Missing OpenSSL installation
- File extraction failures

Errors are displayed with colored output:
- 🔴 **RED**: Errors
- 🟡 **YELLOW**: Warnings
- 🔵 **BLUE**: Information
- 🟢 **GREEN**: Success messages

## Troubleshooting

### OpenSSL Not Found
```bash
# Install OpenSSL
sudo apt-get install openssl

# Verify installation
openssl version
```

### Permission Denied
```bash
# Make script executable
chmod +x process_certificates.sh
```

### Certificate Format Issues
The script handles both PEM and DER formats. If you encounter issues:
- Ensure certificate files are valid X.509 certificates
- Check that files have `.crt` extension
- Verify certificates are not corrupted

## License

This project is provided as-is for certificate processing and comparison purposes.

## Contributing

Feel free to submit issues or pull requests for improvements.

## Author

Created for processing and comparing Estonian eID (ESTEID2025) certificates.

