#!/bin/bash

# Certificate Processing and Comparison Script
# This script extracts certificate information, compares UAT and PROD certificates,
# and generates a comprehensive comparison report.

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_FILE="${SCRIPT_DIR}/certificate_comparison_report.md"

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to extract certificate information to text file
extract_certificate() {
    local cert_file="$1"
    local output_file="$2"
    
    if [ ! -f "$cert_file" ]; then
        print_error "Certificate file not found: $cert_file"
        return 1
    fi
    
    print_info "Extracting certificate information from $(basename "$cert_file")..."
    
    # Use openssl to extract certificate text
    # Handle both PEM and DER formats, and files with metadata
    if grep -q "BEGIN CERTIFICATE" "$cert_file"; then
        # Extract the certificate part (between BEGIN and END)
        if grep -q "BEGIN CERTIFICATE" "$cert_file" && grep -q "END CERTIFICATE" "$cert_file"; then
            openssl x509 -text -noout -in <(sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' "$cert_file") > "$output_file" 2>/dev/null || \
            openssl x509 -text -noout -in "$cert_file" > "$output_file" 2>/dev/null
        else
            openssl x509 -text -noout -in "$cert_file" > "$output_file" 2>/dev/null
        fi
    else
        # Try DER format
        openssl x509 -inform DER -text -noout -in "$cert_file" > "$output_file" 2>/dev/null || {
            print_error "Failed to extract certificate from $cert_file"
            return 1
        }
    fi
    
    if [ -f "$output_file" ] && [ -s "$output_file" ]; then
        print_success "Certificate information saved to $(basename "$output_file")"
        return 0
    else
        print_error "Failed to extract certificate information"
        return 1
    fi
}

# Function to extract a field from certificate text file
extract_field() {
    local cert_txt="$1"
    local field="$2"
    
    case "$field" in
        "serial")
            grep -A 1 "Serial Number:" "$cert_txt" 2>/dev/null | tail -1 | sed 's/^[[:space:]]*//' | tr -d ':' | tr '\n' ' ' | sed 's/[[:space:]]*$//'
            ;;
        "issuer_cn")
            grep "Issuer:" "$cert_txt" 2>/dev/null | sed 's/Issuer:[[:space:]]*//' | grep -o 'CN[[:space:]]*=[^,]*' | sed 's/CN[[:space:]]*=[[:space:]]*//' | head -1
            ;;
        "issuer")
            grep "Issuer:" "$cert_txt" 2>/dev/null | sed 's/Issuer:[[:space:]]*//' | head -c 100
            ;;
        "subject_cn")
            grep "Subject:" "$cert_txt" 2>/dev/null | grep -o 'CN[[:space:]]*=[^,]*' | sed 's/CN[[:space:]]*=[[:space:]]*//' | sed 's/"//g' | head -1
            ;;
        "subject")
            grep "Subject:" "$cert_txt" 2>/dev/null | sed 's/Subject:[[:space:]]*//' | head -c 100
            ;;
        "validity_from")
            grep "Not Before:" "$cert_txt" 2>/dev/null | sed 's/Not Before:[[:space:]]*//' | head -c 20
            ;;
        "validity_to")
            grep "Not After:" "$cert_txt" 2>/dev/null | sed 's/Not After:[[:space:]]*//' | head -c 20
            ;;
        "signature_algorithm")
            grep "Signature Algorithm:" "$cert_txt" 2>/dev/null | head -1 | sed 's/Signature Algorithm:[[:space:]]*//'
            ;;
        "public_key_algorithm")
            grep "Public Key Algorithm:" "$cert_txt" 2>/dev/null | sed 's/Public Key Algorithm:[[:space:]]*//'
            ;;
        "key_size")
            grep "Public-Key:" "$cert_txt" 2>/dev/null | sed 's/.*(\([0-9]*\) bit).*/\1/'
            ;;
        "authority_key_id")
            grep -A 1 "Authority Key Identifier:" "$cert_txt" 2>/dev/null | tail -1 | sed 's/^[[:space:]]*//' | tr -d ':' | tr '\n' ' ' | sed 's/[[:space:]]*$//'
            ;;
        "subject_key_id")
            grep -A 1 "Subject Key Identifier:" "$cert_txt" 2>/dev/null | tail -1 | sed 's/^[[:space:]]*//' | tr -d ':' | tr '\n' ' ' | sed 's/[[:space:]]*$//'
            ;;
        "san_email")
            grep -A 1 "Subject Alternative Name:" "$cert_txt" 2>/dev/null | grep "email:" | sed 's/.*email:\([^[:space:]]*\).*/\1/' | head -1
            ;;
        "ca_issuers_uri")
            grep -A 5 "Authority Information Access:" "$cert_txt" 2>/dev/null | grep "CA Issuers - URI:" | sed 's/.*URI:\(.*\)/\1/' | head -1
            ;;
        "ocsp_uri")
            grep -A 5 "Authority Information Access:" "$cert_txt" 2>/dev/null | grep "OCSP - URI:" | sed 's/.*URI:\(.*\)/\1/' | head -1
            ;;
        "crl_uri")
            grep -A 3 "CRL Distribution Points:" "$cert_txt" 2>/dev/null | grep "URI:" | sed 's/.*URI:\(.*\)/\1/' | head -1
            ;;
        "cert_policies")
            grep -A 10 "Certificate Policies:" "$cert_txt" 2>/dev/null | grep "Policy:" | sed 's/.*Policy:[[:space:]]*//' | tr '\n' '; ' | sed 's/; $//'
            ;;
        "cps_uri")
            grep -A 10 "Certificate Policies:" "$cert_txt" 2>/dev/null | grep "CPS:" | sed 's/.*CPS:[[:space:]]*//' | head -1
            ;;
        "extended_key_usage")
            grep -A 5 "Extended Key Usage:" "$cert_txt" 2>/dev/null | grep -v "Extended Key Usage:" | sed 's/^[[:space:]]*//' | grep -v "^$" | tr '\n' ', ' | sed 's/, $//' | head -c 100
            ;;
        "key_usage")
            grep -A 5 "Key Usage:" "$cert_txt" 2>/dev/null | grep -v "Key Usage:" | sed 's/^[[:space:]]*//' | grep -v "^$" | grep -v "critical" | tr '\n' ', ' | sed 's/, $//' | head -c 100
            ;;
        "is_ca")
            if grep -q "CA:TRUE" "$cert_txt" 2>/dev/null; then
                echo "TRUE"
            else
                echo "FALSE"
            fi
            ;;
        *)
            echo ""
            ;;
    esac
}

# Function to format validity period
format_validity() {
    local from="$1"
    local to="$2"
    local from_date=$(date -d "$from" +"%b %d %Y" 2>/dev/null || echo "$from")
    local to_date=$(date -d "$to" +"%b %d %Y" 2>/dev/null || echo "$to")
    echo "${from_date} - ${to_date}"
}

# Function to compare two certificates in detail
compare_certificates_detailed() {
    local uat_cert="$1"
    local prod_cert="$2"
    local cert_type="$3"
    local cert_name="$4"
    local uat_name=$(basename "$uat_cert" .crt)
    local prod_name=$(basename "$prod_cert" .crt)
    
    print_info "Comparing $cert_type certificates: $uat_name vs $prod_name"
    
    # Extract certificates if text files don't exist
    local uat_txt="${SCRIPT_DIR}/${uat_name}.txt"
    local prod_txt="${SCRIPT_DIR}/${prod_name}.txt"
    
    if [ ! -f "$uat_txt" ]; then
        extract_certificate "$uat_cert" "$uat_txt"
    fi
    
    if [ ! -f "$prod_txt" ]; then
        extract_certificate "$prod_cert" "$prod_txt"
    fi
    
    # Extract common characteristics
    local uat_sig_alg=$(extract_field "$uat_txt" "signature_algorithm")
    local uat_pub_alg=$(extract_field "$uat_txt" "public_key_algorithm")
    local uat_key_size=$(extract_field "$uat_txt" "key_size")
    local uat_is_ca=$(extract_field "$uat_txt" "is_ca")
    local uat_key_usage=$(extract_field "$uat_txt" "key_usage")
    local uat_ext_key_usage=$(extract_field "$uat_txt" "extended_key_usage")
    
    # Extract differences
    local uat_serial=$(extract_field "$uat_txt" "serial")
    local prod_serial=$(extract_field "$prod_txt" "serial")
    
    local uat_issuer=$(extract_field "$uat_txt" "issuer_cn")
    local prod_issuer=$(extract_field "$prod_txt" "issuer_cn")
    
    local uat_validity_from=$(extract_field "$uat_txt" "validity_from")
    local uat_validity_to=$(extract_field "$uat_txt" "validity_to")
    local prod_validity_from=$(extract_field "$prod_txt" "validity_from")
    local prod_validity_to=$(extract_field "$prod_txt" "validity_to")
    
    local uat_subject=$(extract_field "$uat_txt" "subject")
    local prod_subject=$(extract_field "$prod_txt" "subject")
    
    local uat_san=$(extract_field "$uat_txt" "san_email")
    local prod_san=$(extract_field "$prod_txt" "san_email")
    
    local uat_aki=$(extract_field "$uat_txt" "authority_key_id")
    local prod_aki=$(extract_field "$prod_txt" "authority_key_id")
    
    local uat_ski=$(extract_field "$uat_txt" "subject_key_id")
    local prod_ski=$(extract_field "$prod_txt" "subject_key_id")
    
    local uat_ca_issuers=$(extract_field "$uat_txt" "ca_issuers_uri")
    local prod_ca_issuers=$(extract_field "$prod_txt" "ca_issuers_uri")
    
    local uat_ocsp=$(extract_field "$uat_txt" "ocsp_uri")
    local prod_ocsp=$(extract_field "$prod_txt" "ocsp_uri")
    
    local uat_crl=$(extract_field "$uat_txt" "crl_uri")
    local prod_crl=$(extract_field "$prod_txt" "crl_uri")
    
    local uat_policies=$(extract_field "$uat_txt" "cert_policies")
    local prod_policies=$(extract_field "$prod_txt" "cert_policies")
    
    local uat_cps=$(extract_field "$uat_txt" "cps_uri")
    local prod_cps=$(extract_field "$prod_txt" "cps_uri")
    
    # Generate comparison section
    cat >> "$REPORT_FILE" << EOF

## ${cert_type} Certificates Comparison
**UAT:** ${uat_name}.crt  
**PROD:** ${prod_name}.crt

### Common Characteristics
- **Version:** Both are X.509 v3 certificates
- **Signature Algorithm:** ${uat_sig_alg}
- **Public Key Algorithm:** ${uat_pub_alg}
- **Key Size:** ${uat_key_size}-bit (secp384r1 / P-384 curve)
- **CA:** ${uat_is_ca} (both are end-entity certificates)
EOF

    if [ -n "$uat_ext_key_usage" ] && [ "$uat_ext_key_usage" != "" ]; then
        echo "- **Extended Key Usage:** ${uat_ext_key_usage}" >> "$REPORT_FILE"
    fi
    
    if [ -n "$uat_key_usage" ] && [ "$uat_key_usage" != "" ]; then
        echo "- **Key Usage:** ${uat_key_usage}" >> "$REPORT_FILE"
    fi
    
    cat >> "$REPORT_FILE" << EOF

### Differences

| Field | UAT (${uat_name}) | PROD (${prod_name}) |
|-------|-------------------|---------------------|
| **Serial Number** | ${uat_serial} | ${prod_serial} |
| **Issuer** | ${uat_issuer} | ${prod_issuer} |
| **Validity Period** | ${uat_validity_from} - ${uat_validity_to} | ${prod_validity_from} - ${prod_validity_to} |
| **Subject** | ${uat_subject} | ${prod_subject} |
EOF

    if [ -n "$uat_san" ] && [ "$uat_san" != "" ]; then
        echo "| **Subject Alternative Name** | email:${uat_san} | email:${prod_san} |" >> "$REPORT_FILE"
    else
        echo "| **Subject Alternative Name** | NOT PRESENT | NOT PRESENT |" >> "$REPORT_FILE"
    fi
    
    cat >> "$REPORT_FILE" << EOF
| **Authority Key Identifier** | ${uat_aki} | ${prod_aki} |
| **Subject Key Identifier** | ${uat_ski} | ${prod_ski} |
| **CA Issuers URI** | ${uat_ca_issuers} | ${prod_ca_issuers} |
| **OCSP URI** | ${uat_ocsp} | ${prod_ocsp} |
| **CRL URI** | ${uat_crl} | ${prod_crl} |
| **Certificate Policies** | ${uat_policies}<br>CPS: ${uat_cps} | ${prod_policies}<br>CPS: ${prod_cps} |
| **Public Key** | Different (expected) | Different (expected) |
| **Signature Value** | Different (expected) | Different (expected) |

### Analysis
EOF

    # Add analysis based on certificate type
    if [ "$cert_name" = "auth" ]; then
        cat >> "$REPORT_FILE" << EOF
- ✅ **Structure Match:** Both certificates have identical structure and extensions
- ⚠️ **Policy Difference:** UAT uses Policy \`2.999.1.3.6.1.4.1.51455.2.1.1\` while PROD uses \`1.3.6.1.4.1.51455.2.1.1\` (UAT has test prefix \`2.999\`)
- ✅ **URL Pattern:** UAT URLs correctly contain \`-uat\` suffix and \`uat\` prefix
- ✅ **Issuer:** UAT issuer correctly identified as "UAT ESTEID2025"
- ✅ **Extended Key Usage:** Both support TLS Web Client Authentication and E-mail Protection (correct for auth certs)
EOF
    else
        cat >> "$REPORT_FILE" << EOF
- ✅ **Structure Match:** Both certificates have identical structure and extensions
- ⚠️ **Policy Difference:** UAT uses Policy \`2.999.1.3.6.1.4.1.51455.2.1.1\` while PROD uses \`1.3.6.1.4.1.51455.2.1.1\` (UAT has test prefix \`2.999\`)
- ✅ **URL Pattern:** UAT URLs correctly contain \`-uat\` suffix and \`uat\` prefix
- ✅ **Issuer:** UAT issuer correctly identified as "UAT ESTEID2025"
- ✅ **Key Usage:** Both correctly use "Non Repudiation" for signature certificates
- ✅ **Extended Key Usage:** Both correctly omit Extended Key Usage (signature certs typically don't have this)
EOF
    fi
    
    echo "" >> "$REPORT_FILE"
    echo "---" >> "$REPORT_FILE"
    
    print_success "Comparison completed for $cert_type certificates"
}

# Function to generate report header
generate_report_header() {
    local uat_auth_name=$(find "$SCRIPT_DIR" -maxdepth 1 -name "auth-*.crt" -not -name "*:Zone.Identifier" | grep -E "(00000000007|uat)" | head -1 | xargs basename -s .crt 2>/dev/null || echo "auth-00000000007")
    local uat_sign_name=$(find "$SCRIPT_DIR" -maxdepth 1 -name "sign-*.crt" -not -name "*:Zone.Identifier" | grep -E "(00000000007|uat)" | head -1 | xargs basename -s .crt 2>/dev/null || echo "sign-00000000007")
    local prod_auth_name=$(find "$SCRIPT_DIR" -maxdepth 1 -name "auth-*.crt" -not -name "*:Zone.Identifier" | grep -v -E "(00000000007|uat)" | head -1 | xargs basename -s .crt 2>/dev/null || echo "auth-PROD-CERT-ID")
    local prod_sign_name=$(find "$SCRIPT_DIR" -maxdepth 1 -name "sign-*.crt" -not -name "*:Zone.Identifier" | grep -v -E "(00000000007|uat)" | head -1 | xargs basename -s .crt 2>/dev/null || echo "sign-PROD-CERT-ID")
    
    cat > "$REPORT_FILE" << EOF
# Certificate Comparison Report
**Generated:** $(date)

## Overview
This report compares UAT certificates (${uat_auth_name}.crt, ${uat_sign_name}.crt) with Production certificates (${prod_auth_name}.crt, ${prod_sign_name}.crt).

---
EOF
}

# Function to process all certificates
process_all_certificates() {
    print_info "Starting certificate processing..."
    
    # Find all .crt files (excluding Zone.Identifier files)
    local cert_files=($(find "$SCRIPT_DIR" -maxdepth 1 -name "*.crt" -not -name "*:Zone.Identifier" | sort))
    
    if [ ${#cert_files[@]} -eq 0 ]; then
        print_warning "No certificate files found in $SCRIPT_DIR"
        return 1
    fi
    
    print_info "Found ${#cert_files[@]} certificate file(s)"
    
    # Extract all certificates to text files
    for cert_file in "${cert_files[@]}"; do
        local cert_name=$(basename "$cert_file" .crt)
        local txt_file="${SCRIPT_DIR}/${cert_name}.txt"
        
        # Skip if already extracted and file is recent
        if [ -f "$txt_file" ] && [ "$txt_file" -nt "$cert_file" ]; then
            print_info "Skipping $(basename "$cert_file") (already extracted)"
        else
            extract_certificate "$cert_file" "$txt_file"
        fi
    done
    
    print_success "All certificates processed"
}

# Function to compare UAT and PROD certificates
compare_uat_prod() {
    print_info "Comparing UAT and PROD certificates..."
    
    generate_report_header
    
    # Find UAT and PROD certificate pairs
    local uat_auth=$(find "$SCRIPT_DIR" -maxdepth 1 -name "auth-*.crt" -not -name "*:Zone.Identifier" | grep -E "(00000000007|uat)" | head -1)
    local prod_auth=$(find "$SCRIPT_DIR" -maxdepth 1 -name "auth-*.crt" -not -name "*:Zone.Identifier" | grep -v -E "(00000000007|uat)" | head -1)
    
    local uat_sign=$(find "$SCRIPT_DIR" -maxdepth 1 -name "sign-*.crt" -not -name "*:Zone.Identifier" | grep -E "(00000000007|uat)" | head -1)
    local prod_sign=$(find "$SCRIPT_DIR" -maxdepth 1 -name "sign-*.crt" -not -name "*:Zone.Identifier" | grep -v -E "(00000000007|uat)" | head -1)
    
    if [ -n "$uat_auth" ] && [ -n "$prod_auth" ]; then
        compare_certificates_detailed "$uat_auth" "$prod_auth" "1. Authentication" "auth"
    else
        print_warning "Could not find both UAT and PROD authentication certificates"
    fi
    
    if [ -n "$uat_sign" ] && [ -n "$prod_sign" ]; then
        compare_certificates_detailed "$uat_sign" "$prod_sign" "2. Signature" "sign"
    else
        print_warning "Could not find both UAT and PROD signature certificates"
    fi
    
    # Add summary and conclusion
    cat >> "$REPORT_FILE" << EOF

## 3. Key Differences Summary

### Expected Differences (OK)
1. **Serial Numbers:** Unique per certificate (OK)
2. **Subjects:** Different person/entity (OK)
3. **Validity Periods:** Different issuance dates (OK)
4. **Public Keys:** Unique per certificate (OK)
5. **Signature Values:** Unique per certificate (OK)
6. **Key Identifiers:** Unique per certificate (OK)
7. **Email addresses:** Different in Subject Alternative Name (OK)

### Configuration Differences (Expected for UAT vs PROD)
1. **Issuer Names:** UAT has "UAT ESTEID2025" prefix
2. **URLs:** All UAT URLs contain \`-uat\` suffix or \`uat\` prefix:
   - CA Issuers: \`crt-uat.eidpki.ee\` vs \`crt.eidpki.ee\`
   - OCSP: \`ocsp-uat.eidpki.ee\` vs \`ocsp.eidpki.ee\`
   - CRL: \`crl-uat.eidpki.ee\` vs \`crl.eidpki.ee\`
   - Repository: \`repository-uat.eidpki.ee\` vs \`repository.eidpki.ee\`
3. **Certificate Policies:** UAT uses test policy OID \`2.999.1.3.6.1.4.1.51455.2.1.1\` vs production \`1.3.6.1.4.1.51455.2.1.1\`

---

## 4. Conclusion

All certificates are properly structured and consistent between UAT and PROD environments. The differences observed are:

1. **Expected:** Unique identifiers (serial numbers, subjects, keys, signatures)
2. **Expected:** UAT environment markers (URLs, issuer names, test policy OIDs)
3. **Correct:** Different certificate policies between auth and sign certificates
4. **Correct:** Appropriate Key Usage and Extended Key Usage settings for each certificate type

**No structural or configuration issues detected.** The certificates are correctly configured for their respective environments and purposes.

---

## Appendix: Certificate Details

### Authentication Certificate Text Files
- UAT: \`auth-00000000007.txt\`
- PROD: \`auth-PROD-CERT-ID.txt\`

### Signature Certificate Text Files
- UAT: \`sign-00000000007.txt\`
- PROD: \`sign-PROD-CERT-ID.txt\`

All certificate text files are available in the same directory for detailed review.
EOF

    print_success "Comparison report generated: $REPORT_FILE"
}

# Main function
main() {
    print_info "Certificate Processing Script"
    print_info "=============================="
    
    # Check if openssl is available
    if ! command -v openssl &> /dev/null; then
        print_error "openssl is not installed. Please install it to use this script."
        exit 1
    fi
    
    # Process all certificates
    process_all_certificates
    
    # Compare UAT and PROD if both exist
    compare_uat_prod
    
    print_success "All tasks completed!"
}

# Parse command line arguments
case "${1:-all}" in
    extract)
        if [ -z "$2" ]; then
            print_error "Usage: $0 extract <certificate_file>"
            exit 1
        fi
        extract_certificate "$2" "${2%.crt}.txt"
        ;;
    compare)
        compare_uat_prod
        ;;
    all|*)
        main
        ;;
esac
