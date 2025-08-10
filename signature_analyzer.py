import zipfile
import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.exceptions import InvalidSignature
import datetime
import hashlib

class SignatureAnalyzer:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        
    def analyze(self):
        """Analyze APK signature and certificate details"""
        try:
            signature_data = {
                'signer': 'Unknown',
                'valid_from': 'Unknown',
                'valid_until': 'Unknown',
                'algorithm': 'Unknown',
                'sha256_digest': 'Unknown',
                'sha1_digest': 'Unknown',
                'md5_digest': 'Unknown',
                'schemes': {
                    'v1 (JAR signing)': False,
                    'v2 (APK Signature Scheme v2)': False,
                    'v3 (APK Signature Scheme v3)': False,
                    'v3.1 (APK Signature Scheme v3.1)': False,
                    'v4 (APK Signature Scheme v4)': False
                }
            }
            
            # Extract certificate from META-INF
            cert_data = self._extract_certificate()
            if cert_data:
                signature_data.update(cert_data)
            
            # Check signature schemes
            signature_data['schemes'] = self._check_signature_schemes()
            
            return signature_data
            
        except Exception as e:
            return {'error': str(e)}
    
    def _extract_certificate(self):
        """Extract certificate from APK's META-INF directory"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                # Look for certificate files
                cert_files = [f for f in z.namelist() if f.startswith('META-INF/') and 
                            (f.endswith('.RSA') or f.endswith('.DSA') or f.endswith('.EC'))]
                
                if not cert_files:
                    return None
                
                # Read the first certificate file
                cert_file = cert_files[0]
                cert_data = z.read(cert_file)
                
                # Parse the certificate (PKCS#7 format)
                try:
                    # Try to extract certificate from PKCS#7
                    from cryptography.hazmat.primitives.serialization import pkcs7
                    
                    # This is a simplified approach - real PKCS#7 parsing would be more complex
                    # For now, we'll extract basic information
                    return self._parse_certificate_basic_info(cert_data, cert_file)
                    
                except Exception:
                    # Fallback to basic parsing
                    return self._parse_certificate_basic_info(cert_data, cert_file)
                    
        except Exception:
            return None
    
    def _parse_certificate_basic_info(self, cert_data, filename):
        """Parse basic certificate information with improved PKCS#7 handling"""
        try:
            # Extract algorithm from filename
            if filename.endswith('.RSA'):
                algorithm = 'RSA with SHA-256'
            elif filename.endswith('.DSA'):
                algorithm = 'DSA with SHA-1'
            elif filename.endswith('.EC'):
                algorithm = 'ECDSA with SHA-256'
            else:
                algorithm = 'Unknown'
            
            # Try multiple approaches to extract certificate
            cert = None
            
            # Approach 1: Try PKCS#7 parsing
            try:
                from cryptography.hazmat.primitives.serialization import pkcs7
                from cryptography.hazmat.primitives import serialization
                
                # Try parsing as DER-encoded PKCS#7
                certs = pkcs7.load_der_pkcs7_certificates(cert_data)
                if certs and len(certs) > 0:
                    cert = certs[0]
            except Exception as e:
                # PKCS#7 parsing failed, try other approaches
                pass
            
            # Approach 2: Try parsing as raw X.509 certificate (sometimes certificates are embedded)
            if cert is None:
                try:
                    from cryptography import x509
                    from cryptography.hazmat.primitives import serialization
                    
                    # Look for DER-encoded certificate in the data
                    # Sometimes the certificate is embedded in the PKCS#7 structure
                    # Try to find certificate markers in the binary data
                    
                    # Search for ASN.1 certificate sequence starting bytes
                    for i in range(len(cert_data) - 4):
                        # Look for certificate sequence (0x30 followed by length)
                        if cert_data[i:i+2] == b'\x30\x82':
                            try:
                                # Try parsing from this position
                                remaining_data = cert_data[i:]
                                cert = x509.load_der_x509_certificate(remaining_data)
                                break
                            except:
                                continue
                        elif cert_data[i:i+2] == b'\x30\x81':
                            try:
                                # Try parsing from this position (shorter length encoding)
                                remaining_data = cert_data[i:]
                                cert = x509.load_der_x509_certificate(remaining_data)
                                break
                            except:
                                continue
                except Exception:
                    pass
            
            # If we successfully extracted a certificate, get its details
            if cert is not None:
                try:
                    from cryptography.hazmat.primitives import serialization
                    
                    # Extract certificate details
                    subject = cert.subject.rfc4514_string()
                    issuer = cert.issuer.rfc4514_string()
                    valid_from = cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S UTC')
                    valid_until = cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S UTC')
                    
                    # Extract CN from subject
                    subject_cn = "Unknown"
                    for attribute in cert.subject:
                        if attribute.oid._name == 'commonName':
                            subject_cn = attribute.value
                            break
                    
                    # Calculate certificate fingerprints
                    try:
                        cert_der = cert.public_bytes(serialization.Encoding.DER)
                        sha256_digest = hashlib.sha256(cert_der).hexdigest()
                        sha1_digest = hashlib.sha1(cert_der).hexdigest()
                        md5_digest = hashlib.md5(cert_der).hexdigest()
                        
                        # Format fingerprints with colons for readability
                        sha256_formatted = ':'.join(sha256_digest[i:i+2] for i in range(0, len(sha256_digest), 2)).upper()
                        sha1_formatted = ':'.join(sha1_digest[i:i+2] for i in range(0, len(sha1_digest), 2)).upper()
                        md5_formatted = ':'.join(md5_digest[i:i+2] for i in range(0, len(md5_digest), 2)).upper()
                    except Exception as fingerprint_error:
                        # If fingerprint calculation fails, set to debug info
                        sha256_formatted = f"Fingerprint calculation failed: {str(fingerprint_error)}"
                        sha1_formatted = "Fingerprint calculation failed"
                        md5_formatted = "Fingerprint calculation failed"
                    
                    return {
                        'signer': subject_cn,
                        'valid_from': valid_from,
                        'valid_until': valid_until,
                        'algorithm': algorithm,
                        'subject': subject,
                        'issuer': issuer,
                        'sha256_digest': sha256_formatted,
                        'sha1_digest': sha1_formatted,
                        'md5_digest': md5_formatted
                    }
                except Exception as cert_error:
                    # Debug: capture what went wrong
                    sha256_formatted = f"Cert extraction failed: {str(cert_error)}"
                    sha1_formatted = "Cert extraction failed"
                    md5_formatted = "Cert extraction failed"
                    
                    return {
                        'signer': subject_cn if 'subject_cn' in locals() else 'Cert extracted but fingerprint failed',
                        'valid_from': valid_from if 'valid_from' in locals() else 'Unknown',
                        'valid_until': valid_until if 'valid_until' in locals() else 'Unknown',
                        'algorithm': algorithm,
                        'subject': subject if 'subject' in locals() else 'Unknown',
                        'issuer': issuer if 'issuer' in locals() else 'Unknown',
                        'sha256_digest': sha256_formatted,
                        'sha1_digest': sha1_formatted,
                        'md5_digest': md5_formatted
                    }
            
            # Fallback: basic info with certificate file hash if no certificate could be extracted
            # Calculate hash of the certificate file itself as a fallback
            try:
                sha256_file = hashlib.sha256(cert_data).hexdigest()
                sha1_file = hashlib.sha1(cert_data).hexdigest()
                md5_file = hashlib.md5(cert_data).hexdigest()
                
                sha256_formatted = ':'.join(sha256_file[i:i+2] for i in range(0, len(sha256_file), 2)).upper()
                sha1_formatted = ':'.join(sha1_file[i:i+2] for i in range(0, len(sha1_file), 2)).upper()
                md5_formatted = ':'.join(md5_file[i:i+2] for i in range(0, len(md5_file), 2)).upper()
                
                return {
                    'signer': 'Certificate parsing failed - using file hash',
                    'valid_from': 'Unknown',
                    'valid_until': 'Unknown',
                    'algorithm': algorithm,
                    'sha256_digest': sha256_formatted + ' (file hash)',
                    'sha1_digest': sha1_formatted + ' (file hash)',
                    'md5_digest': md5_formatted + ' (file hash)'
                }
            except Exception:
                pass
            
            # Final fallback
            return {
                'signer': 'Certificate found but parsing failed',
                'valid_from': 'Unknown',
                'valid_until': 'Unknown',
                'algorithm': algorithm,
                'sha256_digest': 'Unknown',
                'sha1_digest': 'Unknown',
                'md5_digest': 'Unknown'
            }
            
        except Exception:
            return {
                'signer': 'Error parsing certificate',
                'valid_from': 'Unknown',
                'valid_until': 'Unknown',
                'algorithm': 'Unknown',
                'sha256_digest': 'Unknown',
                'sha1_digest': 'Unknown',
                'md5_digest': 'Unknown'
            }
    
    def _check_signature_schemes(self):
        """Check which APK signature schemes are used"""
        schemes = {
            'v1 (JAR signing)': False,
            'v2 (APK Signature Scheme v2)': False,
            'v3 (APK Signature Scheme v3)': False,
            'v3.1 (APK Signature Scheme v3.1)': False,
            'v4 (APK Signature Scheme v4)': False
        }
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                # Check for v1 signature (JAR signing)
                meta_inf_files = [f for f in z.namelist() if f.startswith('META-INF/')]
                has_manifest = any(f.endswith('MANIFEST.MF') for f in meta_inf_files)
                has_cert = any(f.endswith(('.RSA', '.DSA', '.EC')) for f in meta_inf_files)
                
                if has_manifest and has_cert:
                    schemes['v1 (JAR signing)'] = True
            
            # Check for v2/v3/v4 signatures by examining the APK structure
            # These would require parsing the APK Signing Block
            schemes.update(self._check_apk_signing_block())
            
        except Exception:
            pass
        
        return schemes
    
    def _check_apk_signing_block(self):
        """Check for APK Signing Block (v2, v3, v4 signatures)"""
        schemes = {
            'v2 (APK Signature Scheme v2)': False,
            'v3 (APK Signature Scheme v3)': False,
            'v3.1 (APK Signature Scheme v3.1)': False,
            'v4 (APK Signature Scheme v4)': False
        }
        
        try:
            with open(self.apk_path, 'rb') as f:
                # Read the end of the file to look for APK Signing Block
                f.seek(-1024, 2)  # Go to near the end
                data = f.read()
                
                # Look for APK Signature Block magic
                if b'APK Sig Block 42' in data:
                    # This is a very basic check - real implementation would parse the block
                    schemes['v2 (APK Signature Scheme v2)'] = True
                    
                    # Check for newer scheme indicators
                    # This is simplified - real parsing would be more complex
                    if b'\x03\x01\x00\x00' in data:  # v3 indicator (simplified)
                        schemes['v3 (APK Signature Scheme v3)'] = True
                        
        except Exception:
            pass
            
        return schemes
    
    def get_certificate_details_advanced(self, cert_data):
        """Advanced certificate parsing (if needed)"""
        try:
            # This would implement full PKCS#7/certificate parsing
            # For now, returning basic structure
            return {
                'subject': 'CN=Unknown',
                'issuer': 'CN=Unknown',
                'serial_number': 'Unknown',
                'fingerprint_sha1': 'Unknown',
                'fingerprint_sha256': 'Unknown',
                'public_key_algorithm': 'Unknown',
                'signature_algorithm': 'Unknown'
            }
        except Exception:
            return {}
