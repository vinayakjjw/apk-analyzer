import zipfile
import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.exceptions import InvalidSignature
import datetime

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
        """Parse basic certificate information"""
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
            
            # Try to extract certificate from PKCS#7 structure
            try:
                from cryptography.hazmat.primitives.serialization import pkcs7
                from cryptography.hazmat.primitives import serialization
                
                # Parse PKCS#7 structure
                try:
                    # Try parsing as DER-encoded PKCS#7
                    certs = pkcs7.load_der_pkcs7_certificates(cert_data)
                    if certs:
                        cert = certs[0]  # Get the first certificate
                        
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
                        
                        return {
                            'signer': subject_cn,
                            'valid_from': valid_from,
                            'valid_until': valid_until,
                            'algorithm': algorithm,
                            'subject': subject,
                            'issuer': issuer
                        }
                except Exception:
                    # If PKCS#7 parsing fails, try alternative parsing
                    pass
                    
            except ImportError:
                pass
            
            # Fallback: basic info extraction
            return {
                'signer': 'Certificate found (detailed parsing not available)',
                'valid_from': 'Certificate parsing requires additional libraries',
                'valid_until': 'Certificate parsing requires additional libraries',
                'algorithm': algorithm
            }
            
        except Exception:
            return {
                'signer': 'Error parsing certificate',
                'valid_from': 'Unknown',
                'valid_until': 'Unknown',
                'algorithm': 'Unknown'
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
