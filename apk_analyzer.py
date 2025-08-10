import os
import zipfile
import xml.etree.ElementTree as ET
from androguard.core.apk import APK
from signature_analyzer import SignatureAnalyzer
import re

class APKAnalyzer:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.apk_obj = None
        self.file_size = os.path.getsize(apk_path)
        
    def analyze(self):
        """Perform comprehensive APK analysis"""
        try:
            self.apk_obj = APK(self.apk_path)
            
            analysis_data = {
                'file_size': self.file_size,
                'app_name': self._get_app_name(),
                'package_name': self._get_package_name(),
                'version_name': self._get_version_name(),
                'version_code': self._get_version_code(),
                'min_sdk_version': self._get_min_sdk_version(),
                'target_sdk_version': self._get_target_sdk_version(),
                'debuggable': self._is_debuggable(),
                'architectures': self._get_architectures(),
                'supported_screens': self._get_supported_screens(),
                'supported_densities': self._get_supported_densities(),
                'permissions': self._analyze_permissions(),
                'features': self._analyze_features(),
                'signature': self._analyze_signature(),
                'unity_exported': self._check_unity_exported(),
                'activities': self._get_activities(),
                'services': self._get_services(),
                'receivers': self._get_receivers(),
                'providers': self._get_providers(),
                'app_icon': self._get_app_icon(),
                'manifest_xml': self._get_manifest_xml()
            }
            
            return analysis_data
            
        except Exception as e:
            raise Exception(f"Failed to analyze APK: {str(e)}")
    
    def _get_app_name(self):
        """Extract application name"""
        try:
            return self.apk_obj.get_app_name() or "Unknown"
        except:
            return "Unknown"
    
    def _get_package_name(self):
        """Extract package name"""
        try:
            return self.apk_obj.get_package() or "Unknown"
        except:
            return "Unknown"
    
    def _get_version_name(self):
        """Extract version name"""
        try:
            return self.apk_obj.get_androidversion_name() or "Unknown"
        except:
            return "Unknown"
    
    def _get_version_code(self):
        """Extract version code"""
        try:
            return self.apk_obj.get_androidversion_code() or "Unknown"
        except:
            return "Unknown"
    
    def _get_min_sdk_version(self):
        """Extract minimum SDK version"""
        try:
            return self.apk_obj.get_min_sdk_version() or "Unknown"
        except:
            return "Unknown"
    
    def _get_target_sdk_version(self):
        """Extract target SDK version"""
        try:
            return self.apk_obj.get_target_sdk_version() or "Unknown"
        except:
            return "Unknown"
    
    def _is_debuggable(self):
        """Check if application is debuggable"""
        try:
            manifest = self.apk_obj.get_android_manifest_xml()
            for elem in manifest.iter():
                if elem.tag == 'application':
                    debuggable = elem.get('{http://schemas.android.com/apk/res/android}debuggable')
                    return debuggable == 'true'
            return False
        except:
            return False
    
    def _get_architectures(self):
        """Extract supported architectures"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                files = z.namelist()
                architectures = set()
                
                for file in files:
                    if file.startswith('lib/'):
                        parts = file.split('/')
                        if len(parts) >= 2:
                            arch = parts[1]
                            if arch in ['arm64-v8a', 'armeabi-v7a', 'armeabi', 'x86', 'x86_64', 'mips', 'mips64']:
                                architectures.add(arch)
                
                return ', '.join(sorted(architectures)) if architectures else "Universal"
        except:
            return "Unknown"
    
    def _get_supported_screens(self):
        """Extract supported screen sizes"""
        try:
            manifest = self.apk_obj.get_android_manifest_xml()
            screens = []
            
            for elem in manifest.iter():
                if elem.tag == 'supports-screens':
                    for attr, value in elem.attrib.items():
                        if value == 'true':
                            screen_type = attr.split('}')[-1] if '}' in attr else attr
                            screens.append(screen_type)
            
            return screens if screens else ["All screens (default)"]
        except:
            return []
    
    def _get_supported_densities(self):
        """Extract supported screen densities"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                files = z.namelist()
                densities = set()
                
                density_folders = ['ldpi', 'mdpi', 'hdpi', 'xhdpi', 'xxhdpi', 'xxxhdpi', 'tvdpi', 'nodpi']
                
                for file in files:
                    for density in density_folders:
                        if f'drawable-{density}/' in file or f'mipmap-{density}/' in file:
                            densities.add(density)
                
                return sorted(densities) if densities else ["All densities"]
        except:
            return []
    
    def _analyze_permissions(self):
        """Analyze all types of permissions"""
        try:
            declared = self.apk_obj.get_declared_permissions() or []
            
            # Get implied permissions (basic analysis)
            implied = self._get_implied_permissions()
            
            # Get optional permissions
            optional = self._get_optional_permissions()
            
            return {
                'declared': declared,
                'implied': implied,
                'optional': optional
            }
        except:
            return {'declared': [], 'implied': [], 'optional': []}
    
    def _get_implied_permissions(self):
        """Get permissions that are implied by other permissions or features"""
        implied = []
        try:
            permissions = self.apk_obj.get_declared_permissions() or []
            
            # Some basic implied permission rules
            if 'android.permission.WRITE_EXTERNAL_STORAGE' in permissions:
                implied.append('android.permission.READ_EXTERNAL_STORAGE')
            
            if 'android.permission.ACCESS_FINE_LOCATION' in permissions:
                implied.append('android.permission.ACCESS_COARSE_LOCATION')
                
        except:
            pass
        return implied
    
    def _get_optional_permissions(self):
        """Get optional permissions from manifest"""
        optional = []
        try:
            manifest = self.apk_obj.get_android_manifest_xml()
            
            for elem in manifest.iter():
                if elem.tag == 'uses-permission':
                    required = elem.get('{http://schemas.android.com/apk/res/android}required')
                    if required == 'false':
                        name = elem.get('{http://schemas.android.com/apk/res/android}name')
                        if name:
                            optional.append(name)
        except:
            pass
        return optional
    
    def _analyze_features(self):
        """Analyze required, implied, and not-required features"""
        try:
            required = []
            implied = []
            not_required = []
            opengl_version = None
            
            manifest = self.apk_obj.get_android_manifest_xml()
            
            for elem in manifest.iter():
                if elem.tag == 'uses-feature':
                    name = elem.get('{http://schemas.android.com/apk/res/android}name')
                    required_attr = elem.get('{http://schemas.android.com/apk/res/android}required')
                    gl_es_version = elem.get('{http://schemas.android.com/apk/res/android}glEsVersion')
                    
                    if name:
                        if required_attr == 'false':
                            not_required.append(name)
                        else:
                            required.append(name)
                    
                    # Extract OpenGL ES version
                    if gl_es_version:
                        try:
                            # Convert hex version to readable format
                            version_int = int(gl_es_version, 16) if gl_es_version.startswith('0x') else int(gl_es_version)
                            major = (version_int >> 16) & 0xFFFF
                            minor = version_int & 0xFFFF
                            opengl_version = f"OpenGL ES {major}.{minor}"
                        except:
                            opengl_version = f"OpenGL ES (version: {gl_es_version})"
            
            # Get implied features based on permissions
            implied = self._get_implied_features()
            
            return {
                'required': required,
                'implied': implied,
                'not_required': not_required,
                'opengl_version': opengl_version
            }
        except:
            return {'required': [], 'implied': [], 'not_required': [], 'opengl_version': None}
    
    def _get_implied_features(self):
        """Get features that are implied by permissions"""
        implied = []
        try:
            permissions = self.apk_obj.get_declared_permissions() or []
            
            # Basic implied feature mappings
            feature_mappings = {
                'android.permission.CAMERA': 'android.hardware.camera',
                'android.permission.ACCESS_FINE_LOCATION': 'android.hardware.location.gps',
                'android.permission.ACCESS_COARSE_LOCATION': 'android.hardware.location.network',
                'android.permission.RECORD_AUDIO': 'android.hardware.microphone',
                'android.permission.BLUETOOTH': 'android.hardware.bluetooth',
                'android.permission.BLUETOOTH_ADMIN': 'android.hardware.bluetooth',
                'android.permission.ACCESS_WIFI_STATE': 'android.hardware.wifi',
                'android.permission.CHANGE_WIFI_STATE': 'android.hardware.wifi',
            }
            
            for perm in permissions:
                if perm in feature_mappings:
                    feature = feature_mappings[perm]
                    if feature not in implied:
                        implied.append(feature)
                        
        except:
            pass
        return implied
    
    def _analyze_signature(self):
        """Analyze APK signature"""
        try:
            # Try to use androguard's built-in certificate methods first
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
            
            # Use androguard's certificate methods with proper error handling
            try:
                # Try to get certificates using different methods
                cert_der = None
                try:
                    cert_der = self.apk_obj.get_certificate_der(0)
                except:
                    try:
                        # Alternative method
                        certs_der = self.apk_obj.get_certificates_der_v2()
                        if certs_der:
                            cert_der = certs_der[0]
                    except:
                        try:
                            # V1 method
                            certs_v1 = self.apk_obj.get_certificates_v1()
                            if certs_v1:
                                cert_der = certs_v1[0]
                        except:
                            pass

                if cert_der:
                    from cryptography import x509
                    cert = x509.load_der_x509_certificate(cert_der)
                    
                    # Extract certificate information
                    subject = cert.subject.rfc4514_string()
                    # Use UTC timezone-aware methods to avoid deprecation warnings
                    try:
                        valid_from = cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S UTC')
                        valid_until = cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC')
                    except AttributeError:
                        # Fallback for older cryptography versions
                        valid_from = cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S UTC')
                        valid_until = cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S UTC')
                    
                    # Extract CN from subject
                    subject_cn = "Unknown"
                    try:
                        for attribute in cert.subject:
                            if attribute.oid._name == 'commonName':
                                subject_cn = attribute.value
                                break
                    except:
                        # Try alternative extraction
                        subject_parts = subject.split(',')
                        for part in subject_parts:
                            if 'CN=' in part:
                                subject_cn = part.split('CN=')[1].strip()
                                break
                    
                    # Get algorithm name
                    try:
                        algo_name = cert.signature_algorithm_oid._name
                        if 'sha256' in algo_name.lower():
                            if 'rsa' in algo_name.lower():
                                algorithm = 'RSA with SHA-256'
                            elif 'ecdsa' in algo_name.lower():
                                algorithm = 'ECDSA with SHA-256'
                            else:
                                algorithm = algo_name
                        else:
                            algorithm = algo_name
                    except:
                        algorithm = "Unknown"
                    
                    signature_data.update({
                        'signer': subject,  # Use full subject for detailed display
                        'signer_cn': subject_cn,  # Keep CN for simple display
                        'valid_from': valid_from,
                        'valid_until': valid_until,
                        'algorithm': algorithm,
                        'subject': subject
                    })
                        
            except Exception as cert_error:
                # Log error for debugging but continue
                print(f"Certificate parsing error: {cert_error}")
                # Try to get basic signature info without certificate details
                try:
                    sig_names = self.apk_obj.get_signature_names()
                    if sig_names:
                        signature_data['signer'] = f"Certificate: {sig_names[0]}"
                except:
                    pass
            
            # Check signature schemes using androguard methods
            try:
                signature_data['schemes']['v1 (JAR signing)'] = self.apk_obj.is_signed_v1()
                signature_data['schemes']['v2 (APK Signature Scheme v2)'] = self.apk_obj.is_signed_v2()
                signature_data['schemes']['v3 (APK Signature Scheme v3)'] = self.apk_obj.is_signed_v3()
            except Exception:
                # If androguard methods fail, use fallback analyzer
                signature_analyzer = SignatureAnalyzer(self.apk_path)
                fallback_data = signature_analyzer.analyze()
                if 'schemes' in fallback_data:
                    signature_data['schemes'] = fallback_data['schemes']
            
            return signature_data
            
        except Exception as e:
            # Complete fallback to signature analyzer
            try:
                signature_analyzer = SignatureAnalyzer(self.apk_path)
                return signature_analyzer.analyze()
            except:
                return {'error': str(e)}
    
    def _check_unity_exported(self):
        """Check if Unity main activity has android:exported='true'"""
        try:
            manifest = self.apk_obj.get_android_manifest_xml()
            
            for activity in manifest.iter('activity'):
                name = activity.get('{http://schemas.android.com/apk/res/android}name')
                
                # Check for Unity activity patterns
                if name and ('UnityPlayerActivity' in name or 'MainActivity' in name):
                    # Check if this looks like a Unity app
                    if self._is_unity_app():
                        exported = activity.get('{http://schemas.android.com/apk/res/android}exported')
                        return exported == 'true'
            
            return None  # Not a Unity app or activity not found
        except:
            return None
    
    def _is_unity_app(self):
        """Check if this is a Unity application"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                files = z.namelist()
                
                # Look for Unity-specific files
                unity_indicators = [
                    'assets/bin/Data/unity default resources',
                    'lib/armeabi-v7a/libunity.so',
                    'lib/arm64-v8a/libunity.so',
                    'assets/bin/Data/globalgamemanagers',
                    'assets/bin/Data/level0'
                ]
                
                for indicator in unity_indicators:
                    if indicator in files:
                        return True
                        
                # Also check for libunity.so in any architecture
                for file in files:
                    if 'libunity.so' in file:
                        return True
                        
                return False
        except:
            return False
    
    def _get_activities(self):
        """Get list of activities"""
        try:
            activities = []
            manifest = self.apk_obj.get_android_manifest_xml()
            
            for activity in manifest.iter('activity'):
                name = activity.get('{http://schemas.android.com/apk/res/android}name')
                if name:
                    activities.append(name)
            
            return activities
        except:
            return []
    
    def _get_services(self):
        """Get list of services"""
        try:
            services = []
            manifest = self.apk_obj.get_android_manifest_xml()
            
            for service in manifest.iter('service'):
                name = service.get('{http://schemas.android.com/apk/res/android}name')
                if name:
                    services.append(name)
            
            return services
        except:
            return []
    
    def _get_receivers(self):
        """Get list of broadcast receivers"""
        try:
            receivers = []
            manifest = self.apk_obj.get_android_manifest_xml()
            
            for receiver in manifest.iter('receiver'):
                name = receiver.get('{http://schemas.android.com/apk/res/android}name')
                if name:
                    receivers.append(name)
            
            return receivers
        except:
            return []
    
    def _get_providers(self):
        """Get list of content providers"""
        try:
            providers = []
            manifest = self.apk_obj.get_android_manifest_xml()
            
            for provider in manifest.iter('provider'):
                name = provider.get('{http://schemas.android.com/apk/res/android}name')
                if name:
                    providers.append(name)
            
            return providers
        except:
            return []
    
    def _get_app_icon(self):
        """Extract app icon"""
        try:
            # Method 1: Use androguard's built-in method
            try:
                icon_data = self.apk_obj.get_app_icon()
                if icon_data:
                    return icon_data
            except:
                pass
            
            # Method 2: Manual extraction from common icon locations
            try:
                with zipfile.ZipFile(self.apk_path, 'r') as z:
                    # Common icon paths in order of preference (highest density first)
                    icon_paths = [
                        'res/mipmap-xxxhdpi/ic_launcher.png',
                        'res/mipmap-xxhdpi/ic_launcher.png', 
                        'res/mipmap-xhdpi/ic_launcher.png',
                        'res/mipmap-hdpi/ic_launcher.png',
                        'res/mipmap-mdpi/ic_launcher.png',
                        'res/mipmap-ldpi/ic_launcher.png',
                        'res/drawable-xxxhdpi/ic_launcher.png',
                        'res/drawable-xxhdpi/ic_launcher.png',
                        'res/drawable-xhdpi/ic_launcher.png',
                        'res/drawable-hdpi/ic_launcher.png',
                        'res/drawable-mdpi/ic_launcher.png',
                        'res/drawable-ldpi/ic_launcher.png'
                    ]
                    
                    # Try each common path
                    for icon_path in icon_paths:
                        if icon_path in z.namelist():
                            return z.read(icon_path)
                    
                    # Search for any launcher icon file
                    for file in z.namelist():
                        if ('ic_launcher' in file or 'launcher' in file) and file.endswith(('.png', '.jpg', '.jpeg', '.webp')):
                            return z.read(file)
                    
                    # Fallback: search for any icon file
                    for file in z.namelist():
                        if 'icon' in file.lower() and file.endswith(('.png', '.jpg', '.jpeg', '.webp')):
                            return z.read(file)
            except:
                pass
                
            return None
        except:
            return None
    
    def _get_manifest_xml(self):
        """Get formatted Android Manifest XML"""
        try:
            # Method 1: Try androguard's direct XML conversion
            try:
                manifest_xml = self.apk_obj.get_android_manifest_xml()
                if manifest_xml is not None:
                    import xml.etree.ElementTree as ET
                    
                    # Add proper indentation for readability
                    def indent(elem, level=0):
                        i = "\n" + level*"  "
                        if len(elem):
                            if not elem.text or not elem.text.strip():
                                elem.text = i + "  "
                            if not elem.tail or not elem.tail.strip():
                                elem.tail = i
                            for child in elem:
                                indent(child, level+1)
                            if not elem.tail or not elem.tail.strip():
                                elem.tail = i
                        else:
                            if level and (not elem.tail or not elem.tail.strip()):
                                elem.tail = i
                    
                    # Handle both cases: root element or tree object
                    if hasattr(manifest_xml, 'getroot'):
                        root = manifest_xml.getroot()
                    else:
                        root = manifest_xml
                    
                    indent(root)
                    xml_string = ET.tostring(root, encoding='unicode', method='xml')
                    
                    # Add XML declaration
                    if not xml_string.startswith('<?xml'):
                        xml_string = '<?xml version="1.0" encoding="utf-8"?>\n' + xml_string
                    
                    return xml_string
            except Exception as e1:
                print(f"Method 1 failed: {e1}")
                pass
            
            # Method 2: Use androguard's get_xml() method
            try:
                manifest_data = self.apk_obj.get_android_manifest_axml()
                if manifest_data:
                    xml_content = manifest_data.get_xml()
                    if xml_content:
                        return xml_content
            except Exception as e2:
                print(f"Method 2 failed: {e2}")
                pass
            
            # Method 3: Direct AXML parsing
            try:
                from androguard.core.axml import AXML
                with zipfile.ZipFile(self.apk_path, 'r') as z:
                    if 'AndroidManifest.xml' in z.namelist():
                        manifest_bytes = z.read('AndroidManifest.xml')
                        axml = AXML(manifest_bytes)
                        xml_content = axml.get_xml()
                        if xml_content:
                            return xml_content
            except Exception as e3:
                print(f"Method 3 failed: {e3}")
                pass
            
            # Method 4: Try alternative androguard methods
            try:
                # Sometimes the XML needs to be accessed differently
                manifest_content = str(self.apk_obj.get_android_manifest_xml())
                if manifest_content and manifest_content != 'None':
                    return manifest_content
            except Exception as e4:
                print(f"Method 4 failed: {e4}")
                pass
                
            return "AndroidManifest.xml found but parsing failed. The file is in binary AXML format."
            
        except Exception as e:
            print(f"Manifest XML extraction error: {e}")
            return None
