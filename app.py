import streamlit as st
import os
import tempfile
from pathlib import Path
import pandas as pd
from apk_analyzer import APKAnalyzer
from comparison_utils import APKComparator
from utils import format_size, safe_get

def check_security_concerns(data):
    """Check for security concerns and return warnings"""
    concerns = []
    
    # Check for dangerous permissions
    permissions = safe_get(data, 'permissions', {}).get('declared', [])
    dangerous_perms = []
    for perm in permissions:
        if 'INTERNET' in perm.upper():
            dangerous_perms.append('Internet Access')
        elif any(x in perm.upper() for x in ['WRITE_EXTERNAL_STORAGE', 'READ_EXTERNAL_STORAGE', 'MANAGE_EXTERNAL_STORAGE']):
            dangerous_perms.append('Folder Access')
    
    if dangerous_perms:
        concerns.append(f"⚠️ **Risky Permissions**: {', '.join(dangerous_perms)}")
    
    # Check OpenGL version
    features = safe_get(data, 'features', {})
    opengl_version = features.get('opengl_version', '')
    if opengl_version and '2.0' not in opengl_version:
        concerns.append(f"⚠️ **OpenGL Version**: {opengl_version} (expected 2.0)")
    
    # Check Architecture
    architecture = safe_get(data, 'architectures', '')
    if architecture and 'armeabi-v7a' not in architecture:
        concerns.append(f"⚠️ **Architecture**: {architecture} (expected armeabi-v7a)")
    
    # Check Signature
    signature = safe_get(data, 'signature', {})
    if signature:
        valid_from = safe_get(signature, 'valid_from', '')
        signer = safe_get(signature, 'signer', '')
        sha256_digest = safe_get(signature, 'sha256_digest', '')
        
        expected_date = '2020-12-10 13:55:47 UTC'
        expected_signer = 'Avik Bhowmik'
        expected_sha256 = '9C:EC:B0:0D:53:B2:FA:05:0A:9E:91:96:3D:4F:A1:5F:53:9C:D9:8F:F1:B5:FF:E4:17:60:01:FD:7E:60:A0:7A'
        
        signature_issues = []
        if expected_date not in valid_from:
            signature_issues.append(f"date mismatch (found: {valid_from})")
        
        if expected_signer not in signer:
            signature_issues.append(f"signer mismatch (found: {signer})")
        
        # SHA-256 fingerprint verification
        if sha256_digest != 'Unknown' and sha256_digest != expected_sha256:
            signature_issues.append(f"SHA-256 mismatch (expected: {expected_sha256}, found: {sha256_digest})")
        
        if signature_issues:
            concerns.append(f"⚠️ **Signature Issue**: {', '.join(signature_issues)}")
    
    return concerns

# Configure page
st.set_page_config(
    page_title="APK Analysis Tool",
    page_icon="📱",
    layout="wide",
    initial_sidebar_state="expanded"
)

def main():
    st.title("📱 APK Analysis Tool")
    st.markdown("Upload APK files to extract metadata, permissions, features, and signature details")
    
    # Sidebar for mode selection
    with st.sidebar:
        st.header("Analysis Mode")
        mode = st.radio(
            "Choose analysis mode:",
            ["Single APK Analysis", "Batch APK Analysis", "Dual APK Comparison"],
            help="Single mode analyzes one APK, Batch mode analyzes multiple APKs, Comparison mode compares two APKs"
        )
        
        st.markdown("---")
        st.markdown("Upload APK files to get detailed analysis including permissions, features, signature verification, and security insights.")
    
    if mode == "Single APK Analysis":
        single_apk_analysis()
    elif mode == "Batch APK Analysis":
        batch_apk_analysis()
    else:
        dual_apk_comparison()

def single_apk_analysis():
    st.header("Single APK Analysis")
    
    uploaded_file = st.file_uploader(
        "Upload APK file",
        type=['apk'],
        help="Select an Android APK file for analysis"
    )
    
    if uploaded_file is not None:
        with st.spinner("Analyzing APK..."):
            try:
                # Save uploaded file temporarily
                with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as tmp_file:
                    tmp_file.write(uploaded_file.getvalue())
                    tmp_file_path = tmp_file.name
                
                # Analyze APK
                analyzer = APKAnalyzer(tmp_file_path)
                analysis_data = analyzer.analyze()
                
                # Display results
                display_apk_analysis(analysis_data, uploaded_file.name)
                
                # Cleanup
                os.unlink(tmp_file_path)
                
            except Exception as e:
                st.error(f"Error analyzing APK: {str(e)}")
                st.exception(e)

def batch_apk_analysis():
    st.header("Batch APK Analysis")
    st.markdown("Upload multiple APK files to analyze them in batch and get a comprehensive overview")
    
    # Use session state to manage file uploads and avoid pagination issues
    if 'batch_files' not in st.session_state:
        st.session_state.batch_files = []
    
    # File uploader with session state management
    uploaded_files = st.file_uploader(
        "Upload APK files",
        type=['apk'],
        accept_multiple_files=True,
        help="Select multiple Android APK files for batch analysis",
        key="batch_uploader"
    )
    
    # Update session state if new files are uploaded
    if uploaded_files:
        st.session_state.batch_files = uploaded_files
    
    # Display all uploaded files in a custom list to avoid pagination
    if st.session_state.batch_files:
        st.markdown("### 📁 Uploaded Files")
        
        # Custom file list display
        for i, file in enumerate(st.session_state.batch_files):
            col1, col2, col3 = st.columns([3, 1, 1])
            with col1:
                st.write(f"📄 {file.name}")
            with col2:
                st.write(f"{file.size / (1024*1024):.1f} MB")
            with col3:
                if st.button("❌", key=f"remove_{i}", help="Remove file"):
                    # Remove file from list
                    st.session_state.batch_files = [f for j, f in enumerate(st.session_state.batch_files) if j != i]
                    st.rerun()
        
        # Clear all files button
        if st.button("🗑️ Clear All Files"):
            st.session_state.batch_files = []
            st.rerun()
        
        # Use the files from session state for analysis
        files_to_analyze = st.session_state.batch_files
        
        st.info(f"📁 {len(files_to_analyze)} APK files ready for analysis")
        
        # Analysis options
        col1, col2 = st.columns(2)
        with col1:
            show_details = st.checkbox("Show detailed analysis for each APK", value=False)
        with col2:
            export_csv = st.checkbox("Enable CSV export", value=True)
        
        if st.button("🚀 Analyze All APKs", type="primary"):
            analyze_batch_apks(files_to_analyze, show_details, export_csv)

def analyze_batch_apks(uploaded_files, show_details, export_csv):
    """Analyze multiple APK files in batch"""
    results = []
    
    # Progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    for i, uploaded_file in enumerate(uploaded_files):
        status_text.text(f"Analyzing {uploaded_file.name}...")
        progress_bar.progress((i + 1) / len(uploaded_files))
        
        try:
            # Save uploaded file temporarily
            with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as tmp_file:
                tmp_file.write(uploaded_file.getvalue())
                tmp_file_path = tmp_file.name
            
            # Analyze APK
            analyzer = APKAnalyzer(tmp_file_path)
            analysis_data = analyzer.analyze()
            
            # Add filename to analysis data
            analysis_data['filename'] = uploaded_file.name
            analysis_data['file_size_mb'] = uploaded_file.size / (1024 * 1024)
            
            results.append(analysis_data)
            
            # Cleanup
            os.unlink(tmp_file_path)
            
        except Exception as e:
            st.error(f"Error analyzing {uploaded_file.name}: {str(e)}")
            results.append({
                'filename': uploaded_file.name,
                'error': str(e)
            })
    
    status_text.text("Analysis complete!")
    progress_bar.progress(1.0)
    
    # Display results
    display_batch_results(results, show_details, export_csv)

def display_batch_results(results, show_details, export_csv):
    """Display batch analysis results"""
    st.success(f"✅ Analyzed {len(results)} APK files")
    
    # Summary statistics
    col1, col2, col3, col4 = st.columns(4)
    
    successful_analyses = [r for r in results if 'error' not in r]
    with col1:
        st.metric("Successful Analyses", len(successful_analyses))
    
    with col2:
        if successful_analyses:
            total_size = sum(r.get('file_size', 0) for r in successful_analyses)
            st.metric("Total Size", f"{format_size(total_size)}")
        else:
            st.metric("Total Size", "0 MB")
    
    with col3:
        total_concerns = sum(len(check_security_concerns(r)) for r in successful_analyses)
        st.metric("Total Concerns", total_concerns)
    
    with col4:
        unique_packages = len(set(r.get('package_name', '') for r in successful_analyses if r.get('package_name')))
        st.metric("Unique Packages", unique_packages)
    
    # Summary table
    st.subheader("📊 Analysis Summary")
    if successful_analyses:
        summary_data = []
        for result in successful_analyses:
            concerns = check_security_concerns(result)
            summary_data.append({
                'Filename': result.get('filename', 'Unknown'),
                'App Name': safe_get(result, 'app_name', 'Unknown'),
                'Package': safe_get(result, 'package_name', 'Unknown'),
                'Version': safe_get(result, 'version_name', 'Unknown'),
                'Size': format_size(safe_get(result, 'file_size', 0)),
                'Concerns': len(concerns),
                'Architecture': safe_get(result, 'architectures', 'Unknown'),
                'Min SDK': safe_get(result, 'min_sdk_version', 'Unknown'),
                'Target SDK': safe_get(result, 'target_sdk_version', 'Unknown')
            })
        
        df = pd.DataFrame(summary_data)
        st.dataframe(df, use_container_width=True)
        
        # CSV export
        if export_csv:
            csv = df.to_csv(index=False)
            st.download_button(
                label="📥 Download Summary as CSV",
                data=csv,
                file_name="apk_batch_analysis.csv",
                mime="text/csv",
                key="batch_csv_download"
            )
    
    # Detailed analysis for each APK
    if show_details and successful_analyses:
        st.markdown("---")
        st.subheader("📱 Detailed Analysis")
        
        for i, result in enumerate(successful_analyses):
            with st.expander(f"{result.get('filename', 'Unknown')} - Detailed Analysis", expanded=False):
                # Create a unique context for each detailed analysis to avoid ID conflicts
                st.markdown(f"### {result.get('filename', 'Unknown')}")
                display_apk_analysis_batch(result, result.get('filename', 'Unknown'), i)

def display_apk_analysis_batch(data, filename, index):
    """Display APK analysis for batch mode with unique keys"""
    # Security Concerns Check
    security_concerns = check_security_concerns(data)
    if security_concerns:
        st.error("🚨 **Concerns Detected**")
        for concern in security_concerns:
            st.warning(concern)
        st.markdown("---")
    
    # App Overview with Icon
    with st.expander("📱 App Overview", expanded=True):
        # Display app icon if available
        app_icon = safe_get(data, 'app_icon', None)
        if app_icon:
            try:
                from io import BytesIO
                col_icon, col_info = st.columns([1, 4])
                with col_icon:
                    # Convert to bytes if needed, then to BytesIO for Streamlit
                    if isinstance(app_icon, str):
                        # Convert string to bytes using latin-1 encoding
                        icon_bytes = app_icon.encode('latin-1')
                        icon_stream = BytesIO(icon_bytes)
                        st.image(icon_stream, width=100, caption="App Icon")
                    elif isinstance(app_icon, bytes):
                        icon_stream = BytesIO(app_icon)
                        st.image(icon_stream, width=100, caption="App Icon")
                    else:
                        st.image(app_icon, width=100, caption="App Icon")
                with col_info:
                    st.write(f"**App Name:** {safe_get(data, 'app_name', 'Unknown')}")
                    st.write(f"**Package:** {safe_get(data, 'package_name', 'Unknown')}")
                    st.write(f"**Version:** {safe_get(data, 'version_name', 'Unknown')}")
                    st.write(f"**Build:** {safe_get(data, 'version_code', 'Unknown')}")
            except Exception as e:
                # If icon display fails, show debug info and continue without icon
                st.write(f"**App Name:** {safe_get(data, 'app_name', 'Unknown')}")
                st.write(f"**Package:** {safe_get(data, 'package_name', 'Unknown')}")
                st.write(f"**Version:** {safe_get(data, 'version_name', 'Unknown')}")
                st.write(f"**Build:** {safe_get(data, 'version_code', 'Unknown')}")
                st.info(f"📱 Icon available but couldn't display: {type(app_icon)} - {len(app_icon) if hasattr(app_icon, '__len__') else 'N/A'} bytes")
        else:
            st.write(f"**App Name:** {safe_get(data, 'app_name', 'Unknown')}")
            st.write(f"**Package:** {safe_get(data, 'package_name', 'Unknown')}")
            st.write(f"**Version:** {safe_get(data, 'version_name', 'Unknown')}")
            st.write(f"**Build:** {safe_get(data, 'version_code', 'Unknown')}")
            st.info("📱 No app icon found")
        
        st.write(f"**Min OS:** API {safe_get(data, 'min_sdk_version', 'Unknown')}")
        st.write(f"**Target OS:** API {safe_get(data, 'target_sdk_version', 'Unknown')}")
        st.write(f"**Size:** {format_size(safe_get(data, 'file_size', 0))}")
        st.write(f"**Architecture:** {safe_get(data, 'architectures', 'Unknown')}")
        st.write(f"**Debuggable:** {'Yes' if safe_get(data, 'debuggable', False) else 'No'}")
        
        # OpenGL Version in overview
        features = safe_get(data, 'features', {})
        opengl_version = features.get('opengl_version')
        if opengl_version:
            st.write(f"**Graphics:** {opengl_version}")
    
    # Permissions
    with st.expander("🔒 Permissions", expanded=False):
        permissions = safe_get(data, 'permissions', {})
        
        st.subheader("Declared Permissions")
        declared = permissions.get('declared', [])
        if declared:
            for perm in declared:
                st.write(f"• {perm}")
        else:
            st.info("No declared permissions found")
    
    # Android Manifest
    with st.expander("📄 Android Manifest XML", expanded=False):
        manifest_xml = safe_get(data, 'manifest_xml', None)
        if manifest_xml:
            # Create tabs for different viewing options
            tab1, tab2 = st.tabs(["📋 Formatted View", "💻 Raw XML"])
            
            with tab1:
                # Pretty formatted version with better readability
                try:
                    import xml.dom.minidom
                    # Parse and pretty print the XML
                    dom = xml.dom.minidom.parseString(manifest_xml)
                    pretty_xml = dom.toprettyxml(indent="  ")
                    # Remove empty lines
                    pretty_lines = [line for line in pretty_xml.split('\n') if line.strip()]
                    pretty_xml = '\n'.join(pretty_lines)
                    
                    st.code(pretty_xml, language='xml', line_numbers=True)
                except:
                    # Fallback to original if pretty printing fails
                    st.code(manifest_xml, language='xml', line_numbers=True)
            
            with tab2:
                # Raw XML in a scrollable text area
                st.text_area(
                    "Raw AndroidManifest.xml", 
                    value=manifest_xml, 
                    height=500, 
                    label_visibility="collapsed",
                    help="Raw XML content with vertical scrolling",
                    key=f"manifest_raw_{index}"
                )
                
            # Add download button with unique key
            st.download_button(
                label="📥 Download AndroidManifest.xml",
                data=manifest_xml,
                file_name=f"{safe_get(data, 'package_name', 'unknown')}_AndroidManifest.xml",
                mime="application/xml",
                key=f"manifest_download_batch_{index}"
            )
        else:
            st.warning("Android Manifest XML not available")

def dual_apk_comparison():
    st.header("Dual APK Comparison")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("First APK")
        uploaded_file1 = st.file_uploader(
            "Upload first APK file",
            type=['apk'],
            key="apk1",
            help="Select the first Android APK file for comparison"
        )
    
    with col2:
        st.subheader("Second APK")
        uploaded_file2 = st.file_uploader(
            "Upload second APK file",
            type=['apk'],
            key="apk2",
            help="Select the second Android APK file for comparison"
        )
    
    if uploaded_file1 is not None and uploaded_file2 is not None:
        with st.spinner("Analyzing and comparing APKs..."):
            try:
                # Save uploaded files temporarily
                with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as tmp_file1:
                    tmp_file1.write(uploaded_file1.getvalue())
                    tmp_file1_path = tmp_file1.name
                
                with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as tmp_file2:
                    tmp_file2.write(uploaded_file2.getvalue())
                    tmp_file2_path = tmp_file2.name
                
                # Analyze both APKs
                analyzer1 = APKAnalyzer(tmp_file1_path)
                analyzer2 = APKAnalyzer(tmp_file2_path)
                
                analysis1 = analyzer1.analyze()
                analysis2 = analyzer2.analyze()
                
                # Compare APKs
                comparator = APKComparator(analysis1, analysis2)
                comparison_data = comparator.compare()
                
                # Display comparison
                display_apk_comparison(analysis1, analysis2, comparison_data, 
                                     uploaded_file1.name, uploaded_file2.name)
                
                # Cleanup
                os.unlink(tmp_file1_path)
                os.unlink(tmp_file2_path)
                
            except Exception as e:
                st.error(f"Error comparing APKs: {str(e)}")
                st.exception(e)

def display_apk_analysis(data, filename):
    st.success(f"✅ Successfully analyzed: {filename}")
    
    # Security Concerns Check
    security_concerns = check_security_concerns(data)
    if security_concerns:
        st.error("🚨 **Concerns Detected**")
        for concern in security_concerns:
            st.warning(concern)
        st.markdown("---")
    
    # App Overview with Icon
    with st.expander("📱 App Overview", expanded=True):
        # Display app icon if available
        app_icon = safe_get(data, 'app_icon', None)
        if app_icon:
            try:
                from io import BytesIO
                col_icon, col_info = st.columns([1, 4])
                with col_icon:
                    # Convert to bytes if needed, then to BytesIO for Streamlit
                    if isinstance(app_icon, str):
                        # Convert string to bytes using latin-1 encoding
                        icon_bytes = app_icon.encode('latin-1')
                        icon_stream = BytesIO(icon_bytes)
                        st.image(icon_stream, width=100, caption="App Icon")
                    elif isinstance(app_icon, bytes):
                        icon_stream = BytesIO(app_icon)
                        st.image(icon_stream, width=100, caption="App Icon")
                    else:
                        st.image(app_icon, width=100, caption="App Icon")
                with col_info:
                    st.write(f"**App Name:** {safe_get(data, 'app_name', 'Unknown')}")
                    st.write(f"**Package:** {safe_get(data, 'package_name', 'Unknown')}")
                    st.write(f"**Version:** {safe_get(data, 'version_name', 'Unknown')}")
                    st.write(f"**Build:** {safe_get(data, 'version_code', 'Unknown')}")
            except Exception as e:
                # If icon display fails, show debug info and continue without icon
                st.write(f"**App Name:** {safe_get(data, 'app_name', 'Unknown')}")
                st.write(f"**Package:** {safe_get(data, 'package_name', 'Unknown')}")
                st.write(f"**Version:** {safe_get(data, 'version_name', 'Unknown')}")
                st.write(f"**Build:** {safe_get(data, 'version_code', 'Unknown')}")
                st.info(f"📱 Icon available but couldn't display: {type(app_icon)} - {len(app_icon) if hasattr(app_icon, '__len__') else 'N/A'} bytes")
        else:
            st.write(f"**App Name:** {safe_get(data, 'app_name', 'Unknown')}")
            st.write(f"**Package:** {safe_get(data, 'package_name', 'Unknown')}")
            st.write(f"**Version:** {safe_get(data, 'version_name', 'Unknown')}")
            st.write(f"**Build:** {safe_get(data, 'version_code', 'Unknown')}")
            st.info("📱 No app icon found")
        
        st.write(f"**Min OS:** API {safe_get(data, 'min_sdk_version', 'Unknown')}")
        st.write(f"**Target OS:** API {safe_get(data, 'target_sdk_version', 'Unknown')}")
        st.write(f"**Size:** {format_size(safe_get(data, 'file_size', 0))}")
        st.write(f"**Architecture:** {safe_get(data, 'architectures', 'Unknown')}")
        st.write(f"**Debuggable:** {'Yes' if safe_get(data, 'debuggable', False) else 'No'}")
        
        # OpenGL Version in overview
        features = safe_get(data, 'features', {})
        opengl_version = features.get('opengl_version')
        if opengl_version:
            st.write(f"**Graphics:** {opengl_version}")
    
    # Permissions
    with st.expander("🔒 Permissions", expanded=False):
        permissions = safe_get(data, 'permissions', {})
        
        st.subheader("Declared Permissions")
        declared = permissions.get('declared', [])
        if declared:
            for perm in declared:
                st.write(f"• {perm}")
        else:
            st.info("No declared permissions found")
        
        st.subheader("Implied Permissions")
        implied = permissions.get('implied', [])
        if implied:
            for perm in implied:
                st.write(f"• {perm}")
        else:
            st.info("No implied permissions found")
        
        st.subheader("Optional Permissions")
        optional = permissions.get('optional', [])
        if optional:
            for perm in optional:
                st.write(f"• {perm}")
        else:
            st.info("No optional permissions found")
    
    # Features
    with st.expander("⚡ Features", expanded=False):
        features = safe_get(data, 'features', {})
        
        st.subheader("Required Features")
        required = features.get('required', [])
        if required:
            for feat in required:
                st.write(f"• {feat}")
        else:
            st.info("No required features found")
        
        st.subheader("Implied Features")
        implied = features.get('implied', [])
        if implied:
            for feat in implied:
                st.write(f"• {feat}")
        else:
            st.info("No implied features found")
        
        st.subheader("Not Required Features")
        not_required = features.get('not_required', [])
        if not_required:
            for feat in not_required:
                st.write(f"• {feat}")
        else:
            st.info("No not-required features found")
    
    # Signature Details
    with st.expander("🔐 Signature Details", expanded=False):
        signature = safe_get(data, 'signature', {})
        
        if signature:
            st.subheader("SIGNATURE")
            
            # Basic signature information in a clean format
            signer_info = safe_get(signature, 'signer', 'Unknown')
            st.write(f"**Signer:** {signer_info}")
            st.write(f"**Valid from:** {safe_get(signature, 'valid_from', 'Unknown')}")
            st.write(f"**Valid until:** {safe_get(signature, 'valid_until', 'Unknown')}")
            st.write(f"**Algorithm:** {safe_get(signature, 'algorithm', 'Unknown')}")
            
            st.write("---")
            st.subheader("Certificate Fingerprints")
            
            # Display certificate fingerprints in a more readable format
            sha256_digest = safe_get(signature, 'sha256_digest', 'Unknown')
            sha1_digest = safe_get(signature, 'sha1_digest', 'Unknown')
            md5_digest = safe_get(signature, 'md5_digest', 'Unknown')
            
            if sha256_digest != 'Unknown':
                st.write("**SHA-256:**")
                st.code(sha256_digest, language=None)
            else:
                st.write(f"**SHA-256:** {sha256_digest}")
                
            if sha1_digest != 'Unknown':
                st.write("**SHA-1:**")
                st.code(sha1_digest, language=None)
            else:
                st.write(f"**SHA-1:** {sha1_digest}")
                
            if md5_digest != 'Unknown':
                st.write("**MD5:**")
                st.code(md5_digest, language=None)
            else:
                st.write(f"**MD5:** {md5_digest}")
            
            st.write("---")
            st.subheader("Verification Schemes")
            
            # Display verification schemes in a cleaner format
            schemes = signature.get('schemes', {})
            for scheme_name, status in schemes.items():
                status_icon = "✅" if status else "❌"
                status_text = "Verified" if status else "Not verified"
                st.write(f"{status_icon} **{scheme_name}:** {status_text}")
        else:
            st.warning("No signature information found")
    
    # Unity Export Check
    with st.expander("🎮 Unity Export Check", expanded=False):
        unity_exported = safe_get(data, 'unity_exported', None)
        if unity_exported is not None:
            if unity_exported:
                st.info("ℹ️ Unity main activity has android:exported='true'")
            else:
                st.success("✅ Unity main activity does not have android:exported='true'")
        else:
            st.info("ℹ️ No Unity main activity found or unable to determine export status")
    
    # Additional Details
    with st.expander("📋 Additional Details", expanded=False):
        st.subheader("Screen Support")
        screens = safe_get(data, 'supported_screens', [])
        if screens:
            for screen in screens:
                st.write(f"• {screen}")
        else:
            st.info("Screen support information not available")
        
        st.subheader("Density Support")
        densities = safe_get(data, 'supported_densities', [])
        if densities:
            for density in densities:
                st.write(f"• {density}")
        else:
            st.info("Density support information not available")
    
    # Android Manifest
    with st.expander("📄 Android Manifest XML", expanded=False):
        manifest_xml = safe_get(data, 'manifest_xml', None)
        if manifest_xml:
            # Create tabs for different viewing options
            tab1, tab2 = st.tabs(["📋 Formatted View", "💻 Raw XML"])
            
            with tab1:
                # Pretty formatted version with better readability
                try:
                    import xml.dom.minidom
                    # Parse and pretty print the XML
                    dom = xml.dom.minidom.parseString(manifest_xml)
                    pretty_xml = dom.toprettyxml(indent="  ")
                    # Remove empty lines
                    pretty_lines = [line for line in pretty_xml.split('\n') if line.strip()]
                    pretty_xml = '\n'.join(pretty_lines)
                    
                    st.code(pretty_xml, language='xml', line_numbers=True)
                except:
                    # Fallback to original if pretty printing fails
                    st.code(manifest_xml, language='xml', line_numbers=True)
            
            with tab2:
                # Raw XML in a scrollable text area
                st.text_area(
                    "Raw AndroidManifest.xml", 
                    value=manifest_xml, 
                    height=500, 
                    label_visibility="collapsed",
                    help="Raw XML content with vertical scrolling"
                )
                
            # Add download button
            st.download_button(
                label="📥 Download AndroidManifest.xml",
                data=manifest_xml,
                file_name="AndroidManifest.xml",
                mime="application/xml",
                key=f"manifest_download_{safe_get(data, 'package_name', 'unknown').replace('.', '_')}"
            )
        else:
            st.warning("Android Manifest XML not available")

def display_apk_comparison(data1, data2, comparison, filename1, filename2):
    st.success(f"✅ Successfully compared: {filename1} vs {filename2}")
    
    # Comparison Summary
    with st.expander("📊 Comparison Summary", expanded=True):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Identical Permissions", comparison.get('identical_permissions', 0))
        with col2:
            st.metric("Different Permissions", comparison.get('different_permissions', 0))
        with col3:
            st.metric("Signature Match", "Yes" if comparison.get('signature_match', False) else "No")
    
    # Side-by-side detailed comparison
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader(f"📱 {filename1}")
        display_apk_detailed_summary(data1)
    
    with col2:
        st.subheader(f"📱 {filename2}")
        display_apk_detailed_summary(data2)
    
    # Differences
    with st.expander("🔍 Detailed Differences", expanded=False):
        differences = comparison.get('differences', {})
        
        if differences:
            for category, diffs in differences.items():
                if diffs:
                    st.subheader(f"{category.replace('_', ' ').title()}")
                    for diff in diffs:
                        st.write(f"• {diff}")
        else:
            st.info("No significant differences found")

def display_apk_summary(data):
    st.write(f"**App Name:** {safe_get(data, 'app_name', 'Unknown')}")
    st.write(f"**Package:** {safe_get(data, 'package_name', 'Unknown')}")
    st.write(f"**Version:** {safe_get(data, 'version_name', 'Unknown')} ({safe_get(data, 'version_code', 'Unknown')})")
    st.write(f"**Min SDK:** API {safe_get(data, 'min_sdk_version', 'Unknown')}")
    st.write(f"**Target SDK:** API {safe_get(data, 'target_sdk_version', 'Unknown')}")
    st.write(f"**Size:** {format_size(safe_get(data, 'file_size', 0))}")
    st.write(f"**Debuggable:** {'Yes' if safe_get(data, 'debuggable', False) else 'No'}")
    
    permissions = safe_get(data, 'permissions', {})
    total_perms = len(permissions.get('declared', []))
    st.write(f"**Permissions:** {total_perms}")
    
    features = safe_get(data, 'features', {})
    total_features = len(features.get('required', []))
    st.write(f"**Features:** {total_features}")

def display_apk_detailed_summary(data):
    """Display detailed APK summary for comparison mode"""
    
    # Security concerns check for comparison mode
    security_concerns = check_security_concerns(data)
    if security_concerns:
        st.error("🚨 **Concerns Detected**")
        for concern in security_concerns:
            st.warning(concern)
        st.markdown("---")
    
    # App icon first
    app_icon = safe_get(data, 'app_icon', None)
    if app_icon:
        try:
            from io import BytesIO
            # Handle both string and bytes data types
            if isinstance(app_icon, str):
                icon_bytes = app_icon.encode('latin-1')
                icon_stream = BytesIO(icon_bytes)
            elif isinstance(app_icon, bytes):
                icon_stream = BytesIO(app_icon)
            else:
                icon_stream = app_icon
            st.image(icon_stream, width=80)
        except Exception as e:
            st.info(f"📱 Icon available ({type(app_icon).__name__})")
    else:
        st.info("📱 No icon")
    
    st.markdown("**Basic Information**")
    st.write(f"• **App Name:** {safe_get(data, 'app_name', 'Unknown')}")
    st.write(f"• **Package:** {safe_get(data, 'package_name', 'Unknown')}")
    st.write(f"• **Version:** {safe_get(data, 'version_name', 'Unknown')} ({safe_get(data, 'version_code', 'Unknown')})")
    st.write(f"• **Min SDK:** API {safe_get(data, 'min_sdk_version', 'Unknown')}")
    st.write(f"• **Target SDK:** API {safe_get(data, 'target_sdk_version', 'Unknown')}")
    st.write(f"• **Size:** {format_size(safe_get(data, 'file_size', 0))}")
    st.write(f"• **Architecture:** {safe_get(data, 'architectures', 'Unknown')}")
    st.write(f"• **Debuggable:** {'Yes' if safe_get(data, 'debuggable', False) else 'No'}")
    
    # OpenGL Version
    features = safe_get(data, 'features', {})
    opengl_version = features.get('opengl_version')
    if opengl_version:
        st.write(f"• **Graphics:** {opengl_version}")
    
    
    st.markdown("**Permissions** (showing first 8)")
    permissions = safe_get(data, 'permissions', {})
    declared = permissions.get('declared', [])
    if declared:
        for perm in declared[:8]:  # Show first 8
            clean_perm = perm.replace('android.permission.', '')
            st.write(f"• {clean_perm}")
        if len(declared) > 8:
            st.write(f"• ... and {len(declared) - 8} more")
    else:
        st.write("• No permissions declared")

if __name__ == "__main__":
    main()
