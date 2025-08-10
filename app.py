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
        
        expected_date = '2020-12-10 13:55:47 UTC'
        expected_signer = 'Avik Bhowmik'
        
        signature_issues = []
        if expected_date not in valid_from:
            signature_issues.append(f"date mismatch (found: {valid_from})")
        
        if expected_signer not in signer:
            signature_issues.append(f"signer mismatch (found: {signer})")
        
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
    
    # Configure to show all files on one page
    st.markdown("""
    <style>
    /* Remove pagination and show all uploaded files */
    div[data-testid="stFileUploader"] {
        --uploaded-file-list-max-height: none !important;
    }
    div[data-testid="stFileUploader"] > div > div > div {
        max-height: none !important;
        overflow: visible !important;
    }
    div[data-testid="stFileUploader"] .uploadedFiles {
        max-height: none !important;
        overflow: visible !important;
    }
    div[data-testid="stFileUploader"] .uploadedFile {
        display: block !important;
    }
    /* Hide pagination controls */
    div[data-testid="stFileUploader"] button[kind="secondary"] {
        display: none !important;
    }
    div[data-testid="stFileUploader"] .stSpinner {
        display: none !important;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Use a container to better control the file uploader
    with st.container():
        uploaded_files = st.file_uploader(
            "Upload APK files",
            type=['apk'],
            accept_multiple_files=True,
            help="Select multiple Android APK files for batch analysis"
        )
        
        # Additional CSS to ensure no pagination
        if uploaded_files:
            st.markdown("""
            <style>
            /* Force display all files without pagination */
            section[data-testid="stFileUploader"] div[data-testid="stFileUploaderDropzone"] + div {
                max-height: none !important;
            }
            section[data-testid="stFileUploader"] [data-testid="stFileUploaderFileList"] {
                max-height: none !important;
                overflow-y: visible !important;
            }
            /* Hide page navigation if it exists */
            section[data-testid="stFileUploader"] button[aria-label*="page"] {
                display: none !important;
            }
            section[data-testid="stFileUploader"] span:contains("Showing page") {
                display: none !important;
            }
            </style>
            """, unsafe_allow_html=True)
    
    if uploaded_files:
        st.info(f"📁 {len(uploaded_files)} APK files uploaded")
        
        # Analysis options
        col1, col2 = st.columns(2)
        with col1:
            show_details = st.checkbox("Show detailed analysis for each APK", value=False)
        with col2:
            export_csv = st.checkbox("Enable CSV export", value=True)
        
        if st.button("🚀 Analyze All APKs", type="primary"):
            analyze_batch_apks(uploaded_files, show_details, export_csv)

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
            
            # Create a table-like display for signature information
            col1, col2 = st.columns([1, 2])
            
            with col1:
                st.write("**Signer**")
                st.write("**Valid from**")
                st.write("**Valid until**") 
                st.write("**Algorithm**")
                st.write("")
                
                # Verification schemes
                schemes = signature.get('schemes', {})
                for scheme_name in schemes.keys():
                    if 'v1' in scheme_name.lower():
                        st.write("**Verified scheme v1 (JAR signing)**")
                    elif 'v2' in scheme_name.lower():
                        st.write("**Verified scheme v2 (APK Signature Scheme v2)**")
                    elif 'v3' in scheme_name.lower():
                        st.write("**Verified scheme v3 (APK Signature Scheme v3)**")
                    elif 'v3.1' in scheme_name.lower():
                        st.write("**Verified scheme v3.1 (APK Signature Scheme v3.1)**")
                    elif 'v4' in scheme_name.lower():
                        st.write("**Verified scheme v4 (APK Signature Scheme v4)**")
            
            with col2:
                # Extract detailed signer information
                signer_info = safe_get(signature, 'signer', 'Unknown')
                if 'CN=' in signer_info:
                    # Parse the full certificate subject
                    st.write(signer_info)
                else:
                    st.write(signer_info)
                
                st.write(safe_get(signature, 'valid_from', 'Unknown'))
                st.write(safe_get(signature, 'valid_until', 'Unknown'))
                st.write(safe_get(signature, 'algorithm', 'Unknown'))
                st.write("")
                
                # Verification status with proper formatting
                for scheme_name, status in schemes.items():
                    if status:
                        st.write("Yes")
                    else:
                        st.write("No")
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
    
    st.write("**Basic Information**")
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
    
    st.write("")
    st.write("**Permissions** (showing first 8)")
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
    
    st.write("")
    st.write("**Features** (showing first 5)")
    required = features.get('required', [])
    if required:
        for feat in required[:5]:  # Show first 5
            clean_feat = feat.replace('android.hardware.', '').replace('android.software.', '')
            st.write(f"• {clean_feat}")
        if len(required) > 5:
            st.write(f"• ... and {len(required) - 5} more")
    else:
        st.write("• No features required")
    
    st.write("")
    st.write("**Signature Information**")
    signature = safe_get(data, 'signature', {})
    if signature:
        signer = safe_get(signature, 'signer', 'Unknown')
        # Extract just the CN if it's a full subject
        if 'CN=' in signer:
            cn_part = [part for part in signer.split(',') if 'CN=' in part]
            if cn_part:
                signer = cn_part[0].replace('CN=', '').strip()
        
        st.write(f"• **Signer:** {signer}")
        st.write(f"• **Algorithm:** {safe_get(signature, 'algorithm', 'Unknown')}")
        st.write(f"• **Valid From:** {safe_get(signature, 'valid_from', 'Unknown')}")
        
        schemes = signature.get('schemes', {})
        verified_schemes = []
        for scheme, status in schemes.items():
            if status:
                if 'v1' in scheme.lower():
                    verified_schemes.append('v1')
                elif 'v2' in scheme.lower():
                    verified_schemes.append('v2')
                elif 'v3.1' in scheme.lower():
                    verified_schemes.append('v3.1')
                elif 'v3' in scheme.lower():
                    verified_schemes.append('v3')
                elif 'v4' in scheme.lower():
                    verified_schemes.append('v4')
        
        if verified_schemes:
            st.write(f"• **Verified Schemes:** {', '.join(verified_schemes)}")
        else:
            st.write("• **Verified Schemes:** None")
    else:
        st.write("• No signature information available")

if __name__ == "__main__":
    main()
