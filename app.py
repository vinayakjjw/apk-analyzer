import streamlit as st
import os
import tempfile
from pathlib import Path
import pandas as pd
from apk_analyzer import APKAnalyzer
from comparison_utils import APKComparator
from utils import format_size, safe_get

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
            ["Single APK Analysis", "Dual APK Comparison"],
            help="Single mode analyzes one APK, Comparison mode compares two APKs"
        )
        
        st.markdown("---")
        st.markdown("### Features")
        st.markdown("• Extract app metadata")
        st.markdown("• Analyze permissions & features")
        st.markdown("• Verify signatures")
        st.markdown("• Check Unity exported status")
        st.markdown("• Compare APKs side-by-side")
    
    if mode == "Single APK Analysis":
        single_apk_analysis()
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
    
    # App Overview with Icon
    with st.expander("📱 App Overview", expanded=True):
        # Display app icon if available
        app_icon = safe_get(data, 'app_icon', None)
        if app_icon:
            try:
                col_icon, col_info = st.columns([1, 4])
                with col_icon:
                    st.image(app_icon, width=100, caption="App Icon")
                with col_info:
                    st.write(f"**App Name:** {safe_get(data, 'app_name', 'Unknown')}")
                    st.write(f"**Package:** {safe_get(data, 'package_name', 'Unknown')}")
                    st.write(f"**Version:** {safe_get(data, 'version_name', 'Unknown')}")
                    st.write(f"**Build:** {safe_get(data, 'version_code', 'Unknown')}")
            except:
                # If icon display fails, just show info without icon
                st.write(f"**App Name:** {safe_get(data, 'app_name', 'Unknown')}")
                st.write(f"**Package:** {safe_get(data, 'package_name', 'Unknown')}")
                st.write(f"**Version:** {safe_get(data, 'version_name', 'Unknown')}")
                st.write(f"**Build:** {safe_get(data, 'version_code', 'Unknown')}")
        else:
            st.write(f"**App Name:** {safe_get(data, 'app_name', 'Unknown')}")
            st.write(f"**Package:** {safe_get(data, 'package_name', 'Unknown')}")
            st.write(f"**Version:** {safe_get(data, 'version_name', 'Unknown')}")
            st.write(f"**Build:** {safe_get(data, 'version_code', 'Unknown')}")
        
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
            # Use a text area with proper height for vertical scrolling
            st.text_area("AndroidManifest.xml", value=manifest_xml, height=400, label_visibility="collapsed")
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
    
    # App icon first
    app_icon = safe_get(data, 'app_icon', None)
    if app_icon:
        try:
            from io import BytesIO
            icon_bytes = BytesIO(app_icon)
            st.image(icon_bytes, width=80)
        except:
            st.info("📱 Icon available")
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
