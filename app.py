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
    
    # App Overview
    with st.expander("📱 App Overview", expanded=True):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("App Name", safe_get(data, 'app_name', 'Unknown'))
            st.metric("Package", safe_get(data, 'package_name', 'Unknown'))
            st.metric("Version", safe_get(data, 'version_name', 'Unknown'))
        
        with col2:
            st.metric("Build", safe_get(data, 'version_code', 'Unknown'))
            st.metric("Min OS", f"API {safe_get(data, 'min_sdk_version', 'Unknown')}")
            st.metric("Target OS", f"API {safe_get(data, 'target_sdk_version', 'Unknown')}")
        
        with col3:
            st.metric("Size", format_size(safe_get(data, 'file_size', 0)))
            st.metric("Architecture", safe_get(data, 'architectures', 'Unknown'))
            st.metric("Debuggable", "Yes" if safe_get(data, 'debuggable', False) else "No")
    
    # Permissions
    with st.expander("🔒 Permissions", expanded=False):
        permissions = safe_get(data, 'permissions', {})
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.subheader("Declared Permissions")
            declared = permissions.get('declared', [])
            if declared:
                for perm in declared:
                    st.write(f"• {perm}")
            else:
                st.info("No declared permissions found")
        
        with col2:
            st.subheader("Implied Permissions")
            implied = permissions.get('implied', [])
            if implied:
                for perm in implied:
                    st.write(f"• {perm}")
            else:
                st.info("No implied permissions found")
        
        with col3:
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
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.subheader("Required Features")
            required = features.get('required', [])
            if required:
                for feat in required:
                    st.write(f"• {feat}")
            else:
                st.info("No required features found")
        
        with col2:
            st.subheader("Implied Features")
            implied = features.get('implied', [])
            if implied:
                for feat in implied:
                    st.write(f"• {feat}")
            else:
                st.info("No implied features found")
        
        with col3:
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
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Certificate Information")
                st.write(f"**Signer:** {safe_get(signature, 'signer', 'Unknown')}")
                st.write(f"**Valid From:** {safe_get(signature, 'valid_from', 'Unknown')}")
                st.write(f"**Valid Until:** {safe_get(signature, 'valid_until', 'Unknown')}")
                st.write(f"**Algorithm:** {safe_get(signature, 'algorithm', 'Unknown')}")
            
            with col2:
                st.subheader("Verification Status")
                schemes = signature.get('schemes', {})
                for scheme, status in schemes.items():
                    status_icon = "✅" if status else "❌"
                    st.write(f"{status_icon} {scheme}")
        else:
            st.warning("No signature information found")
    
    # Unity Export Check
    with st.expander("🎮 Unity Export Check", expanded=False):
        unity_exported = safe_get(data, 'unity_exported', None)
        if unity_exported is not None:
            if unity_exported:
                st.error("⚠️ Unity main activity has android:exported='true' - potential security risk!")
            else:
                st.success("✅ Unity main activity does not have android:exported='true'")
        else:
            st.info("ℹ️ No Unity main activity found or unable to determine export status")
    
    # Additional Details
    with st.expander("📋 Additional Details", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Screen Support")
            screens = safe_get(data, 'supported_screens', [])
            if screens:
                for screen in screens:
                    st.write(f"• {screen}")
            else:
                st.info("Screen support information not available")
        
        with col2:
            st.subheader("Density Support")
            densities = safe_get(data, 'supported_densities', [])
            if densities:
                for density in densities:
                    st.write(f"• {density}")
            else:
                st.info("Density support information not available")

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
    
    # Side-by-side comparison
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader(f"📱 {filename1}")
        display_apk_summary(data1)
    
    with col2:
        st.subheader(f"📱 {filename2}")
        display_apk_summary(data2)
    
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

if __name__ == "__main__":
    main()
