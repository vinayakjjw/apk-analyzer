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
    # Modern header with clean design
    st.markdown("### 📱 APK Analysis Results")
    st.markdown(f"**{filename}**")
    st.divider()
    
    # Main app card - Apple-inspired design
    with st.container():
        st.markdown("""
        <style>
        .app-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 2rem;
            border-radius: 16px;
            color: white;
            margin-bottom: 2rem;
        }
        .app-title {
            font-size: 2rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }
        .app-subtitle {
            opacity: 0.9;
            margin-bottom: 1rem;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }
        .info-item {
            background: rgba(255,255,255,0.1);
            padding: 1rem;
            border-radius: 12px;
            backdrop-filter: blur(10px);
        }
        </style>
        """, unsafe_allow_html=True)
        
        # App overview card
        col_icon, col_info = st.columns([1, 4])
        
        with col_icon:
            # Display app icon if available
            app_icon = safe_get(data, 'app_icon', None)
            if app_icon:
                try:
                    # Try to display icon with validation
                    if isinstance(app_icon, str):
                        icon_bytes = app_icon.encode('latin-1')
                    elif isinstance(app_icon, bytes):
                        icon_bytes = app_icon
                    else:
                        icon_bytes = app_icon
                    
                    # Validate if it's actually image data
                    if len(icon_bytes) > 10:  # Basic size check
                        from io import BytesIO
                        icon_stream = BytesIO(icon_bytes)
                        st.image(icon_stream, width=100)
                    else:
                        st.markdown("📱")
                        st.caption("Icon too small")
                except:
                    st.markdown("📱")
                    st.caption("Icon found")
            else:
                st.markdown("📱")
                st.caption("No icon")
        
        with col_info:
            # App header information
            st.markdown(f"## {safe_get(data, 'app_name', 'Unknown')}")
            st.markdown(f"**{safe_get(data, 'package_name', 'Unknown')}**")
            st.markdown(f"Version {safe_get(data, 'version_name', 'Unknown')} (Build {safe_get(data, 'version_code', 'Unknown')})")
        
        st.divider()
        
        # Technical specifications in cards
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Min Android", f"API {safe_get(data, 'min_sdk_version', 'Unknown')}")
            
        with col2:
            st.metric("Target Android", f"API {safe_get(data, 'target_sdk_version', 'Unknown')}")
            
        with col3:
            st.metric("File Size", format_size(safe_get(data, 'file_size', 0)))
            
        with col4:
            st.metric("Architecture", safe_get(data, 'architectures', 'Unknown'))
        
        # Additional info
        col5, col6 = st.columns(2)
        with col5:
            debug_status = "Development" if safe_get(data, 'debuggable', False) else "Production"
            st.metric("Build Type", debug_status)
            
        with col6:
            features = safe_get(data, 'features', {})
            opengl_version = features.get('opengl_version', 'Standard')
            st.metric("Graphics", opengl_version)
    
    # Modern tabbed interface for detailed analysis
    st.markdown("---")
    
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🔒 Permissions", 
        "⚡ Features", 
        "🔐 Security", 
        "📄 Manifest", 
        "🛠️ Technical"
    ])
    
    with tab1:
        permissions = safe_get(data, 'permissions', {})
        
        # Permission categories with modern styling
        declared = permissions.get('declared', [])
        implied = permissions.get('implied', [])
        optional = permissions.get('optional', [])
        
        if declared or implied or optional:
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown("##### 🔴 Required Permissions")
                if declared:
                    for perm in declared:
                        clean_perm = perm.replace('android.permission.', '')
                        st.markdown(f"• {clean_perm}")
                else:
                    st.info("None")
            
            with col2:
                st.markdown("##### 🟡 Implied Permissions")
                if implied:
                    for perm in implied:
                        clean_perm = perm.replace('android.permission.', '')
                        st.markdown(f"• {clean_perm}")
                else:
                    st.info("None")
            
            with col3:
                st.markdown("##### 🟢 Optional Permissions")
                if optional:
                    for perm in optional:
                        clean_perm = perm.replace('android.permission.', '')
                        st.markdown(f"• {clean_perm}")
                else:
                    st.info("None")
        else:
            st.info("No permissions found")
    
    with tab2:
        features = safe_get(data, 'features', {})
        
        required = features.get('required', [])
        implied = features.get('implied', [])
        not_required = features.get('not_required', [])
        
        if required or implied or not_required:
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown("##### ✅ Required Features")
                if required:
                    for feat in required[:10]:  # Limit display
                        clean_feat = feat.replace('android.hardware.', '').replace('android.software.', '')
                        st.markdown(f"• {clean_feat}")
                    if len(required) > 10:
                        st.info(f"... and {len(required) - 10} more")
                else:
                    st.info("None")
            
            with col2:
                st.markdown("##### 💡 Implied Features")
                if implied:
                    for feat in implied[:10]:
                        clean_feat = feat.replace('android.hardware.', '').replace('android.software.', '')
                        st.markdown(f"• {clean_feat}")
                    if len(implied) > 10:
                        st.info(f"... and {len(implied) - 10} more")
                else:
                    st.info("None")
            
            with col3:
                st.markdown("##### ➖ Not Required")
                if not_required:
                    for feat in not_required[:10]:
                        clean_feat = feat.replace('android.hardware.', '').replace('android.software.', '')
                        st.markdown(f"• {clean_feat}")
                    if len(not_required) > 10:
                        st.info(f"... and {len(not_required) - 10} more")
                else:
                    st.info("None")
        else:
            st.info("No features information available")
    
    with tab3:
        signature = safe_get(data, 'signature', {})
        
        if signature:
            # Security overview metrics
            col1, col2, col3 = st.columns(3)
            
            with col1:
                schemes = signature.get('schemes', {})
                verified_count = sum(1 for status in schemes.values() if status)
                st.metric("Signature Schemes", f"{verified_count}/{len(schemes)}")
            
            with col2:
                algorithm = safe_get(signature, 'algorithm', 'Unknown')
                st.metric("Algorithm", algorithm)
            
            with col3:
                # Check if signature is valid (simplified)
                is_valid = any(schemes.values()) if schemes else False
                status = "Valid" if is_valid else "Invalid"
                st.metric("Status", status)
            
            st.divider()
            
            # Detailed signature information
            st.markdown("##### Certificate Details")
            signer_info = safe_get(signature, 'signer', 'Unknown')
            if 'CN=' in signer_info:
                # Parse certificate subject
                parts = signer_info.split(',')
                for part in parts:
                    if '=' in part:
                        key, value = part.strip().split('=', 1)
                        st.markdown(f"**{key}:** {value}")
            else:
                st.markdown(f"**Signer:** {signer_info}")
            
            col_from, col_until = st.columns(2)
            with col_from:
                st.markdown(f"**Valid From:** {safe_get(signature, 'valid_from', 'Unknown')}")
            with col_until:
                st.markdown(f"**Valid Until:** {safe_get(signature, 'valid_until', 'Unknown')}")
            
            # Verification schemes with status indicators
            st.markdown("##### Verification Schemes")
            for scheme_name, status in schemes.items():
                icon = "✅" if status else "❌"
                clean_name = scheme_name.replace('_', ' ').title()
                st.markdown(f"{icon} {clean_name}")
        else:
            st.warning("No signature information found")
        
        # Unity check
        unity_exported = safe_get(data, 'unity_exported', None)
        if unity_exported is not None:
            st.divider()
            st.markdown("##### Unity Application Analysis")
            if unity_exported:
                st.warning("🎮 Unity exported: YES - Potential security considerations")
                st.info("Unity applications with exported main activity may have additional security considerations.")
            else:
                st.success("🎮 Unity exported: NO - Standard security profile")
    
    with tab4:
        manifest_xml = safe_get(data, 'manifest_xml', None)
        if manifest_xml:
            # Create tabs for different viewing options
            manifest_tab1, manifest_tab2 = st.tabs(["📋 Formatted View", "💻 Raw XML"])
            
            with manifest_tab1:
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
            
            with manifest_tab2:
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
                mime="application/xml"
            )
        else:
            st.warning("Android Manifest XML not available")
    
    with tab5:
        # Technical Details
        st.markdown("##### 📊 File Analysis")
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Activities**")
            activities = safe_get(data, 'activities', [])
            st.metric("Count", len(activities))
            if activities:
                with st.expander("View Activities"):
                    for activity in activities[:10]:
                        st.markdown(f"• {activity}")
                    if len(activities) > 10:
                        st.info(f"... and {len(activities) - 10} more")
        
        with col2:
            st.markdown("**Services**")
            services = safe_get(data, 'services', [])
            st.metric("Count", len(services))
            if services:
                with st.expander("View Services"):
                    for service in services[:10]:
                        st.markdown(f"• {service}")
                    if len(services) > 10:
                        st.info(f"... and {len(services) - 10} more")
        
        # Screen and Density Support
        st.divider()
        st.markdown("##### 📱 Display Support")
        
        col3, col4 = st.columns(2)
        with col3:
            st.markdown("**Screen Sizes**")
            screens = safe_get(data, 'supported_screens', [])
            if screens:
                for screen in screens:
                    st.markdown(f"• {screen}")
            else:
                st.info("Not specified")
        
        with col4:
            st.markdown("**Density Support**")
            densities = safe_get(data, 'supported_densities', [])
            if densities:
                for density in densities:
                    st.markdown(f"• {density}")
            else:
                st.info("Not specified")

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
