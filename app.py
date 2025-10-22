import streamlit as st
import os
import tempfile
from pathlib import Path
import pandas as pd
from apk_analyzer import APKAnalyzer
from comparison_utils import APKComparator
from utils import format_size, safe_get

def check_security_concerns(data):
    """Check for security concerns and return warnings with enhanced styling"""
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
        concerns.append(f"🔒 **Risky Permissions**: {', '.join(dangerous_perms)}")
    
    # Check OpenGL version
    features = safe_get(data, 'features', {})
    opengl_version = features.get('opengl_version', '')
    if opengl_version and '2.0' not in opengl_version:
        concerns.append(f"🎮 **OpenGL Version**: {opengl_version} (expected 2.0)")
    
    # Check Architecture
    architecture = safe_get(data, 'architectures', '')
    if architecture and 'armeabi-v7a' not in architecture:
        concerns.append(f"🏗️ **Architecture**: {architecture} (expected armeabi-v7a)")
    
    # Check Target SDK
    target_sdk = safe_get(data, 'target_sdk_version', '')
    if target_sdk and str(target_sdk) != '29':
        concerns.append(f"📱 **Target SDK**: API {target_sdk} (expected API 29)")
    
    # Check Unity Export Status
    unity_exported = safe_get(data, 'unity_exported', None)
    if unity_exported is not None and not unity_exported:
        concerns.append("🎮 **Unity Export**: Main activity missing android:exported='true'")
    
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
            signature_issues.append("SHA-256 mismatch")
        
        if signature_issues:
            concerns.append(f"🔐 **Signature Issue**: {' and '.join(signature_issues)}")
    
    return concerns

# Configure page
st.set_page_config(
    page_title="APK Analysis Tool",
    page_icon="📱",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "Get Help": "https://docs.streamlit.io/",
        "Report a bug": "https://github.com/",
        "About": "APK Analysis Tool — inspect Android APKs quickly and securely."
    },
)


def inject_custom_css() -> None:
    """Inject modern CSS for enhanced UI/UX."""
    st.markdown(
        """
        <style>
        /* Import Google Fonts */
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
        
        /* Global Styles */
        .main .block-container {
            padding-top: 2rem;
            padding-bottom: 4rem;
            max-width: 1200px;
        }
        
        /* Custom Font */
        .main, .main * {
            font-family: 'Inter', sans-serif !important;
        }
        
        /* Hero Section */
        .hero-section {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 3rem 2rem;
            border-radius: 20px;
            margin-bottom: 2rem;
            text-align: center;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
        }
        
        .hero-title {
            font-size: 3rem;
            font-weight: 800;
            margin-bottom: 1rem;
            background: linear-gradient(45deg, #fff, #f0f9ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .hero-subtitle {
            font-size: 1.2rem;
            opacity: 0.9;
            margin-bottom: 2rem;
        }
        
        /* Section Chips */
        .section-chip {
            display: inline-block;
            padding: 0.5rem 1rem;
            border-radius: 50px;
            background: rgba(255,255,255,0.2);
            color: white;
            font-weight: 600;
            font-size: 0.9rem;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.3);
        }
        
        /* Enhanced Cards - Dark Theme Compatible */
        .section-card {
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 16px;
            padding: 2rem;
            background: rgba(30, 41, 59, 0.8);
            color: white;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            transition: all 0.3s ease;
            margin-bottom: 1.5rem;
            backdrop-filter: blur(10px);
        }
        
        .section-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 30px rgba(0,0,0,0.4);
            background: rgba(30, 41, 59, 0.9);
        }
        
        .card {
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            background: rgba(51, 65, 85, 0.6);
            color: white;
            transition: all 0.3s ease;
            backdrop-filter: blur(5px);
        }
        
        .card:hover {
            background: rgba(51, 65, 85, 0.8);
            border-color: #667eea;
        }
        
        /* Warning Cards - Dark Theme */
        .warn-card {
            border: 1px solid rgba(239, 68, 68, 0.4);
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.15), rgba(239, 68, 68, 0.25));
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            border-left: 4px solid #ef4444;
            color: white;
            backdrop-filter: blur(5px);
        }
        
        .success-card {
            border: 1px solid rgba(34, 197, 94, 0.4);
            background: linear-gradient(135deg, rgba(34, 197, 94, 0.15), rgba(34, 197, 94, 0.25));
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            border-left: 4px solid #22c55e;
            color: white;
            backdrop-filter: blur(5px);
        }
        
        /* Info Cards - Dark Theme */
        .info-card {
            border: 1px solid rgba(59, 130, 246, 0.4);
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.15), rgba(59, 130, 246, 0.25));
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            border-left: 4px solid #3b82f6;
            color: white;
            backdrop-filter: blur(5px);
        }
        
        /* Header Rows */
        .header-row {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1rem;
        }
        
        .header-row .title {
            font-weight: 700;
            font-size: 1.3rem;
            color: #1f2937;
        }
        
        /* KPI Grid */
        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 1rem 0;
        }
        
        .kpi-item {
            background: white;
            padding: 1.5rem;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            border: 1px solid rgba(0,0,0,0.05);
        }
        
        .kpi-value {
            font-size: 2rem;
            font-weight: 800;
            color: #667eea;
            margin-bottom: 0.5rem;
        }
        
        .kpi-label {
            font-size: 0.9rem;
            color: #6b7280;
            font-weight: 500;
        }
        
        /* App Header */
        .app-header {
            display: flex;
            align-items: center;
            gap: 1rem;
            min-height: 80px;
            padding: 1rem;
            background: linear-gradient(135deg, #f8fafc, #e2e8f0);
            border-radius: 12px;
            margin-bottom: 1rem;
        }
        
        /* Enhanced Expanders */
        .streamlit-expanderHeader {
            font-weight: 700 !important;
            font-size: 1.1rem !important;
            color: #1f2937 !important;
            padding: 1rem !important;
            background: linear-gradient(135deg, #f8fafc, #e2e8f0) !important;
            border-radius: 8px !important;
            margin-bottom: 0.5rem !important;
        }
        
        .streamlit-expanderContent {
            padding: 1.5rem !important;
        }
        
        /* Enhanced DataFrames */
        .stDataFrame, .stTable {
            border-radius: 12px !important;
            overflow: hidden !important;
            box-shadow: 0 4px 20px rgba(0,0,0,0.05) !important;
            border: 1px solid rgba(0,0,0,0.05) !important;
        }
        
        /* File Upload Styling */
        .stFileUploader > div {
            border: 2px dashed #667eea !important;
            border-radius: 12px !important;
            padding: 2rem !important;
            background: linear-gradient(135deg, rgba(102, 126, 234, 0.05), rgba(118, 75, 162, 0.05)) !important;
            transition: all 0.3s ease !important;
        }
        
        .stFileUploader > div:hover {
            border-color: #4f46e5 !important;
            background: linear-gradient(135deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1)) !important;
        }
        
        /* Button Styling */
        .stButton > button {
            background: linear-gradient(135deg, #667eea, #764ba2) !important;
            color: white !important;
            border: none !important;
            border-radius: 8px !important;
            padding: 0.75rem 2rem !important;
            font-weight: 600 !important;
            transition: all 0.3s ease !important;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3) !important;
        }
        
        .stButton > button:hover {
            transform: translateY(-2px) !important;
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.4) !important;
        }
        
        /* Tab Styling - Dark Theme */
        .stTabs [data-baseweb="tab-list"] {
            gap: 1rem;
            background: rgba(15, 23, 42, 0.8) !important;
            padding: 0.5rem !important;
            border-radius: 12px !important;
        }
        
        .stTabs [data-baseweb="tab"] {
            background: rgba(30, 41, 59, 0.8) !important;
            color: white !important;
            border-radius: 8px !important;
            padding: 0.75rem 1.5rem !important;
            font-weight: 600 !important;
            transition: all 0.3s ease !important;
            border: 1px solid rgba(255,255,255,0.1) !important;
        }
        
        .stTabs [data-baseweb="tab"]:hover {
            background: rgba(51, 65, 85, 0.8) !important;
            transform: translateY(-1px) !important;
        }
        
        .stTabs [aria-selected="true"] {
            background: linear-gradient(135deg, #667eea, #764ba2) !important;
            color: white !important;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3) !important;
        }
        
        .stTabs [aria-selected="false"] {
            background: rgba(30, 41, 59, 0.8) !important;
            color: white !important;
        }
        
        /* Progress Bar */
        .stProgress > div > div > div {
            background: linear-gradient(135deg, #667eea, #764ba2) !important;
        }
        
        /* Sidebar Styling */
        .css-1d391kg {
            background: linear-gradient(180deg, #f8fafc, #e2e8f0) !important;
        }
        
        /* Footer */
        .app-footer {
            color: #6b7280;
            font-size: 0.9rem;
            border-top: 1px solid rgba(0,0,0,0.08);
            padding-top: 2rem;
            margin-top: 3rem;
            text-align: center;
        }
        
        /* Loading Spinner */
        .stSpinner {
            color: #667eea !important;
        }
        
        /* Metric Cards */
        .metric-card {
            background: white;
            padding: 1.5rem;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.05);
            border: 1px solid rgba(0,0,0,0.05);
            text-align: center;
        }
        
        /* Responsive Design */
        @media (max-width: 768px) {
            .hero-title {
                font-size: 2rem;
            }
            .kpi-grid {
                grid-template-columns: 1fr;
            }
        }
        
        /* Animation for cards */
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .section-card, .card {
            animation: fadeInUp 0.6s ease-out;
        }
        
        /* Fix any remaining white backgrounds */
        .stMarkdown, .stMarkdown * {
            color: inherit !important;
        }
        
        /* Ensure all text in cards is white */
        .section-card *, .card *, .warn-card *, .success-card *, .info-card * {
            color: white !important;
        }
        
        /* Fix Streamlit default components */
        .stAlert {
            background: rgba(30, 41, 59, 0.9) !important;
            color: white !important;
            border: 1px solid rgba(255,255,255,0.1) !important;
        }
        
        /* Fix any white backgrounds in Streamlit components */
        .stApp > div {
            background: #0f172a !important;
        }
        
        /* Ensure proper contrast for all text */
        .main .block-container {
            color: white;
        }
        
        /* Fix metric cards */
        .metric-container {
            background: rgba(30, 41, 59, 0.8) !important;
            color: white !important;
            border: 1px solid rgba(255,255,255,0.1) !important;
        }
        
        /* Force all Streamlit components to dark theme */
        .stTabs > div > div > div {
            background: transparent !important;
        }
        
        /* Override any remaining white backgrounds */
        .stTabs [data-baseweb="tab"] {
            background: rgba(30, 41, 59, 0.8) !important;
            color: white !important;
        }
        
        /* Ensure tab content area is dark */
        .stTabs [data-baseweb="tab-panel"] {
            background: transparent !important;
        }
        
        /* Fix any remaining white text on white background issues */
        .stTabs [data-baseweb="tab"] * {
            color: white !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

def main():
    inject_custom_css()

    # Enhanced Hero Section
    st.markdown("""
    <div class="hero-section">
        <div class="section-chip">🔒 Android Security Analysis</div>
        <h1 class="hero-title">📱 APK Analysis Tool</h1>
        <p class="hero-subtitle">Analyze, compare, and validate Android APKs with advanced security insights</p>
        <div style="display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap; margin-top: 2rem;">
            <div style="background: rgba(255,255,255,0.2); padding: 0.5rem 1rem; border-radius: 20px; font-size: 0.9rem;">🔍 Deep Analysis</div>
            <div style="background: rgba(255,255,255,0.2); padding: 0.5rem 1rem; border-radius: 20px; font-size: 0.9rem;">⚡ Fast Processing</div>
            <div style="background: rgba(255,255,255,0.2); padding: 0.5rem 1rem; border-radius: 20px; font-size: 0.9rem;">🛡️ Security Focused</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Enhanced Sidebar
    with st.sidebar:
        st.markdown("### 🚀 How it works")
        st.markdown("""
        <div class="info-card">
            <strong>1. Upload APK</strong><br>
            Select your Android APK file(s)
        </div>
        <div class="info-card">
            <strong>2. Analysis</strong><br>
            We parse metadata, permissions, and signatures
        </div>
        <div class="info-card">
            <strong>3. Results</strong><br>
            Get detailed security insights and recommendations
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("---")
        st.markdown("### 📋 Quick Links")
        st.page_link("pages/Rules.py", label="⚖️ Security Rules", icon="📜")
        st.caption("View all security checks and validation rules")
        
        st.markdown("---")
        st.markdown("### 💡 Tips")
        st.info("💡 **Pro Tip:** Use batch mode for analyzing multiple APKs efficiently")
        st.info("🔍 **Security:** Check the signature details for authenticity verification")
        st.info("📊 **Compare:** Use the comparison tool to spot differences between APK versions")

    # Enhanced Tab Navigation
    tab1, tab2, tab3 = st.tabs(["🔍 Single APK", "📦 Batch Analysis", "⚖️ Compare APKs"])

    with tab1:
        st.markdown("""
        <div class="section-card">
            <div class="header-row">
                <span class="title">🔍 Single APK Analysis</span>
            </div>
            <p>Upload a single APK file to get a comprehensive security analysis with detailed insights.</p>
        </div>
        """, unsafe_allow_html=True)
        single_apk_analysis()

    with tab2:
        st.markdown("""
        <div class="section-card">
            <div class="header-row">
                <span class="title">📦 Batch Analysis</span>
            </div>
            <p>Analyze multiple APKs simultaneously and export results for comprehensive security auditing.</p>
        </div>
        """, unsafe_allow_html=True)
        batch_apk_analysis()

    with tab3:
        st.markdown("""
        <div class="section-card">
            <div class="header-row">
                <span class="title">⚖️ APK Comparison</span>
            </div>
            <p>Compare two APK files side-by-side to identify differences, security changes, and version updates.</p>
        </div>
        """, unsafe_allow_html=True)
        dual_apk_comparison()

    # Footer
    st.markdown("<div class='app-footer'>Built with ❤️ using Streamlit & Androguard. For security research and educational purposes only.</div>", unsafe_allow_html=True)

def single_apk_analysis():
    # Enhanced file upload section
    st.markdown("""
    <div class="info-card">
        <strong>📋 File Requirements:</strong> Maximum 500 MB per APK file. For best performance, use files under 100 MB.
    </div>
    """, unsafe_allow_html=True)
    
    uploaded_file = st.file_uploader(
        "📱 Upload APK File",
        type=['apk'],
        help="Select an Android APK file for comprehensive security analysis",
        label_visibility="collapsed"
    )
    
    if uploaded_file is not None:
        file_size = len(uploaded_file.getvalue())
        
        # Enhanced file info display
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("📊 File Size", format_size(file_size))
        with col2:
            st.metric("📱 File Type", "Android APK")
        with col3:
            st.metric("⚡ Status", "Ready for Analysis")
        
        with st.spinner("🔍 Analyzing APK - This may take a few moments..."):
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
    
    # Add file size information
    st.info("📋 **File Size Limit:** 500 MB per APK file. If you encounter upload errors, try smaller APK files.")
    
    # Use session state to manage file uploads and avoid pagination issues
    if 'batch_files' not in st.session_state:
        st.session_state.batch_files = []
    
    # File uploader with session state management
    uploaded_files = st.file_uploader(
        "Upload APK files",
        type=['apk'],
        accept_multiple_files=True,
        help="Select multiple Android APK files for batch analysis (max 500 MB each)",
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
    # Enhanced Security Concerns Display
    security_concerns = check_security_concerns(data)
    if security_concerns:
        st.markdown("""
        <div class="warn-card">
            <div class="header-row">
                <span class="title">🚨 Security Concerns Detected</span>
            </div>
            <p>The following security issues were found in this APK:</p>
        </div>
        """, unsafe_allow_html=True)
        
        for concern in security_concerns:
            st.markdown(f"""
            <div class="warn-card">
                {concern}
            </div>
            """, unsafe_allow_html=True)
        st.markdown("---")
    else:
        st.markdown("""
        <div class="success-card">
            <div class="header-row">
                <span class="title">✅ No Security Concerns</span>
            </div>
            <p>This APK passed all security checks!</p>
        </div>
        """, unsafe_allow_html=True)
    
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
    
    # Add file size information
    st.info("📋 **File Size Limit:** 500 MB per APK file. If you encounter upload errors, try smaller APK files.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("First APK")
        uploaded_file1 = st.file_uploader(
            "Upload first APK file",
            type=['apk'],
            key="apk1",
            help="Select the first Android APK file for comparison (max 500 MB)"
        )
        if uploaded_file1 is not None:
            file_size1 = len(uploaded_file1.getvalue())
            st.write(f"📊 **File size:** {format_size(file_size1)}")
    
    with col2:
        st.subheader("Second APK")
        uploaded_file2 = st.file_uploader(
            "Upload second APK file",
            type=['apk'],
            key="apk2",
            help="Select the second Android APK file for comparison (max 500 MB)"
        )
        if uploaded_file2 is not None:
            file_size2 = len(uploaded_file2.getvalue())
            st.write(f"📊 **File size:** {format_size(file_size2)}")
    
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
    
    # Enhanced Security Concerns Display
    security_concerns = check_security_concerns(data)
    if security_concerns:
        st.markdown("""
        <div class="warn-card">
            <div class="header-row">
                <span class="title">🚨 Security Concerns Detected</span>
            </div>
            <p>The following security issues were found in this APK:</p>
        </div>
        """, unsafe_allow_html=True)
        
        for concern in security_concerns:
            st.markdown(f"""
            <div class="warn-card">
                {concern}
            </div>
            """, unsafe_allow_html=True)
        st.markdown("---")
    else:
        st.markdown("""
        <div class="success-card">
            <div class="header-row">
                <span class="title">✅ No Security Concerns</span>
            </div>
            <p>This APK passed all security checks!</p>
        </div>
        """, unsafe_allow_html=True)
    
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
        render_app_header(data1, filename1)
        render_security_concerns_card(data1)
        render_export_status_card(data1)
        display_apk_detailed_summary(data1, compact=True)
    
    with col2:
        render_app_header(data2, filename2)
        render_security_concerns_card(data2)
        render_export_status_card(data2)
        display_apk_detailed_summary(data2, compact=True)
    
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

def render_app_header(data, filename):
    """Consistent header with icon and filename for columns"""
    app_icon = safe_get(data, 'app_icon', None)
    from io import BytesIO
    cols = st.columns([1, 5])
    with cols[0]:
        try:
            if app_icon:
                if isinstance(app_icon, str):
                    st.image(BytesIO(app_icon.encode('latin-1')), width=60)
                elif isinstance(app_icon, bytes):
                    st.image(BytesIO(app_icon), width=60)
                else:
                    st.image(app_icon, width=60)
            else:
                st.write("📱")
        except Exception:
            st.write("📱")
    with cols[1]:
        st.markdown(f"<div class='app-header'><h3 style='margin:0'>{filename}</h3></div>", unsafe_allow_html=True)


def render_security_concerns_card(data):
    concerns = check_security_concerns(data)
    if concerns:
        items = "".join([f"<li>{c}</li>" for c in concerns])
        html = f"""
        <div class='warn-card'>
            <div class='header-row'><span class='title'>🚨 Security Concerns</span></div>
            <ul class='bullet'>{items}</ul>
        </div>
        """
        st.markdown(html, unsafe_allow_html=True)


def render_export_status_card(data):
    """Show Unity android:exported status in a dedicated card for comparison mode."""
    unity_exported = safe_get(data, 'unity_exported', None)
    if unity_exported is None:
        html = """
        <div class='card'>
            <div class='group-title'>Unity Export</div>
            <div class='small'>No Unity main activity found or unable to determine export status.</div>
        </div>
        """
    elif unity_exported:
        html = """
        <div class='card'>
            <div class='group-title'>Unity Export</div>
            <div>ℹ️ Unity main activity has android:exported='true'</div>
        </div>
        """
    else:
        html = """
        <div class='warn-card'>
            <div class='header-row'><span class='title'>Unity Export</span></div>
            <div>⚠️ Main activity missing android:exported='true'</div>
        </div>
        """
    st.markdown(html, unsafe_allow_html=True)


def display_apk_detailed_summary(data, compact=False):
    """Display detailed APK summary for comparison mode"""
    # Compact, aligned presentation for side-by-side columns
    if compact:
        info = {
            'App Name': safe_get(data, 'app_name', 'Unknown'),
            'Package': safe_get(data, 'package_name', 'Unknown'),
            'Version': f"{safe_get(data, 'version_name', 'Unknown')} ({safe_get(data, 'version_code', 'Unknown')})",
            'Min SDK': f"API {safe_get(data, 'min_sdk_version', 'Unknown')}",
            'Target SDK': f"API {safe_get(data, 'target_sdk_version', 'Unknown')}",
            'Size': format_size(safe_get(data, 'file_size', 0)),
            'Architecture': safe_get(data, 'architectures', 'Unknown'),
            'Debuggable': 'Yes' if safe_get(data, 'debuggable', False) else 'No',
        }
        features = safe_get(data, 'features', {})
        opengl_version = features.get('opengl_version')
        if opengl_version:
            info['Graphics'] = opengl_version

        info_items = "".join([f"<li><strong>{k}:</strong> {v}</li>" for k, v in info.items()])

        permissions = safe_get(data, 'permissions', {})
        declared = permissions.get('declared', [])
        if declared:
            listed = [p.replace('android.permission.', '') for p in declared[:8]]
            extra = f"<li>... and {len(declared)-8} more</li>" if len(declared) > 8 else ""
            perm_items = "".join([f"<li>{p}</li>" for p in listed]) + extra
        else:
            perm_items = "<li>No permissions declared</li>"

        html = f"""
        <div class='card card-basic'>
            <div class='group-title'>Basic Information</div>
            <ul class='bullet'>
                {info_items}
            </ul>
        </div>
        <div class='card card-perms'>
            <div class='group-title'>Permissions (first 8)</div>
            <ul class='bullet'>
                {perm_items}
            </ul>
        </div>
        """
        st.markdown(html, unsafe_allow_html=True)
        return
    
    # Original verbose layout (used elsewhere if needed)
    app_icon = safe_get(data, 'app_icon', None)
    if app_icon:
        try:
            from io import BytesIO
            if isinstance(app_icon, str):
                icon_bytes = app_icon.encode('latin-1')
                icon_stream = BytesIO(icon_bytes)
            elif isinstance(app_icon, bytes):
                icon_stream = BytesIO(app_icon)
            else:
                icon_stream = app_icon
            st.image(icon_stream, width=60)
        except Exception as e:
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
    features = safe_get(data, 'features', {})
    opengl_version = features.get('opengl_version')
    if opengl_version:
        st.write(f"• **Graphics:** {opengl_version}")
    st.write("")
    st.write("**Permissions** (showing first 8)")
    permissions = safe_get(data, 'permissions', {})
    declared = permissions.get('declared', [])
    if declared:
        for perm in declared[:8]:
            clean_perm = perm.replace('android.permission.', '')
            st.write(f"• {clean_perm}")
        if len(declared) > 8:
            st.write(f"• ... and {len(declared) - 8} more")
    else:
        st.write("• No permissions declared")

if __name__ == "__main__":
    main()
