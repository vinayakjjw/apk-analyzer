# APK Analysis Tool

A comprehensive Streamlit-based web application for analyzing Android APK files with advanced security assessment capabilities.

## Features

### 🔍 Analysis Modes
- **Single APK Analysis**: Detailed examination of individual APK files
- **Batch APK Analysis**: Analyze multiple APK files simultaneously with summary statistics
- **Dual APK Comparison**: Side-by-side comparison of two APK files with difference highlighting

### 🛡️ Security Analysis
- **Permission Analysis**: Comprehensive extraction and categorization of Android permissions
- **Signature Verification**: Multi-scheme APK signature validation (v1-v4)
- **Certificate Analysis**: X.509 certificate parsing and validation
- **Architecture Validation**: Ensures compatibility with expected architectures
- **Target SDK Compliance**: Validates API level requirements for security
- **Unity Export Verification**: Checks Unity applications for required export settings

### 📊 Metadata Extraction
- Application information (name, package, version)
- SDK versions and compatibility
- Supported architectures and screen densities
- Application components (activities, services, receivers, providers)
- App icon extraction with intelligent quality selection
- Manifest analysis with fallback parsing methods

### ⚡ Advanced Features
- **Multi-method Permission Extraction**: Uses multiple fallback methods for robust permission detection
- **Intelligent Icon Extraction**: Finds and selects the best quality app icon
- **Security Concern Detection**: Highlights potential security issues with specific criteria
- **Batch Processing**: Progress tracking for multiple file analysis
- **Error Resilience**: Comprehensive error handling with graceful degradation

## Installation

### Prerequisites
- Python 3.8+
- Required packages (automatically installed):
  - `streamlit`
  - `androguard`
  - `cryptography`
  - `pandas`

### Setup
1. Clone this repository:
```bash
git clone <your-repo-url>
cd apk-analysis-tool
```

2. Install dependencies:
```bash
pip install streamlit androguard cryptography pandas
```

3. Run the application:
```bash
streamlit run app.py --server.port 5000
```

4. Open your browser and navigate to `http://localhost:5000`

## Usage

### Single APK Analysis
1. Select "Single APK Analysis" from the sidebar
2. Upload an APK file (up to 500MB supported)
3. View comprehensive analysis results including:
   - Basic information and metadata
   - Permissions and features
   - Security assessment
   - Certificate details
   - Application components

### Batch APK Analysis
1. Select "Batch APK Analysis" from the sidebar
2. Upload multiple APK files
3. Monitor progress as files are processed
4. Review summary statistics and individual results

### Dual APK Comparison
1. Select "Dual APK Comparison" from the sidebar
2. Upload two APK files for comparison
3. View side-by-side comparison with:
   - Metadata differences
   - Permission changes
   - Security concern analysis
   - Component differences

## Security Criteria

The tool flags the following security concerns:
- **Internet Permission**: Apps with network access capabilities
- **External Storage Access**: Apps with folder/storage access permissions
- **OpenGL Version**: Non-2.0 OpenGL versions
- **Architecture**: Non-armeabi-v7a architectures
- **Signature Validation**: Signatures not matching specific criteria
- **Target SDK**: Applications not targeting API level 29
- **Unity Export**: Unity applications missing required export settings

## Technical Architecture

### Core Components
- **APKAnalyzer**: Main analysis engine using androguard
- **SignatureAnalyzer**: Certificate and signature verification
- **APKComparator**: Side-by-side comparison functionality
- **Utility Functions**: Data formatting and helper methods

### Analysis Pipeline
1. APK file validation and loading
2. Metadata extraction using multiple methods
3. Permission analysis with fallback techniques
4. Security assessment against defined criteria
5. Certificate and signature verification
6. Component and feature analysis

### Error Handling
- Graceful degradation for partial analysis results
- Multiple extraction methods for robust data retrieval
- Comprehensive logging for debugging
- User-friendly error messages

## File Structure
```
apk-analysis-tool/
├── app.py                 # Main Streamlit application
├── apk_analyzer.py        # Core APK analysis functionality
├── signature_analyzer.py  # Certificate and signature analysis
├── comparison_utils.py    # APK comparison utilities
├── utils.py              # Helper functions
├── requirements.txt      # Python dependencies
├── .streamlit/
│   └── config.toml       # Streamlit configuration
└── README.md            # This file
```

## Configuration

### Streamlit Configuration
The application uses custom Streamlit settings for optimal deployment:
- Server runs on `0.0.0.0:5000` for accessibility
- File upload limit set to 500MB
- Wide layout for better data visualization

### Security Settings
Security criteria can be customized by modifying the analysis functions in `app.py` and related modules.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is open source and available under the [MIT License](LICENSE).

## Support

For questions, issues, or contributions, please:
1. Check existing issues on GitHub
2. Create a new issue with detailed information
3. Include sample APK files (if possible) for bug reports

## Changelog

### Recent Updates
- Enhanced permission extraction with multiple fallback methods
- Improved icon extraction with intelligent quality selection
- Added Target SDK 29 validation
- Added Unity export status verification
- Enhanced error handling and debugging capabilities
- Fixed dual APK comparison UI issues
- Increased file upload limit to 500MB

---

**Note**: This tool is designed for security analysis and educational purposes. Always ensure you have proper authorization before analyzing APK files that you do not own.
