"""
Vercel serverless function entry point for Streamlit app
"""
import os
import sys
import subprocess
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

# Add the parent directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class StreamlitHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests by proxying to Streamlit"""
        try:
            # Parse the URL
            parsed_path = urllib.parse.urlparse(self.path)
            
            # Forward the request to Streamlit
            self.proxy_to_streamlit()
            
        except Exception as e:
            self.send_error(500, f"Error handling request: {str(e)}")
    
    def do_POST(self):
        """Handle POST requests by proxying to Streamlit"""
        try:
            self.proxy_to_streamlit()
        except Exception as e:
            self.send_error(500, f"Error handling request: {str(e)}")
    
    def proxy_to_streamlit(self):
        """Proxy requests to the Streamlit server"""
        try:
            # Import and run the Streamlit app
            from app import main
            
            # Set up environment for Streamlit
            os.environ['STREAMLIT_SERVER_PORT'] = '8501'
            os.environ['STREAMLIT_SERVER_ADDRESS'] = '0.0.0.0'
            os.environ['STREAMLIT_SERVER_HEADLESS'] = 'true'
            os.environ['STREAMLIT_BROWSER_GATHER_USAGE_STATS'] = 'false'
            
            # Start Streamlit in a subprocess
            process = subprocess.Popen([
                sys.executable, '-m', 'streamlit', 'run', 'app.py',
                '--server.port=8501',
                '--server.address=0.0.0.0',
                '--server.headless=true',
                '--browser.gatherUsageStats=false'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait a moment for Streamlit to start
            time.sleep(2)
            
            # Send a simple response
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            html_response = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>APK Analysis Tool</title>
                <meta http-equiv="refresh" content="0; url=http://localhost:8501">
            </head>
            <body>
                <h1>APK Analysis Tool</h1>
                <p>Starting Streamlit application...</p>
                <p>If you are not redirected automatically, <a href="http://localhost:8501">click here</a>.</p>
            </body>
            </html>
            """
            
            self.wfile.write(html_response.encode())
            
        except Exception as e:
            self.send_error(500, f"Error starting Streamlit: {str(e)}")

def handler(request):
    """Vercel serverless function handler"""
    try:
        # Set up environment
        os.environ['STREAMLIT_SERVER_PORT'] = '8501'
        os.environ['STREAMLIT_SERVER_ADDRESS'] = '0.0.0.0'
        os.environ['STREAMLIT_SERVER_HEADLESS'] = 'true'
        os.environ['STREAMLIT_BROWSER_GATHER_USAGE_STATS'] = 'false'
        
        # Import and run the main app
        from app import main
        
        # Return a simple HTML response
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'text/html',
            },
            'body': '''
            <!DOCTYPE html>
            <html>
            <head>
                <title>APK Analysis Tool</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; }
                    .container { max-width: 800px; margin: 0 auto; }
                    .error { color: red; }
                    .info { color: blue; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>📱 APK Analysis Tool</h1>
                    <p class="info">This application requires a persistent server environment to run properly.</p>
                    <p>Streamlit applications are not suitable for serverless deployment on Vercel due to their interactive nature and persistent state requirements.</p>
                    <h2>Alternative Deployment Options:</h2>
                    <ul>
                        <li><strong>Heroku:</strong> Better suited for Streamlit apps with persistent processes</li>
                        <li><strong>Railway:</strong> Good for Python web applications</li>
                        <li><strong>DigitalOcean App Platform:</strong> Supports long-running processes</li>
                        <li><strong>Google Cloud Run:</strong> Can handle containerized Streamlit apps</li>
                        <li><strong>Streamlit Cloud:</strong> Free hosting specifically for Streamlit apps</li>
                    </ul>
                    <h2>Recommended: Streamlit Cloud</h2>
                    <p>For the best experience with this APK Analysis Tool, consider deploying to <a href="https://share.streamlit.io" target="_blank">Streamlit Cloud</a>, which is specifically designed for Streamlit applications.</p>
                </div>
            </body>
            </html>
            '''
        }
        
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'text/html',
            },
            'body': f'<html><body><h1>Error</h1><p>Failed to start application: {str(e)}</p></body></html>'
        }
