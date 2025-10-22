"""
WSGI entry point for Vercel deployment
"""
import os
import subprocess
import sys

def application(environ, start_response):
    """WSGI application entry point"""
    # Set environment variables
    os.environ['STREAMLIT_SERVER_PORT'] = '8501'
    os.environ['STREAMLIT_SERVER_ADDRESS'] = '0.0.0.0'
    os.environ['STREAMLIT_SERVER_HEADLESS'] = 'true'
    os.environ['STREAMLIT_BROWSER_GATHER_USAGE_STATS'] = 'false'
    
    # Start Streamlit server
    try:
        # Import and run the Streamlit app
        from app import main
        import streamlit.web.cli as stcli
        
        # Set up Streamlit configuration
        sys.argv = ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true"]
        
        # Run the app
        stcli.main()
        
    except Exception as e:
        # Return error response
        status = '500 Internal Server Error'
        headers = [('Content-Type', 'text/plain')]
        start_response(status, headers)
        return [f'Error starting Streamlit: {str(e)}'.encode()]
    
    # This should not be reached as Streamlit handles the response
    status = '200 OK'
    headers = [('Content-Type', 'text/html')]
    start_response(status, headers)
    return [b'Streamlit app started']
