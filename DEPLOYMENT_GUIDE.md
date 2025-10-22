# APK Analysis Tool - Deployment Guide

## Deployment Options

Due to the size and nature of this Streamlit application, here are the recommended deployment options:

### 1. 🚀 **Streamlit Cloud (Recommended)**
**Best for:** Free hosting specifically designed for Streamlit apps

**Steps:**
1. Push your code to GitHub
2. Go to [share.streamlit.io](https://share.streamlit.io)
3. Connect your GitHub repository
4. Deploy with one click

**Advantages:**
- Free hosting
- Designed specifically for Streamlit
- Easy deployment
- Automatic updates from GitHub

### 2. 🐳 **Docker + Railway/Render**
**Best for:** More control and custom configurations

**Steps:**
1. Create a `Dockerfile` (see below)
2. Push to GitHub
3. Connect to Railway or Render
4. Deploy

### 3. ☁️ **Google Cloud Run**
**Best for:** Scalable containerized deployment

### 4. 🏗️ **Heroku**
**Best for:** Traditional web app hosting

## Dockerfile for Alternative Deployments

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 8501

# Health check
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health

# Run the application
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
```

## Why Vercel Isn't Ideal

1. **Size Limit:** Vercel has a 250MB limit for serverless functions
2. **Streamlit Nature:** Streamlit apps require persistent processes
3. **Dependencies:** Heavy dependencies like `androguard` and `cryptography` make the bundle large

## Quick Streamlit Cloud Deployment

1. **Push to GitHub:**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/yourusername/apk-analyzer.git
   git push -u origin main
   ```

2. **Deploy on Streamlit Cloud:**
   - Visit [share.streamlit.io](https://share.streamlit.io)
   - Click "New app"
   - Select your repository
   - Set main file path to `app.py`
   - Click "Deploy"

## Environment Variables for Production

If deploying elsewhere, set these environment variables:

```bash
STREAMLIT_SERVER_PORT=8501
STREAMLIT_SERVER_ADDRESS=0.0.0.0
STREAMLIT_SERVER_HEADLESS=true
STREAMLIT_BROWSER_GATHER_USAGE_STATS=false
```

## File Size Optimization

To reduce deployment size, consider:

1. **Remove unnecessary files:**
   - `__pycache__/` directories
   - `attached_assets/` (if not needed)
   - `.git/` directory
   - `repl_nix_workspace.egg-info/`

2. **Use lighter alternatives:**
   - Consider replacing heavy dependencies
   - Use `--no-deps` for specific packages if possible

3. **Multi-stage Docker builds:**
   - Use Alpine Linux base images
   - Remove build dependencies after installation
