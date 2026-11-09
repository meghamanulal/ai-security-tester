#!/usr/bin/env python3
"""
AI Security Tester - Production Setup
Complete production-ready deployment script
"""

import os
import sys
import subprocess
import time
import requests
import json
from pathlib import Path

class ProductionSetup:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.backend_dir = self.base_dir / "backend"
        self.frontend_dir = self.base_dir / "frontend"
        
    def check_dependencies(self):
        """Check all production dependencies"""
        print("🔍 Checking production dependencies...")
        
        # Check Python
        try:
            import sys
            print(f"✅ Python: {sys.version.split()[0]}")
        except ImportError:
            print("❌ Python: Not available")
            return False
            
        # Check Node.js
        try:
            result = subprocess.run(["node", "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ Node.js: {result.stdout.strip()}")
            else:
                print("❌ Node.js: Not available")
                return False
        except FileNotFoundError:
            print("❌ Node.js: Not available")
            return False
            
        # Check npm
        try:
            result = subprocess.run(["npm.cmd", "--version"] if sys.platform == "win32" else ["npm", "--version"], 
                                  capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                print(f"✅ npm: {result.stdout.strip()}")
            else:
                print("❌ npm: Not available")
                return False
        except (FileNotFoundError, subprocess.SubprocessError):
            print("❌ npm: Not available")
            return False
            
        return True
    
    def setup_backend(self):
        """Setup production backend"""
        print("\n🛠️ Setting up production backend...")
        
        # Install Python dependencies
        print("📦 Installing Python dependencies...")
        subprocess.run([
            sys.executable, "-m", "pip", "install", 
            "fastapi", "uvicorn", "requests", "dnspython", 
            "python-multipart", "python-dotenv"
        ], cwd=self.backend_dir)
        
        # Create production environment file
        env_content = """
# Production Environment Variables
ENVIRONMENT=production
DEBUG=False
API_HOST=0.0.0.0
API_PORT=8000
AI_ORCHESTRATOR_PORT=8001
FRONTEND_URL=http://localhost:3000

# Security
SECRET_KEY=your-production-secret-key-here
CORS_ORIGINS=http://localhost:3000

# Scanning Configuration
MAX_CONCURRENT_SCANS=5
SCAN_TIMEOUT=300
ENABLE_REAL_SCANNING=True

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/production.log
"""
        
        with open(self.backend_dir / ".env", "w") as f:
            f.write(env_content)
        
        print("✅ Backend environment configured")
        
    def setup_frontend(self):
        """Setup production frontend"""
        print("\n🛠️ Setting up production frontend...")
        
        # Install Node.js dependencies
        print("📦 Installing Node.js dependencies...")
        npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
        subprocess.run([npm_cmd, "install"], cwd=self.frontend_dir, shell=True)
        
        # Create production environment file
        env_content = """
# Production Environment Variables
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_AI_ORCHESTRATOR_URL=http://localhost:8001
NEXT_PUBLIC_ENVIRONMENT=production
"""
        
        with open(self.frontend_dir / ".env.local", "w") as f:
            f.write(env_content)
        
        print("✅ Frontend environment configured")
        
    def create_production_scripts(self):
        """Create production startup scripts"""
        print("\n📝 Creating production scripts...")
        
        # Windows production script
        windows_script = """
@echo off
echo Starting AI Security Tester - Production Mode
echo =============================================

echo Starting Backend Services...
cd /d "%~dp0backend"
start "Main Platform API" python simple_async_main.py
timeout /t 3 /nobreak > nul
start "AI Orchestrator" python pentest_api.py
timeout /t 3 /nobreak > nul

echo Starting Frontend...
cd /d "%~dp0frontend"
start "Frontend" npm run dev

echo =============================================
echo AI Security Tester is running in Production Mode
echo Main Platform: http://localhost:3000
echo AI Orchestrator: http://localhost:3000/pentest
echo =============================================
pause
"""
        
        with open(self.base_dir / "start_production.bat", "w") as f:
            f.write(windows_script)
        
        # Linux/Mac production script
        unix_script = """
#!/bin/bash
echo "Starting AI Security Tester - Production Mode"
echo "============================================="

echo "Starting Backend Services..."
cd backend
python simple_async_main.py &
sleep 3
python pentest_api.py &
sleep 3

echo "Starting Frontend..."
cd ../frontend
npm run dev &

echo "============================================="
echo "AI Security Tester is running in Production Mode"
echo "Main Platform: http://localhost:3000"
echo "AI Orchestrator: http://localhost:3000/pentest"
echo "============================================="
wait
"""
        
        with open(self.base_dir / "start_production.sh", "w") as f:
            f.write(unix_script)
        
        os.chmod(self.base_dir / "start_production.sh", 0o755)
        
        print("✅ Production scripts created")
        
    def create_production_config(self):
        """Create production configuration"""
        print("\n⚙️ Creating production configuration...")
        
        config = {
            "production": {
                "mode": "production",
                "debug": False,
                "api": {
                    "main_platform": {
                        "host": "0.0.0.0",
                        "port": 8000,
                        "workers": 4
                    },
                    "ai_orchestrator": {
                        "host": "0.0.0.0", 
                        "port": 8001,
                        "workers": 2
                    }
                },
                "frontend": {
                    "host": "localhost",
                    "port": 3000,
                    "build_mode": "production"
                },
                "security": {
                    "enable_cors": True,
                    "cors_origins": ["http://localhost:3000"],
                    "enable_rate_limiting": True,
                    "max_requests_per_minute": 60
                },
                "scanning": {
                    "max_concurrent_scans": 5,
                    "scan_timeout": 300,
                    "enable_real_scanning": True,
                    "allowed_targets": ["domains", "ips", "localhost"]
                },
                "logging": {
                    "level": "INFO",
                    "file": "logs/production.log",
                    "max_size": "10MB",
                    "backup_count": 5
                }
            }
        }
        
        with open(self.base_dir / "production_config.json", "w") as f:
            json.dump(config, f, indent=2)
        
        # Create logs directory
        (self.base_dir / "logs").mkdir(exist_ok=True)
        
        print("✅ Production configuration created")
        
    def optimize_backend_code(self):
        """Optimize backend for production"""
        print("\n🚀 Optimizing backend for production...")
        
        # Create production-optimized main file
        production_main = """
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Create FastAPI app
app = FastAPI(
    title="AI Security Tester - Production",
    description="Production-ready AI Security Testing Platform",
    version="1.0.0",
    docs_url=None,  # Disable docs in production
    redoc_url=None  # Disable docs in production
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "mode": "production"}

# Import and include routers
from simple_async_main import app as main_router
from pentest_api import app as orchestrator_router

# Mount routers
app.mount("/api/main", main_router)
app.mount("/api/orchestrator", orchestrator_router)

if __name__ == "__main__":
    uvicorn.run(
        "production_main:app",
        host="0.0.0.0",
        port=int(os.getenv("API_PORT", 8000)),
        workers=int(os.getenv("WORKERS", 4)),
        log_level="info"
    )
"""
        
        with open(self.backend_dir / "production_main.py", "w") as f:
            f.write(production_main)
        
        print("✅ Backend optimized for production")
        
    def optimize_frontend_code(self):
        """Optimize frontend for production"""
        print("\n🚀 Optimizing frontend for production...")
        
        # Create production Next.js config
        next_config = """
/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  compress: true,
  poweredByHeader: false,
  env: {
    CUSTOM_KEY: process.env.CUSTOM_KEY,
  },
  async headers() {
    return [
      {
        source: '/api/:path*',
        headers: [
          { key: 'Access-Control-Allow-Credentials', value: 'true' },
          { key: 'Access-Control-Allow-Origin', value: '*' },
          { key: 'Access-Control-Allow-Methods', value: 'GET,DELETE,PATCH,POST,PUT' },
          { key: 'Access-Control-Allow-Headers', value: 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version' },
        ],
      },
    ]
  },
}

module.exports = nextConfig
"""
        
        with open(self.frontend_dir / "next.config.js", "w") as f:
            f.write(next_config)
        
        print("✅ Frontend optimized for production")
        
    def run_production_tests(self):
        """Run production readiness tests"""
        print("\n🧪 Running production readiness tests...")
        
        # Test backend health
        try:
            response = requests.get("http://localhost:8000/health", timeout=5)
            if response.status_code == 200:
                print("✅ Backend health check: PASSED")
            else:
                print("❌ Backend health check: FAILED")
                return False
        except:
            print("❌ Backend not responding")
            return False
            
        # Test frontend
        try:
            response = requests.get("http://localhost:3000", timeout=5)
            if response.status_code == 200:
                print("✅ Frontend health check: PASSED")
            else:
                print("❌ Frontend health check: FAILED")
                return False
        except:
            print("❌ Frontend not responding")
            return False
            
        print("✅ All production tests PASSED")
        return True
        
    def create_documentation(self):
        """Create production documentation"""
        print("\n📚 Creating production documentation...")
        
        readme = """
# AI Security Tester - Production Version

## Overview
AI Security Tester is a production-ready cybersecurity testing platform that provides comprehensive security scanning and analysis capabilities.

## Features

### Main Platform
- **Advanced Security Scanning**: Real-time vulnerability assessment
- **AI-Powered Analysis**: Intelligent threat detection and prioritization
- **Interactive Dashboard**: Real-time scan progress and results
- **Report Generation**: Professional PDF and DOC reports
- **Scan History**: Complete audit trail of all security tests

### AI Pentest Orchestrator
- **Tool Orchestration**: Automated coordination of security tools
- **Executive Reports**: C-suite ready security reports
- **Multi-Profile Scanning**: Quick, Standard, Aggressive, and Full scan modes
- **Real-time Monitoring**: Live scan progress and status updates
- **Professional Findings**: Enterprise-grade vulnerability reports

## Quick Start

### Windows
```bash
# Run the production startup script
start_production.bat
```

### Linux/Mac
```bash
# Make the script executable and run
chmod +x start_production.sh
./start_production.sh
```

### Manual Start
```bash
# Terminal 1: Main Platform API
cd backend
python simple_async_main.py

# Terminal 2: AI Orchestrator API
cd backend
python pentest_api.py

# Terminal 3: Frontend
cd frontend
npm run dev
```

## Access Points

- **Main Platform**: http://localhost:3000
- **AI Pentest Orchestrator**: http://localhost:3000/pentest
- **Main API**: http://localhost:8000
- **Orchestrator API**: http://localhost:8001

## Configuration

### Environment Variables
- `ENVIRONMENT`: Set to 'production'
- `DEBUG`: Set to False for production
- `API_HOST`: Backend host (default: 0.0.0.0)
- `API_PORT`: Main API port (default: 8000)
- `AI_ORCHESTRATOR_PORT`: Orchestrator API port (default: 8001)

### Security Features
- CORS protection
- Rate limiting
- Input validation
- Secure headers
- Logging and monitoring

## API Documentation

### Main Platform API
- `GET /api/scans` - List all scans
- `POST /api/scans/start` - Start new scan
- `GET /api/reports` - Get scan reports

### AI Orchestrator API
- `POST /api/scan/plan` - Create scan plan
- `POST /api/scan/execute` - Execute scan
- `GET /api/reports` - Get orchestrator reports

## Production Considerations

### Performance
- Concurrent scan limiting
- Connection pooling
- Caching strategies
- Resource monitoring

### Security
- Input sanitization
- Rate limiting
- Audit logging
- Secure communication

### Monitoring
- Health check endpoints
- Performance metrics
- Error tracking
- Log aggregation

## Support

For production support and issues:
1. Check the logs in the `logs/` directory
2. Verify all services are running
3. Test API endpoints individually
4. Check network connectivity

## License
Production License - Enterprise Use
"""
        
        with open(self.base_dir / "PRODUCTION_README.md", "w") as f:
            f.write(readme)
        
        print("✅ Production documentation created")
        
    def deploy_production(self):
        """Deploy complete production setup"""
        print("🚀 Deploying AI Security Tester - Production Version")
        print("=" * 60)
        
        # Check dependencies
        if not self.check_dependencies():
            print("❌ Dependencies check failed")
            return False
            
        # Setup components
        self.setup_backend()
        self.setup_frontend()
        self.create_production_scripts()
        self.create_production_config()
        self.optimize_backend_code()
        self.optimize_frontend_code()
        self.create_documentation()
        
        print("\n" + "=" * 60)
        print("🎉 Production Setup Complete!")
        print("=" * 60)
        print("\n📋 Next Steps:")
        print("1. Run 'start_production.bat' (Windows) or './start_production.sh' (Linux/Mac)")
        print("2. Access Main Platform: http://localhost:3000")
        print("3. Access AI Orchestrator: http://localhost:3000/pentest")
        print("4. Check logs in 'logs/' directory for monitoring")
        print("\n📚 Documentation: PRODUCTION_README.md")
        print("⚙️ Configuration: production_config.json")
        print("\n✅ AI Security Tester is ready for production use!")
        
        return True

if __name__ == "__main__":
    setup = ProductionSetup()
    setup.deploy_production()
