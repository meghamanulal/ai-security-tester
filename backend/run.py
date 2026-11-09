#!/usr/bin/env python3
"""
AI Security Tester - Unified Entry Point
=====================================

This is the main entry point for the AI Security Tester platform.
It provides options to run different components:

1. Main API Server (Port 8000) - Advanced pentesting with PDF/DOC reports
2. AI Pentest Orchestrator (Port 8001) - Professional pentest orchestration
3. Both services simultaneously

Usage:
    python run.py --service [main|orchestrator|both]
"""

import argparse
import sys
import subprocess
import time
import signal
import os

def run_main_api():
    """Run the main API server on port 8000"""
    print("🚀 Starting Main API Server on port 8000...")
    print("   - Advanced Pentesting Scanner")
    print("   - PDF/DOC Report Generation") 
    print("   - Past Reports Management")
    print("   - Frontend Integration")
    print()
    
    try:
        from simple_async_main import app
        import uvicorn
        uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
    except ImportError as e:
        print(f"❌ Error importing main API: {e}")
        print("   Make sure all dependencies are installed: pip install -r requirements.txt")
        return False
    except Exception as e:
        print(f"❌ Error running main API: {e}")
        return False

def run_pentest_orchestrator():
    """Run the AI Pentest Orchestrator on port 8001"""
    print("🎯 Starting AI Pentest Orchestrator on port 8001...")
    print("   - Professional Tool Orchestration")
    print("   - AI-Powered Analysis")
    print("   - Executive Reporting")
    print("   - Real-time Scan Status")
    print()
    
    try:
        import uvicorn
        uvicorn.run("pentest_api:app", host="0.0.0.0", port=8001, reload=False)
    except ImportError as e:
        print(f"❌ Error importing pentest orchestrator: {e}")
        print("   Make sure all dependencies are installed: pip install -r requirements.txt")
        return False
    except Exception as e:
        print(f"❌ Error running pentest orchestrator: {e}")
        return False

def run_both():
    """Run both services simultaneously"""
    print("🚀 Starting Both Services...")
    print("   - Main API: http://localhost:8000")
    print("   - Pentest Orchestrator: http://localhost:8001")
    print()
    
    try:
        # Start both services in background processes
        processes = []
        
        # Start main API
        print("Starting Main API Server...")
        main_proc = subprocess.Popen([
            sys.executable, "-c", 
            "from simple_async_main import app; "
            "import uvicorn; "
            "uvicorn.run(app, host='0.0.0.0', port=8000, reload=False)"
        ])
        processes.append(main_proc)
        
        # Give main API time to start
        time.sleep(2)
        
        # Start pentest orchestrator
        print("Starting AI Pentest Orchestrator...")
        orchestrator_proc = subprocess.Popen([
            sys.executable, "-c",
            "import uvicorn; "
            "uvicorn.run('pentest_api:app', host='0.0.0.0', port=8001, reload=False)"
        ])
        processes.append(orchestrator_proc)
        
        print("✅ Both services started successfully!")
        print("   Main API: http://localhost:8000")
        print("   Pentest Orchestrator: http://localhost:8001")
        print("   Frontend: http://localhost:3000")
        print()
        print("Press Ctrl+C to stop both services")
        
        # Wait for processes
        try:
            for proc in processes:
                proc.wait()
        except KeyboardInterrupt:
            print("\n🛑 Stopping services...")
            for proc in processes:
                proc.terminate()
                proc.wait()
            print("✅ All services stopped")
            
        return True
        
    except Exception as e:
        print(f"❌ Error running services: {e}")
        # Cleanup processes on error
        for proc in processes:
            try:
                proc.terminate()
                proc.wait()
            except:
                pass
        return False

def check_dependencies():
    """Check if all required dependencies are installed"""
    print("🔍 Checking dependencies...")
    
    required_modules = [
        'fastapi', 'uvicorn', 'pydantic', 'requests',
        'reportlab', 'docx', 'xmltodict'
    ]
    
    missing = []
    for module in required_modules:
        try:
            if module == 'docx':
                __import__('docx')
            else:
                __import__(module)
        except ImportError:
            missing.append(module)
    
    if missing:
        print(f"❌ Missing dependencies: {', '.join(missing)}")
        print("   Install with: pip install -r requirements.txt")
        return False
    
    print("✅ All dependencies satisfied")
    return True

def main():
    parser = argparse.ArgumentParser(
        description="AI Security Tester - Unified Entry Point",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py --service main           # Run main API only
  python run.py --service orchestrator  # Run pentest orchestrator only  
  python run.py --service both          # Run both services
        """
    )
    
    parser.add_argument(
        '--service',
        choices=['main', 'orchestrator', 'both'],
        default='both',
        help='Service to run (default: both)'
    )
    
    parser.add_argument(
        '--check-deps',
        action='store_true',
        help='Check dependencies only'
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("🛡️  AI Security Tester - Professional Security Platform")
    print("=" * 60)
    print()
    
    # Check dependencies first
    if not check_dependencies():
        sys.exit(1)
    
    if args.check_deps:
        print("✅ Dependencies check completed")
        return
    
    # Run the requested service
    if args.service == 'main':
        success = run_main_api()
    elif args.service == 'orchestrator':
        success = run_pentest_orchestrator()
    elif args.service == 'both':
        success = run_both()
    else:
        print(f"❌ Unknown service: {args.service}")
        success = False
    
    if success:
        print("\n✅ Service completed successfully")
    else:
        print("\n❌ Service failed")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n🛑 Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        sys.exit(1)
