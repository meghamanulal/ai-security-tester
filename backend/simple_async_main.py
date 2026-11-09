from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import asyncio
import uuid
import json
import datetime
import time
import logging
from concurrent.futures import ThreadPoolExecutor
from fastapi.staticfiles import StaticFiles
import os
import tempfile

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="AI Security Tester API", version="2.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for scans
scans_db = {}

# Thread pool for background tasks
executor = ThreadPoolExecutor(max_workers=4)

class ScanRequest(BaseModel):
    domain: str

class ChatRequest(BaseModel):
    message: str
    scanId: Optional[str] = None

class Scan(BaseModel):
    id: str
    domain: str
    status: str
    progress: int
    startTime: str
    endTime: Optional[str] = None
    vulnerabilities: Optional[int] = None
    subdomains: Optional[int] = None
    openPorts: Optional[int] = None

def update_scan_progress(scan_id: str, progress: int, message: str = ""):
    """Update scan progress"""
    if scan_id in scans_db:
        scans_db[scan_id]['progress'] = progress
        scans_db[scan_id]['status'] = 'completed' if progress == 100 else 'running'
        if message:
            scans_db[scan_id]['current_stage'] = message
        scans_db[scan_id]['last_updated'] = datetime.datetime.now().isoformat()

# Health check endpoints
@app.get("/")
async def root():
    """Instant health check endpoint"""
    return {
        "status": "API running",
        "service": "AI Security Scanner",
        "version": "2.1.0",
        "timestamp": datetime.datetime.now().isoformat()
    }

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.datetime.now().isoformat()
    }

# Scan endpoints
@app.post("/api/start_scan")
async def start_scan_alt(request: ScanRequest, background_tasks: BackgroundTasks):
    return await start_scan(request, background_tasks)

@app.post("/api/scans/start")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new scan - returns immediately, runs in background"""
    try:
        # Validate domain format
        domain = request.domain.strip()
        if not domain:
            raise HTTPException(status_code=400, detail="Domain cannot be empty")
        
        # Very permissive validation - allow most inputs
        import re
        # Allow domains, IPs, subdomains, localhost, etc.
        if len(domain) < 1 or len(domain) > 253:
            raise HTTPException(status_code=400, detail="Domain must be 1-253 characters long")
        
        # Basic check for invalid characters only
        if re.search(r'[<>\"\'\s]', domain):
            raise HTTPException(status_code=400, detail="Domain contains invalid characters")
        
        scan_id = str(uuid.uuid4())
        
        # Create initial scan record
        scan_data = {
            'id': scan_id,
            'domain': domain,
            'status': 'queued',
            'progress': 0,
            'startTime': datetime.datetime.now().isoformat(),
            'vulnerabilities': 0,
            'subdomains': 0,
            'openPorts': 0,
            'current_stage': 'Queued for processing',
            'last_updated': datetime.datetime.now().isoformat()
        }
        
        # Save scan data
        scans_db[scan_id] = scan_data
        
        # Start the scan in background
        background_tasks.add_task(run_pentesting_scan, scan_id, domain)
        
        logger.info(f"Queued scan {scan_id} for domain {domain}")
        
        return {
            "scan_id": scan_id,
            "status": "queued",
            "message": "Scan queued for processing"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")

@app.get("/api/reports")
async def get_past_reports():
    """Get all completed scan reports"""
    try:
        completed_scans = []
        for scan_id, scan_data in scans_db.items():
            if scan_data.get('status') == 'completed' and 'pentesting_results' in scan_data:
                completed_scans.append({
                    'id': scan_id,
                    'domain': scan_data.get('domain', ''),
                    'startTime': scan_data.get('startTime', ''),
                    'endTime': scan_data.get('endTime', ''),
                    'subdomains': scan_data.get('subdomains', 0),
                    'openPorts': scan_data.get('openPorts', 0),
                    'vulnerabilities': scan_data.get('vulnerabilities', 0),
                    'adminPanels': scan_data.get('adminPanels', 0),
                    'backupFiles': scan_data.get('backupFiles', 0),
                    'attackPaths': scan_data.get('attackPaths', 0),
                    'riskLevel': scan_data.get('pentesting_results', {}).get('ai_reasoning_analysis', {}).get('risk_level', 'Unknown')
                })
        
        # Sort by endTime (most recent first)
        completed_scans.sort(key=lambda x: x.get('endTime', ''), reverse=True)
        
        return {
            'reports': completed_scans,
            'total': len(completed_scans)
        }
    except Exception as e:
        logger.error(f"Failed to get past reports: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve past reports")

@app.get("/api/reports/{scan_id}")
async def get_past_report_details(scan_id: str):
    """Get detailed information about a past report"""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Report not found")
    
    scan_data = scans_db[scan_id]
    
    if scan_data.get('status') != 'completed' or 'pentesting_results' not in scan_data:
        raise HTTPException(status_code=404, detail="Report not available")
    
    try:
        from enhanced_report_generator import EnhancedReportGenerator
        pentesting_results = scan_data['pentesting_results']
        report_generator = EnhancedReportGenerator(pentesting_results)
        
        # Generate enhanced HTML report
        html_content = report_generator.generate_html_report()
        
        return HTMLResponse(content=html_content)
    except Exception as e:
        logger.error(f"Failed to generate past report details for {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate report details")

@app.get("/api/scans")
async def get_scans():
    """Get all scans"""
    try:
        scans = []
        for scan_data in scans_db.values():
            scans.append(Scan(
                id=scan_data.get('id', ''),
                domain=scan_data.get('domain', ''),
                status=scan_data.get('status', 'unknown'),
                progress=int(scan_data.get('progress', 0)),
                startTime=scan_data.get('startTime', ''),
                endTime=scan_data.get('endTime'),
                vulnerabilities=int(scan_data.get('vulnerabilities', 0)) if scan_data.get('vulnerabilities') is not None else None,
                subdomains=int(scan_data.get('subdomains', 0)) if scan_data.get('subdomains') is not None else None,
                openPorts=int(scan_data.get('openPorts', 0)) if scan_data.get('openPorts') is not None else None
            ))
        
        return sorted(scans, key=lambda x: x.startTime, reverse=True)
        
    except Exception as e:
        logger.error(f"Error getting scans: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve scans")

@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Get specific scan details"""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scans_db[scan_id]
    return Scan(
        id=scan_data.get('id', ''),
        domain=scan_data.get('domain', ''),
        status=scan_data.get('status', 'unknown'),
        progress=int(scan_data.get('progress', 0)),
        startTime=scan_data.get('startTime', ''),
        endTime=scan_data.get('endTime'),
        vulnerabilities=int(scan_data.get('vulnerabilities', 0)) if scan_data.get('vulnerabilities') is not None else None,
        subdomains=int(scan_data.get('subdomains', 0)) if scan_data.get('subdomains') is not None else None,
        openPorts=int(scan_data.get('openPorts', 0)) if scan_data.get('openPorts') is not None else None
    )

@app.get("/api/scans/{scan_id}/report/pdf")
async def download_pdf_report(scan_id: str):
    """Download scan report as PDF"""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scans_db[scan_id]
    
    if 'pentesting_results' not in scan_data:
        raise HTTPException(status_code=404, detail="Report not available")
    
    try:
        from enhanced_report_generator import EnhancedReportGenerator
        pentesting_results = scan_data['pentesting_results']
        report_generator = EnhancedReportGenerator(pentesting_results)
        
        # Generate PDF report
        pdf_path = report_generator.generate_pdf_report()
        
        # Return file response
        return FileResponse(
            pdf_path,
            media_type='application/pdf',
            filename=f"pentesting_report_{scan_data['domain']}_{scan_id}.pdf"
        )
    except ImportError as e:
        raise HTTPException(status_code=501, detail=f"PDF generation not available: {str(e)}")
    except Exception as e:
        logger.error(f"PDF generation failed for {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="PDF generation failed")

@app.get("/api/scans/{scan_id}/report/doc")
async def download_doc_report(scan_id: str):
    """Download scan report as DOC"""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scans_db[scan_id]
    
    if 'pentesting_results' not in scan_data:
        raise HTTPException(status_code=404, detail="Report not available")
    
    try:
        from enhanced_report_generator import EnhancedReportGenerator
        pentesting_results = scan_data['pentesting_results']
        report_generator = EnhancedReportGenerator(pentesting_results)
        
        # Generate DOC report
        doc_path = report_generator.generate_doc_report()
        
        # Return file response
        return FileResponse(
            doc_path,
            media_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            filename=f"pentesting_report_{scan_data['domain']}_{scan_id}.docx"
        )
    except ImportError as e:
        raise HTTPException(status_code=501, detail=f"DOC generation not available: {str(e)}")
    except Exception as e:
        logger.error(f"DOC generation failed for {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="DOC generation failed")

@app.get("/api/scans/{scan_id}/report/html")
async def download_html_report(scan_id: str):
    """Download scan report as HTML"""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scans_db[scan_id]
    
    if 'pentesting_results' not in scan_data:
        raise HTTPException(status_code=404, detail="Report not available")
    
    try:
        from enhanced_report_generator import EnhancedReportGenerator
        pentesting_results = scan_data['pentesting_results']
        report_generator = EnhancedReportGenerator(pentesting_results)
        
        # Generate HTML report
        html_content = report_generator.generate_html_report()
        
        # Return HTML response
        return HTMLResponse(content=html_content)
    except Exception as e:
        logger.error(f"HTML generation failed for {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="HTML generation failed")

@app.get("/api/scans/{scan_id}/report")
async def get_scan_report(scan_id: str):
    """Get detailed scan report"""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scans_db[scan_id]
    
    # Check if we have professional pentesting results
    if 'pentesting_results' in scan_data:
        from advanced_pentesting_scanner import AdvancedPentestingScanner
        from professional_report_generator import ProfessionalReportGenerator
        pentesting_results = scan_data['pentesting_results']
        report_generator = ProfessionalReportGenerator(pentesting_results)
        report_html = report_generator.generate_professional_html_report()
        return HTMLResponse(content=report_html)
    
    # Fallback report
    return HTMLResponse(content=f"""
    <html>
    <head><title>Professional Pentesting Report - {scan_data.get('domain', 'Unknown')}</title></head>
    <body style="font-family: Arial, sans-serif; margin: 40px;">
        <h1 style="color: #333;">Professional Pentesting Report</h1>
        <h2>Target: {scan_data.get('domain', 'Unknown')}</h2>
        <p><strong>Status:</strong> {scan_data.get('status', 'Unknown')}</p>
        <p><strong>Progress:</strong> {scan_data.get('progress', 0)}%</p>
        <p><strong>Current Stage:</strong> {scan_data.get('current_stage', 'Unknown')}</p>
        <p><strong>Scan Date:</strong> {scan_data.get('startTime', 'Unknown')}</p>
        
        <div style="margin-top: 20px; padding: 15px; background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 5px;">
            <p><strong>⚠️ Professional Pentesting Pipeline</strong></p>
            <p>Scan status: {scan_data.get('status', 'Unknown')}</p>
            {f'<p>Current stage: {scan_data.get("current_stage", "Unknown")}</p>' if scan_data.get('current_stage') else ''}
        </div>
    </body>
    </html>
    """)

@app.post("/api/chat")
async def chat_with_ai(request: ChatRequest):
    """AI chat endpoint - returns immediately"""
    try:
        responses = [
            "Based on the professional pentesting pipeline, I recommend reviewing all findings and prioritizing critical vulnerabilities.",
            "The comprehensive security assessment includes multiple scanning stages for thorough coverage.",
            "For the vulnerabilities detected, I suggest following standard remediation practices and re-scanning after fixes.",
            "The multi-stage scanning approach ensures comprehensive coverage of your security posture."
        ]
        
        import random
        response_text = random.choice(responses)
        
        if request.scanId and request.scanId in scans_db:
            scan_data = scans_db[request.scanId]
            domain = scan_data.get('domain', 'Unknown')
            status = scan_data.get('status', 'Unknown')
            progress = scan_data.get('progress', 0)
            
            response_text = f"For scan of {domain} (Status: {status}, Progress: {progress}%): {response_text}"
        
        return {"response": response_text}
        
    except Exception as e:
        logger.error(f"Error in chat: {e}")
        return {"response": "I'm here to help with security questions. Please ask about your scan results or security recommendations."}

async def run_pentesting_scan(scan_id: str, domain: str):
    """Run attack surface scan in background"""
    try:
        logger.info(f"Starting background scan for {scan_id} on domain {domain}")
        
        # Update status
        update_scan_progress(scan_id, 5, "Initializing attack surface scanning pipeline...")
        
        # Import attack surface scanner with proper path handling
        import sys
        import os
        current_dir = os.path.dirname(os.path.abspath(__file__))
        if current_dir not in sys.path:
            sys.path.insert(0, current_dir)
        
        try:
            from advanced_pentesting_scanner import AdvancedPentestingScanner
            scanner = AdvancedPentestingScanner(domain)
            
            # Run complete advanced pentesting pipeline
            update_scan_progress(scan_id, 10, "Stage 1: Target validation and DNS resolution...")
            pentesting_results = scanner.run_advanced_pentesting_pipeline()
            
            if 'error' in pentesting_results:
                raise Exception(pentesting_results['error'])
            
            # Store results
            if scan_id in scans_db:
                scan_data = scans_db[scan_id]
                scan_data['pentesting_results'] = pentesting_results
                
                # Update counts for advanced pentesting results
                attack_surface = pentesting_results.get('attack_surface_mapping', {})
                discovered_endpoints = pentesting_results.get('endpoint_discovery', {})
                vulnerabilities = pentesting_results.get('vulnerability_findings', {})
                attack_paths = pentesting_results.get('attack_path_analysis', {})
                
                scan_data['subdomains'] = len(attack_surface.get('subdomains', []))
                scan_data['openPorts'] = sum(len(ports) for ports in pentesting_results.get('port_scanning_results', {}).values())
                scan_data['vulnerabilities'] = sum(len(vulns) for vulns in vulnerabilities.values())
                scan_data['adminPanels'] = len(discovered_endpoints.get('admin_panels', []))
                scan_data['backupFiles'] = len(discovered_endpoints.get('backup_files', []))
                scan_data['attackPaths'] = len(attack_paths.get('attack_paths', []))
                scan_data['endTime'] = datetime.datetime.now().isoformat()
                
                scans_db[scan_id] = scan_data
            
            update_scan_progress(scan_id, 100, "Advanced pentesting pipeline completed successfully")
            logger.info(f"Completed background scan for {scan_id}")
            
        except Exception as scanner_error:
            logger.error(f"Scanner error for {scan_id}: {scanner_error}")
            # Update scan with error
            if scan_id in scans_db:
                scan_data = scans_db[scan_id]
                scan_data['status'] = 'failed'
                scan_data['error'] = str(scanner_error)
                scan_data['endTime'] = datetime.datetime.now().isoformat()
                scans_db[scan_id] = scan_data
        
    except Exception as e:
        logger.error(f"Background scan failed for {scan_id}: {e}")
        
        # Update scan with error
        if scan_id in scans_db:
            scan_data = scans_db[scan_id]
            scan_data['status'] = 'failed'
            scan_data['error'] = str(e)
            scan_data['endTime'] = datetime.datetime.now().isoformat()
            scans_db[scan_id] = scan_data

if __name__ == "__main__":
    import uvicorn
    logger.info("Starting AI Security Tester API v2.1.0")
    uvicorn.run(app, host="0.0.0.0", port=8000)
