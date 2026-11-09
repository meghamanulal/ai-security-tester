from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import asyncio
import uuid
import json
import datetime
import subprocess
import re
import os
from celery import Celery
import redis
import openai
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="AI Security Tester API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

celery_app = Celery(
    'security_scanner',
    broker='redis://localhost:6379/0',
    backend='redis://localhost:6379/0'
)

openai.api_key = os.getenv('OPENAI_API_KEY', 'your-openai-key-here')

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
    results: Optional[Dict[str, Any]] = None

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

@celery_app.task
def run_subdomain_scan(domain: str, scan_id: str):
    try:
        update_scan_progress(scan_id, 10, "Running subdomain enumeration...")
        
        result = subprocess.run(
            ['subfinder', '-d', domain, '-json'],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        subdomains = []
        if result.stdout:
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        if 'host' in data:
                            subdomains.append(data['host'])
                    except json.JSONDecodeError:
                        continue
        
        redis_client.hset(f"scan:{scan_id}", "subdomains", json.dumps(subdomains))
        update_scan_progress(scan_id, 30, f"Found {len(subdomains)} subdomains")
        
        return subdomains
    except Exception as e:
        update_scan_progress(scan_id, 0, f"Subdomain scan failed: {str(e)}")
        return []

@celery_app.task
def run_port_scan(targets: List[str], scan_id: str):
    try:
        update_scan_progress(scan_id, 40, "Running port scan...")
        
        open_ports = {}
        for target in targets[:10]:
            try:
                result = subprocess.run(
                    ['nmap', '-sS', '-T4', '-p', '1-1000', target],
                    capture_output=True,
                    text=True,
                    timeout=180
                )
                
                ports = []
                for line in result.stdout.split('\n'):
                    if '/tcp' in line and 'open' in line:
                        match = re.search(r'(\d+)/tcp\s+open\s+(\w+)', line)
                        if match:
                            ports.append(f"{match.group(1)}/{match.group(2)}")
                
                open_ports[target] = ports
            except Exception as e:
                print(f"Error scanning {target}: {e}")
                continue
        
        redis_client.hset(f"scan:{scan_id}", "open_ports", json.dumps(open_ports))
        update_scan_progress(scan_id, 70, f"Port scan completed")
        
        return open_ports
    except Exception as e:
        update_scan_progress(scan_id, 0, f"Port scan failed: {str(e)}")
        return {}

@celery_app.task
def analyze_vulnerabilities(scan_data: Dict[str, Any], scan_id: str):
    try:
        update_scan_progress(scan_id, 80, "Analyzing vulnerabilities...")
        
        vulnerabilities = []
        
        open_ports = scan_data.get('open_ports', {})
        for target, ports in open_ports.items():
            for port in ports:
                port_num = port.split('/')[0]
                
                if port_num in ['21', '23', '25', '53', '135', '139', '445']:
                    vulnerabilities.append({
                        'target': target,
                        'port': port,
                        'severity': 'medium',
                        'description': f'Potentially vulnerable service running on port {port_num}',
                        'recommendation': 'Review service necessity and secure configuration'
                    })
                elif port_num in ['80', '443', '8080', '8443']:
                    vulnerabilities.append({
                        'target': target,
                        'port': port,
                        'severity': 'low',
                        'description': f'Web service detected on port {port_num}',
                        'recommendation': 'Perform web application security testing'
                    })
        
        redis_client.hset(f"scan:{scan_id}", "vulnerabilities", json.dumps(vulnerabilities))
        update_scan_progress(scan_id, 100, f"Scan completed - {len(vulnerabilities)} vulnerabilities found")
        
        return vulnerabilities
    except Exception as e:
        update_scan_progress(scan_id, 0, f"Vulnerability analysis failed: {str(e)}")
        return []

def update_scan_progress(scan_id: str, progress: int, message: str = ""):
    scan_data = redis_client.hgetall(f"scan:{scan_id}")
    if scan_data:
        scan_data['progress'] = str(progress)
        scan_data['status'] = 'completed' if progress == 100 else 'running'
        if message:
            scan_data['message'] = message
        redis_client.hset(f"scan:{scan_id}", mapping=scan_data)

@app.post("/api/start_scan")
async def start_scan_alt(request: ScanRequest, background_tasks: BackgroundTasks):
    return await start_scan(request, background_tasks)

@app.post("/api/scans/start")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    
    scan_data = {
        'id': scan_id,
        'domain': request.domain,
        'status': 'pending',
        'progress': '0',
        'startTime': datetime.datetime.now().isoformat(),
        'vulnerabilities': '0',
        'subdomains': '0',
        'openPorts': '0'
    }
    
    redis_client.hset(f"scan:{scan_id}", mapping=scan_data)
    
    background_tasks.add_task(run_full_scan, request.domain, scan_id)
    
    return {"scanId": scan_id, "status": "started"}

async def run_full_scan(domain: str, scan_id: str):
    try:
        update_scan_progress(scan_id, 5, "Initializing scan...")
        
        subdomains_task = run_subdomain_scan.delay(domain, scan_id)
        subdomains = subdomains_task.get(timeout=600)
        
        all_targets = [domain] + subdomains
        
        ports_task = run_port_scan.delay(all_targets, scan_id)
        open_ports_result = ports_task.get(timeout=600)
        
        scan_data = {
            'subdomains': json.dumps(subdomains),
            'open_ports': json.dumps(open_ports_result)
        }
        
        vulns_task = analyze_vulnerabilities.delay(scan_data, scan_id)
        vulnerabilities = vulns_task.get(timeout=300)
        
        redis_client.hset(f"scan:{scan_id}", "vulnerabilities", str(len(vulnerabilities)))
        redis_client.hset(f"scan:{scan_id}", "subdomains", str(len(subdomains)))
        
        total_ports = sum(len(ports) for ports in open_ports_result.values())
        redis_client.hset(f"scan:{scan_id}", "openPorts", str(total_ports))
        
        redis_client.hset(f"scan:{scan_id}", "endTime", datetime.datetime.now().isoformat())
        update_scan_progress(scan_id, 100, "Scan completed successfully")
        
    except Exception as e:
        redis_client.hset(f"scan:{scan_id}", "status", "failed")
        redis_client.hset(f"scan:{scan_id}", "message", f"Scan failed: {str(e)}")

@app.get("/api/scans")
async def get_scans():
    scans = []
    scan_keys = redis_client.keys("scan:*")
    
    for key in scan_keys:
        scan_data = redis_client.hgetall(key)
        if scan_data:
            scans.append(Scan(
                id=scan_data.get('id', ''),
                domain=scan_data.get('domain', ''),
                status=scan_data.get('status', 'unknown'),
                progress=int(scan_data.get('progress', 0)),
                startTime=scan_data.get('startTime', ''),
                endTime=scan_data.get('endTime'),
                vulnerabilities=int(scan_data.get('vulnerabilities', 0)) if scan_data.get('vulnerabilities') else None,
                subdomains=int(scan_data.get('subdomains', 0)) if scan_data.get('subdomains') else None,
                openPorts=int(scan_data.get('openPorts', 0)) if scan_data.get('openPorts') else None
            ))
    
    return sorted(scans, key=lambda x: x.startTime, reverse=True)

@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    scan_data = redis_client.hgetall(f"scan:{scan_id}")
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return Scan(
        id=scan_data.get('id', ''),
        domain=scan_data.get('domain', ''),
        status=scan_data.get('status', 'unknown'),
        progress=int(scan_data.get('progress', 0)),
        startTime=scan_data.get('startTime', ''),
        endTime=scan_data.get('endTime'),
        vulnerabilities=int(scan_data.get('vulnerabilities', 0)) if scan_data.get('vulnerabilities') else None,
        subdomains=int(scan_data.get('subdomains', 0)) if scan_data.get('subdomains') else None,
        openPorts=int(scan_data.get('openPorts', 0)) if scan_data.get('openPorts') else None
    )

@app.get("/api/scans/{scan_id}/report")
async def get_scan_report(scan_id: str):
    scan_data = redis_client.hgetall(f"scan:{scan_id}")
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    subdomains = json.loads(scan_data.get('subdomains', '[]'))
    open_ports = json.loads(scan_data.get('open_ports', '{}'))
    vulnerabilities = json.loads(scan_data.get('vulnerabilities', '[]'))
    
    report = f"""
    <html>
    <head><title>Security Scan Report - {scan_data.get('domain', 'Unknown')}</title></head>
    <body>
        <h1>Security Scan Report</h1>
        <h2>Target: {scan_data.get('domain', 'Unknown')}</h2>
        <p>Scan Date: {scan_data.get('startTime', 'Unknown')}</p>
        
        <h3>Executive Summary</h3>
        <ul>
            <li>Total Subdomains Found: {len(subdomains)}</li>
            <li>Total Open Ports: {sum(len(ports) for ports in open_ports.values())}</li>
            <li>Total Vulnerabilities: {len(vulnerabilities)}</li>
        </ul>
        
        <h3>Subdomains</h3>
        <ul>
            {"".join([f"<li>{subdomain}</li>" for subdomain in subdomains])}
        </ul>
        
        <h3>Open Ports</h3>
        {"".join([f"<h4>{target}</h4><ul>{''.join([f'<li>{port}</li>' for port in ports])}</ul>" for target, ports in open_ports.items()])}
        
        <h3>Vulnerabilities</h3>
        {"".join([f"""
        <div style="border: 1px solid #ccc; margin: 10px 0; padding: 10px;">
            <h4>{vuln.get('severity', 'unknown').title()} - {vuln.get('target', 'Unknown')}</h4>
            <p><strong>Port:</strong> {vuln.get('port', 'Unknown')}</p>
            <p><strong>Description:</strong> {vuln.get('description', 'No description')}</p>
            <p><strong>Recommendation:</strong> {vuln.get('recommendation', 'No recommendation')}</p>
        </div>
        """ for vuln in vulnerabilities])}
    </body>
    </html>
    """
    
    return HTMLResponse(content=report)

@app.post("/api/chat")
async def chat_with_ai(request: ChatRequest):
    try:
        context = ""
        if request.scanId:
            scan_data = redis_client.hgetall(f"scan:{request.scanId}")
            if scan_data:
                vulnerabilities = json.loads(scan_data.get('vulnerabilities', '[]'))
                subdomains = json.loads(scan_data.get('subdomains', '[]'))
                open_ports = json.loads(scan_data.get('open_ports', '{}'))
                
                context = f"""
                Scan Context for {scan_data.get('domain', 'Unknown')}:
                - Subdomains found: {len(subdomains)}
                - Open ports: {sum(len(ports) for ports in open_ports.values())}
                - Vulnerabilities: {len(vulnerabilities)}
                - Recent vulnerabilities: {vulnerabilities[:3] if vulnerabilities else 'None'}
                """
        
        messages = [
            {"role": "system", "content": f"""You are an AI security assistant specializing in vulnerability analysis and penetration testing. 
            Provide helpful, actionable security advice. Focus on explaining vulnerabilities clearly and suggesting remediation steps.
            {context}"""},
            {"role": "user", "content": request.message}
        ]
        
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=messages,
            max_tokens=500,
            temperature=0.7
        )
        
        return {"response": response.choices[0].message.content}
        
    except Exception as e:
        return {"response": f"I apologize, but I'm having trouble processing your request right now. Error: {str(e)}"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await manager.send_personal_message(f"Message received: {data}", websocket)
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/")
async def root():
    return {"message": "AI Security Tester API is running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
