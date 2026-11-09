# 🛡️ AI Security Tester - Professional Security Platform

A comprehensive AI-powered security testing platform with advanced penetration testing capabilities, professional reporting, and intelligent vulnerability analysis.

## 🚀 Features

### 🔍 **Main Platform (Port 8000)**
- **Advanced Pentesting Scanner**: Complete attack surface mapping
- **AI-Powered Analysis**: Attack path identification and reasoning
- **Multiple Report Formats**: PDF, DOC, HTML downloads
- **Past Reports Management**: Complete scan history
- **Real-time Scanning**: Live progress updates
- **Professional UI**: Modern, responsive interface

### 🎯 **AI Pentest Orchestrator (Port 8001)**
- **Tool Orchestration**: Nmap, Nuclei, SSLscan, Nikto, etc.
- **Profile-Based Scanning**: Quick, Standard, Aggressive, Full
- **Intelligent Planning**: Automated scan plan generation
- **Human-Like Analysis**: Vulnerability triage and attack paths
- **Executive Reporting**: Business-ready security reports
- **Real-time Status**: Live scan progress monitoring

### Frontend
- **Next.js 14** with TypeScript
- **Tailwind CSS** for styling
- **Lucide React** for icons
- **Axios** for API communication

### Backend
- **FastAPI** for REST API
- **Celery** with Redis for background task processing
- **Real Security Tools**:
  - **Nmap** for port scanning and service detection
  - **Nikto** for web vulnerability scanning
  - **Nuclei** for template-based vulnerability detection
- **OpenAI API** for AI analysis
- **Redis** for caching and session management

## Prerequisites

Before you begin, ensure you have the following installed:

- Node.js (v18 or higher)
- Python (v3.8 or higher)
- Redis server
- **Security Tools**: Nmap, Nikto, Nuclei, Go

### Installing Security Tools

#### Windows
Run the provided PowerShell script as Administrator:
```bash
.\setup_tools.ps1
```

Or install manually:
```bash
# Install Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install tools
choco install nmap golang strawberryperl -y

# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Install Nikto
git clone https://github.com/sullo/nikto.git
# nikto.pl will be in the program/ directory
```

#### macOS/Linux
Run the provided shell script:
```bash
chmod +x setup_tools.sh
./setup_tools.sh
```

Or install manually:
```bash
# macOS
brew install nmap golang nikto

# Linux (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y nmap golang-go nikto

# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update Nuclei templates
nuclei -update-templates
```

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd ai-security-tester
   ```

2. **Set up the Backend**
   ```bash
   cd backend
   
   # Create virtual environment
   python -m venv venv
   
   # Activate virtual environment
   # Windows
   venv\Scripts\activate
   # macOS/Linux
   source venv/bin/activate
   
   # Install dependencies
   pip install -r requirements.txt
   
   # Set up environment variables
   cp .env.example .env
   # Edit .env and add your OpenAI API key
   ```

3. **Set up the Frontend**
   ```bash
   cd ../frontend
   
   # Install dependencies
   npm install
   ```

## Running the Application

### Step 1: Start Redis
```bash
redis-server
```

### Step 2: Start Celery Worker
```bash
cd backend
python celery_worker.py
```

### Step 3: Start the Backend API
```bash
cd backend
python main.py
```

### Step 4: Start the Frontend
```bash
cd frontend
npm run dev
```

The application will be available at:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Documentation: http://localhost:8000/docs

## Usage

1. **Start a Security Scan**
   - Enter a target domain (e.g., example.com)
   - Click "Start Scan"
   - Monitor real-time progress with detailed status messages

2. **View Detailed Scan Results**
   - Click on a completed scan in the history
   - View detailed findings including:
     - **Open Ports**: Port numbers, services, and versions
     - **Web Vulnerabilities**: Nikto findings with URLs and descriptions
     - **Nuclei Findings**: Template-based vulnerabilities with severity levels
     - **Security Headers**: Missing and present HTTP security headers
   - Download full HTML report with professional formatting

3. **Chat with AI Assistant**
   - Ask questions about specific vulnerabilities
   - Get context-aware security recommendations
   - Discuss remediation strategies

## Scan Output Examples

### Nmap Results
```
OPEN PORTS
22/tcp   open   ssh        OpenSSH 8.2p1
80/tcp   open   http       nginx 1.18.0
443/tcp  open   https      nginx 1.18.0
```

### Nikto Results
```
WEB SERVER FINDINGS
- Server: nginx/1.18.0
- X-Powered-By header exposed: PHP/7.4.3
- Directory indexing enabled: /uploads/
- Retrieved x-powered-by header: PHP/7.4.3
```

### Nuclei Results
```
NUCLEI FINDINGS
[medium] exposed-git-config
URL: https://site/.git/config
Template: git-config-exposure

[high] wordpress-xmlrpc-enabled  
URL: https://site/xmlrpc.php
Template: wordpress-xmlrpc
```

### Security Headers Analysis
```
SECURITY HEADERS
Present:
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin

Missing:
- X-Frame-Options
- Content-Security-Policy
- Strict-Transport-Security
```

## API Endpoints

### Scans
- `POST /api/scans/start` - Start a new scan
- `GET /api/scans` - Get all scans
- `GET /api/scans/{scan_id}` - Get specific scan
- `GET /api/scans/{scan_id}/report` - Download scan report

### Chat
- `POST /api/chat` - Chat with AI assistant

### WebSocket
- `WS /ws` - Real-time updates

## Configuration

### Environment Variables

Create a `.env` file in the backend directory:

```env
OPENAI_API_KEY=your-openai-api-key-here
REDIS_URL=redis://localhost:6379/0
```

### Scan Configuration

You can modify scan parameters in `backend/main.py`:
- Nmap port range and scan type
- Subfinder configuration
- Vulnerability detection rules
- AI prompts and context

## Security Considerations

⚠️ **Important**: This tool is for educational and authorized testing purposes only.

- Only scan domains you own or have explicit permission to test
- Ensure compliance with local laws and regulations
- Rate-limit scans to avoid overwhelming target systems
- Store API keys securely
- Consider implementing authentication for production use

## Troubleshooting

### Common Issues

1. **Redis Connection Error**
   - Ensure Redis server is running
   - Check Redis configuration in `.env`

2. **Nmap Not Found**
   - Verify Nmap installation
   - Add Nmap to system PATH

3. **Subfinder Not Found**
   - Ensure Go is installed
   - Check `$GOPATH/bin` is in PATH
   - Run `go install` command again

4. **OpenAI API Errors**
   - Verify API key in `.env`
   - Check API quota and billing

5. **Frontend Connection Issues**
   - Ensure backend is running on port 8000
   - Check CORS configuration

### Logs

- Backend logs: Console output from `python main.py`
- Celery logs: Console output from `python celery_worker.py`
- Frontend logs: Browser developer console

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems. The developers are not responsible for any misuse of this software.
