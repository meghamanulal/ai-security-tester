
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
