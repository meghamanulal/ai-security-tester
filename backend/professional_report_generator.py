from typing import Dict, List, Any
from datetime import datetime
import json

class ProfessionalReportGenerator:
    def __init__(self, pentesting_results: Dict[str, Any]):
        self.pentesting_results = pentesting_results
        self.target = pentesting_results.get('scan_metadata', {}).get('target', 'Unknown')

    def generate_professional_html_report(self) -> str:
        """Generate comprehensive professional pentesting report"""
        
        metadata = self.pentesting_results.get('scan_metadata', {})
        target_info = self.pentesting_results.get('target_information', {})
        subdomain_data = self.pentesting_results.get('subdomain_discovery', {})
        live_host_data = self.pentesting_results.get('live_host_detection', {})
        port_scans = self.pentesting_results.get('port_scanning_results', {})
        technologies = self.pentesting_results.get('technology_detection', {})
        web_vulns = self.pentesting_results.get('web_vulnerability_findings', {})
        nuclei_vulns = self.pentesting_results.get('nuclei_vulnerability_findings', {})
        security_headers = self.pentesting_results.get('security_headers_analysis', {})
        ai_analysis = self.pentesting_results.get('ai_security_analysis', {})
        
        report = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Professional Pentesting Report - {self.target}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 300;
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .metadata {{
            background: #f8f9fa;
            padding: 20px 40px;
            border-bottom: 1px solid #dee2e6;
        }}
        
        .metadata-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }}
        
        .metadata-item {{
            padding: 10px;
            background: white;
            border-radius: 5px;
            border-left: 4px solid #667eea;
        }}
        
        .metadata-item strong {{
            color: #667eea;
            display: block;
            margin-bottom: 5px;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .section {{
            margin-bottom: 50px;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .section-header {{
            background: #667eea;
            color: white;
            padding: 20px;
            font-size: 1.3em;
            font-weight: 500;
        }}
        
        .section-content {{
            padding: 30px;
        }}
        
        .section-header.critical {{
            background: #dc3545;
        }}
        
        .section-header.high {{
            background: #fd7e14;
        }}
        
        .section-header.medium {{
            background: #ffc107;
            color: #333;
        }}
        
        .section-header.low {{
            background: #28a745;
        }}
        
        .table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        
        .table th, .table td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }}
        
        .table th {{
            background: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }}
        
        .table tr:hover {{
            background: #f8f9fa;
        }}
        
        .vulnerability {{
            border-left: 4px solid #dc3545;
            padding: 20px;
            margin: 15px 0;
            background: #fff5f5;
            border-radius: 5px;
        }}
        
        .vulnerability.high {{
            border-left-color: #fd7e14;
            background: #fff8f0;
        }}
        
        .vulnerability.medium {{
            border-left-color: #ffc107;
            background: #fffbf0;
        }}
        
        .vulnerability.low {{
            border-left-color: #28a745;
            background: #f8fff8;
        }}
        
        .severity {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .severity.critical {{
            background: #dc3545;
            color: white;
        }}
        
        .severity.high {{
            background: #fd7e14;
            color: white;
        }}
        
        .severity.medium {{
            background: #ffc107;
            color: #333;
        }}
        
        .severity.low {{
            background: #28a745;
            color: white;
        }}
        
        .host-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        
        .host-card {{
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            background: white;
        }}
        
        .host-card h4 {{
            color: #667eea;
            margin-bottom: 15px;
        }}
        
        .port-list {{
            list-style: none;
            padding: 0;
        }}
        
        .port-list li {{
            padding: 8px 0;
            border-bottom: 1px solid #f8f9fa;
        }}
        
        .port-list li:last-child {{
            border-bottom: none;
        }}
        
        .port {{
            font-family: 'Courier New', monospace;
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
            font-weight: 600;
        }}
        
        .service {{
            color: #495057;
            margin-left: 10px;
        }}
        
        .version {{
            color: #6c757d;
            font-size: 0.9em;
            margin-left: 5px;
        }}
        
        .tech-badge {{
            display: inline-block;
            background: #e9ecef;
            padding: 4px 8px;
            border-radius: 4px;
            margin: 2px;
            font-size: 0.85em;
        }}
        
        .missing-header {{
            color: #dc3545;
            font-weight: 600;
        }}
        
        .present-header {{
            color: #28a745;
        }}
        
        .recommendations {{
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }}
        
        .recommendations h4 {{
            color: #856404;
            margin-bottom: 15px;
        }}
        
        .recommendations ul {{
            margin-left: 20px;
        }}
        
        .recommendations li {{
            margin: 8px 0;
        }}
        
        .summary-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        
        .stat-card {{
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        
        .stat-number {{
            font-size: 2em;
            font-weight: 600;
            color: #667eea;
            display: block;
        }}
        
        .stat-label {{
            color: #6c757d;
            font-size: 0.9em;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 30px 40px;
            text-align: center;
            color: #6c757d;
            border-top: 1px solid #dee2e6;
        }}
        
        .risk-indicator {{
            display: inline-block;
            padding: 8px 20px;
            border-radius: 25px;
            font-weight: 600;
            text-transform: uppercase;
            margin: 10px 0;
        }}
        
        .risk-indicator.critical {{
            background: #dc3545;
            color: white;
        }}
        
        .risk-indicator.high {{
            background: #fd7e14;
            color: white;
        }}
        
        .risk-indicator.medium {{
            background: #ffc107;
            color: #333;
        }}
        
        .risk-indicator.low {{
            background: #28a745;
            color: white;
        }}
        
        .code {{
            font-family: 'Courier New', monospace;
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
        }}
        
        @media print {{
            body {{
                background: white;
            }}
            .container {{
                box-shadow: none;
            }}
            .section {{
                page-break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Professional Pentesting Report</h1>
            <div class="subtitle">Comprehensive Security Assessment</div>
        </div>
        
        <div class="metadata">
            <div class="metadata-grid">
                <div class="metadata-item">
                    <strong>Target Domain</strong>
                    {metadata.get('target', 'Unknown')}
                </div>
                <div class="metadata-item">
                    <strong>IP Addresses</strong>
                    {', '.join(target_info.get('ip_addresses', []))}
                </div>
                <div class="metadata-item">
                    <strong>Scan Date</strong>
                    {metadata.get('scan_start_time', 'Unknown')}
                </div>
                <div class="metadata-item">
                    <strong>Assessment Duration</strong>
                    {self._calculate_duration()}
                </div>
            </div>
        </div>
        
        <div class="content">
            {self._generate_executive_summary()}
            {self._generate_target_information_section()}
            {self._generate_subdomain_discovery_section()}
            {self._generate_live_hosts_section()}
            {self._generate_port_scanning_section()}
            {self._generate_technology_detection_section()}
            {self._generate_web_vulnerabilities_section()}
            {self._generate_nuclei_vulnerabilities_section()}
            {self._generate_security_headers_section()}
            {self._generate_ai_analysis_section()}
        </div>
        
        <div class="footer">
            <p>Report generated by AI Security Tester Professional Pentesting Suite</p>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>
        """
        
        return report

    def _calculate_duration(self) -> str:
        """Calculate scan duration"""
        try:
            start_time = self.pentesting_results.get('scan_metadata', {}).get('scan_start_time')
            end_time = self.pentesting_results.get('scan_metadata', {}).get('scan_completion_time')
            
            if start_time and end_time:
                start = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                end = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
                duration = end - start
                
                hours, remainder = divmod(duration.total_seconds(), 3600)
                minutes, seconds = divmod(remainder, 60)
                
                if hours > 0:
                    return f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
                elif minutes > 0:
                    return f"{int(minutes)}m {int(seconds)}s"
                else:
                    return f"{int(seconds)}s"
        except:
            pass
        
        return "Unknown"

    def _generate_executive_summary(self) -> str:
        """Generate executive summary section"""
        ai_analysis = self.pentesting_results.get('ai_security_analysis', {})
        risk_level = ai_analysis.get('risk_level', 'Unknown')
        summary = ai_analysis.get('summary', '')
        
        # Calculate statistics
        total_hosts = len(self.pentesting_results.get('live_host_detection', {}).get('hosts', []))
        total_subdomains = len(self.pentesting_results.get('subdomain_discovery', {}).get('subdomains', []))
        total_ports = sum(len(ports) for ports in self.pentesting_results.get('port_scanning_results', {}).values())
        
        # Count vulnerabilities
        total_vulns = 0
        critical_vulns = 0
        for hostname, vulns in self.pentesting_results.get('nuclei_vulnerability_findings', {}).items():
            for vuln in vulns:
                total_vulns += 1
                if vuln.get('severity') == 'critical':
                    critical_vulns += 1
        
        return f"""
        <div class="section">
            <div class="section-header">📊 Executive Summary</div>
            <div class="section-content">
                <div class="risk-indicator {risk_level.lower()}">
                    Overall Risk Level: {risk_level.upper()}
                </div>
                
                <div class="summary-stats">
                    <div class="stat-card">
                        <span class="stat-number">{total_subdomains}</span>
                        <span class="stat-label">Subdomains Found</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">{total_hosts}</span>
                        <span class="stat-label">Live Hosts</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">{total_ports}</span>
                        <span class="stat-label">Open Ports</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">{total_vulns}</span>
                        <span class="stat-label">Vulnerabilities</span>
                    </div>
                    <div class="stat-card">
                        <span class="stat-number">{critical_vulns}</span>
                        <span class="stat-label">Critical Issues</span>
                    </div>
                </div>
                
                <div style="margin-top: 30px;">
                    <h3>Assessment Overview</h3>
                    <p style="white-space: pre-line; margin-top: 15px;">{summary}</p>
                </div>
            </div>
        </div>
        """

    def _generate_target_information_section(self) -> str:
        """Generate target information section"""
        target_info = self.pentesting_results.get('target_information', {})
        
        return f"""
        <div class="section">
            <div class="section-header">🎯 Target Information</div>
            <div class="section-content">
                <table class="table">
                    <tr>
                        <th>Domain</th>
                        <td>{target_info.get('domain', 'Unknown')}</td>
                    </tr>
                    <tr>
                        <th>Primary IP</th>
                        <td>{target_info.get('primary_ip', 'Unknown')}</td>
                    </tr>
                    <tr>
                        <th>All IP Addresses</th>
                        <td>{', '.join(target_info.get('ip_addresses', []))}</td>
                    </tr>
                    <tr>
                        <th>Validation Time</th>
                        <td>{target_info.get('validation_time', 'Unknown')}</td>
                    </tr>
                </table>
            </div>
        </div>
        """

    def _generate_subdomain_discovery_section(self) -> str:
        """Generate subdomain discovery section"""
        subdomain_data = self.pentesting_results.get('subdomain_discovery', {})
        subdomains = subdomain_data.get('subdomains', [])
        
        if not subdomains:
            return """
            <div class="section">
                <div class="section-header">🔍 Subdomain Discovery</div>
                <div class="section-content">
                    <p>No subdomains discovered or subdomain enumeration failed.</p>
                </div>
            </div>
            """
        
        subdomain_list = ""
        for subdomain in subdomains[:50]:  # Limit to 50 for display
            subdomain_list += f"<li>{subdomain}</li>"
        
        return f"""
        <div class="section">
            <div class="section-header">🔍 Subdomain Discovery</div>
            <div class="section-content">
                <p><strong>Total Subdomains Discovered:</strong> {len(subdomains)}</p>
                <ul style="columns: 3; column-gap: 30px; margin-top: 20px;">
                    {subdomain_list}
                </ul>
                {f'<p><em>Showing first 50 of {len(subdomains)} subdomains</em></p>' if len(subdomains) > 50 else ''}
            </div>
        </div>
        """

    def _generate_live_hosts_section(self) -> str:
        """Generate live hosts section"""
        live_host_data = self.pentesting_results.get('live_host_detection', {})
        hosts = live_host_data.get('hosts', [])
        
        if not hosts:
            return """
            <div class="section">
                <div class="section-header">💻 Live Host Detection</div>
                <div class="section-content">
                    <p>No live hosts detected or host detection failed.</p>
                </div>
            </div>
            """
        
        host_cards = ""
        for host in hosts[:20]:  # Limit to 20 for display
            host_cards += f"""
            <div class="host-card">
                <h4>{host.get('host', 'Unknown')}</h4>
                <p><strong>Status Code:</strong> {host.get('status_code', 'Unknown')}</p>
                <p><strong>Title:</strong> {host.get('title', 'No title')}</p>
            </div>
            """
        
        return f"""
        <div class="section">
            <div class="section-header">💻 Live Host Detection</div>
            <div class="section-content">
                <p><strong>Total Live Hosts:</strong> {len(hosts)}</p>
                <div class="host-grid">
                    {host_cards}
                </div>
                {f'<p><em>Showing first 20 of {len(hosts)} live hosts</em></p>' if len(hosts) > 20 else ''}
            </div>
        </div>
        """

    def _generate_port_scanning_section(self) -> str:
        """Generate port scanning section"""
        port_scans = self.pentesting_results.get('port_scanning_results', {})
        
        if not port_scans:
            return """
            <div class="section">
                <div class="section-header">🔌 Port Scanning Results</div>
                <div class="section-content">
                    <p>No port scan results available or port scanning failed.</p>
                </div>
            </div>
            """
        
        host_sections = ""
        for hostname, ports in port_scans.items():
            port_list = ""
            for port_info in ports:
                port_list += f"""
                <li>
                    <span class="port">{port_info.get('port', 'Unknown')}</span>
                    <span class="service">{port_info.get('service', 'Unknown')}</span>
                    <span class="version">{port_info.get('version', 'Unknown')}</span>
                </li>
                """
            
            host_sections += f"""
            <div class="host-card">
                <h4>{hostname}</h4>
                <p><strong>Open Ports:</strong> {len(ports)}</p>
                <ul class="port-list">
                    {port_list}
                </ul>
            </div>
            """
        
        total_ports = sum(len(ports) for ports in port_scans.values())
        
        return f"""
        <div class="section">
            <div class="section-header">🔌 Port Scanning Results</div>
            <div class="section-content">
                <p><strong>Total Open Ports:</strong> {total_ports}</p>
                <div class="host-grid">
                    {host_sections}
                </div>
            </div>
        </div>
        """

    def _generate_technology_detection_section(self) -> str:
        """Generate technology detection section"""
        technologies = self.pentesting_results.get('technology_detection', {})
        
        if not technologies:
            return """
            <div class="section">
                <div class="section-header">🛠️ Technology Detection</div>
                <div class="section-content">
                    <p>No technology detection results available.</p>
                </div>
            </div>
            """
        
        tech_table = ""
        for hostname, tech_info in technologies.items():
            tech_table += f"""
            <tr>
                <td>{hostname}</td>
                <td>{tech_info.get('server', 'Unknown')}</td>
                <td>{tech_info.get('framework', 'Unknown')}</td>
                <td>{tech_info.get('language', 'Unknown')}</td>
                <td>{tech_info.get('database', 'Unknown')}</td>
            </tr>
            """
        
        return f"""
        <div class="section">
            <div class="section-header">🛠️ Technology Detection</div>
            <div class="section-content">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Host</th>
                            <th>Server</th>
                            <th>Framework</th>
                            <th>Language</th>
                            <th>Database</th>
                        </tr>
                    </thead>
                    <tbody>
                        {tech_table}
                    </tbody>
                </table>
            </div>
        </div>
        """

    def _generate_web_vulnerabilities_section(self) -> str:
        """Generate web vulnerabilities section"""
        web_vulns = self.pentesting_results.get('web_vulnerability_findings', {})
        
        if not web_vulns:
            return """
            <div class="section">
                <div class="section-header">🌐 Web Vulnerability Findings</div>
                <div class="section-content">
                    <p>No web vulnerabilities detected by Nikto.</p>
                </div>
            </div>
            """
        
        vuln_sections = ""
        for hostname, findings in web_vulns.items():
            for finding in findings:
                vuln_sections += f"""
                <div class="vulnerability medium">
                    <h4>🔍 Web Vulnerability</h4>
                    <p><strong>Host:</strong> {hostname}</p>
                    <p><strong>URL:</strong> <span class="code">{finding.get('url', 'Unknown')}</span></p>
                    <p><strong>Issue:</strong> {finding.get('message', 'No description')}</p>
                    {f'<p><strong>Reference:</strong> {finding.get("reference", "")}</p>' if finding.get('reference') else ''}
                </div>
                """
        
        return f"""
        <div class="section">
            <div class="section-header">🌐 Web Vulnerability Findings</div>
            <div class="section-content">
                {vuln_sections}
            </div>
        </div>
        """

    def _generate_nuclei_vulnerabilities_section(self) -> str:
        """Generate Nuclei vulnerabilities section"""
        nuclei_vulns = self.pentesting_results.get('nuclei_vulnerability_findings', {})
        
        if not nuclei_vulns:
            return """
            <div class="section">
                <div class="section-header">⚡ Nuclei Vulnerability Findings</div>
                <div class="section-content">
                    <p>No vulnerabilities detected by Nuclei.</p>
                </div>
            </div>
            """
        
        vuln_sections = ""
        for hostname, findings in nuclei_vulns.items():
            for finding in findings:
                severity = finding.get('severity', 'unknown')
                vuln_sections += f"""
                <div class="vulnerability {severity}">
                    <h4>⚡ <span class="severity {severity}">{severity}</span> {finding.get('name', 'Unknown')}</h4>
                    <p><strong>Host:</strong> {hostname}</p>
                    <p><strong>URL:</strong> <span class="code">{finding.get('url', 'Unknown')}</span></p>
                    <p><strong>Description:</strong> {finding.get('description', 'No description')}</p>
                    {f'<p><strong>Template ID:</strong> {finding.get("template_id", "")}</p>' if finding.get('template_id') else ''}
                </div>
                """
        
        return f"""
        <div class="section">
            <div class="section-header">⚡ Nuclei Vulnerability Findings</div>
            <div class="section-content">
                {vuln_sections}
            </div>
        </div>
        """

    def _generate_security_headers_section(self) -> str:
        """Generate security headers section"""
        security_headers = self.pentesting_results.get('security_headers_analysis', {})
        
        if not security_headers:
            return """
            <div class="section">
                <div class="section-header">🛡️ Security Headers Analysis</div>
                <div class="section-content">
                    <p>No security header analysis available.</p>
                </div>
            </div>
            """
        
        headers_content = ""
        for hostname, header_info in security_headers.items():
            present_headers = header_info.get('present', {})
            missing_headers = header_info.get('missing', [])
            
            present_html = ""
            for header, value in present_headers.items():
                present_html += f"""
                <tr>
                    <td class="present-header">{header}</td>
                    <td><span class="code">{value}</span></td>
                </tr>
                """
            
            missing_html = ""
            for header in missing_headers:
                missing_html += f"""
                <tr>
                    <td class="missing-header">{header}</td>
                    <td>❌ Missing</td>
                </tr>
                """
            
            headers_content += f"""
            <div class="host-card">
                <h4>{hostname}</h4>
                
                <h5>Present Headers</h5>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Header</th>
                            <th>Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        {present_html}
                    </tbody>
                </table>
                
                <h5 style="margin-top: 20px;">Missing Headers</h5>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Header</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {missing_html}
                    </tbody>
                </table>
            </div>
            """
        
        return f"""
        <div class="section">
            <div class="section-header">🛡️ Security Headers Analysis</div>
            <div class="section-content">
                <div class="host-grid">
                    {headers_content}
                </div>
            </div>
        </div>
        """

    def _generate_ai_analysis_section(self) -> str:
        """Generate AI analysis section"""
        ai_analysis = self.pentesting_results.get('ai_security_analysis', {})
        
        if not ai_analysis or 'error' in ai_analysis:
            return """
            <div class="section">
                <div class="section-header">🤖 AI Security Analysis</div>
                <div class="section-content">
                    <p>AI security analysis not available.</p>
                </div>
            </div>
            """
        
        critical_findings = ai_analysis.get('critical_findings', [])
        recommendations = ai_analysis.get('recommendations', [])
        
        critical_html = ""
        for finding in critical_findings[:10]:  # Limit to 10
            critical_html += f"""
            <tr>
                <td>{finding.get('host', 'Unknown')}</td>
                <td>{finding.get('vulnerability', 'Unknown')}</td>
                <td><span class="code">{finding.get('url', 'Unknown')}</span></td>
            </tr>
            """
        
        recommendations_html = ""
        for rec in recommendations:
            recommendations_html += f"<li>{rec}</li>"
        
        return f"""
        <div class="section">
            <div class="section-header">🤖 AI Security Analysis</div>
            <div class="section-content">
                <div class="risk-indicator {ai_analysis.get('risk_level', 'unknown').lower()}">
                    Overall Risk Level: {ai_analysis.get('risk_level', 'Unknown').upper()}
                </div>
                
                {f'''
                <div style="margin-top: 30px;">
                    <h3>🚨 Critical Findings</h3>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Host</th>
                                <th>Vulnerability</th>
                                <th>URL</th>
                            </tr>
                        </thead>
                        <tbody>
                            {critical_html}
                        </tbody>
                    </table>
                </div>
                ''' if critical_findings else ''}
                
                {f'''
                <div class="recommendations">
                    <h4>📋 Security Recommendations</h4>
                    <ul>
                        {recommendations_html}
                    </ul>
                </div>
                ''' if recommendations else ''}
            </div>
        </div>
        """
