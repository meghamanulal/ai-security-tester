import os
import json
from typing import Dict, List, Any
from datetime import datetime
from pathlib import Path
import tempfile
import shutil

# Try to import PDF and DOC generation libraries
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.pdfgen import canvas
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

try:
    from docx import Document
    from docx.shared import Inches, Pt
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.table import WD_TABLE_ALIGNMENT
    DOC_AVAILABLE = True
except ImportError:
    DOC_AVAILABLE = False

class EnhancedReportGenerator:
    def __init__(self, scan_results: Dict[str, Any]):
        self.scan_results = scan_results
        self.target = scan_results.get('scan_metadata', {}).get('target', scan_results.get('domain', 'Unknown'))
        self.scan_date = scan_results.get('scan_metadata', {}).get('scan_completion_time', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
    def generate_pdf_report(self) -> str:
        """Generate PDF report"""
        if not PDF_AVAILABLE:
            raise ImportError("PDF generation requires reportlab. Install with: pip install reportlab")
        
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        temp_path = temp_file.name
        temp_file.close()
        
        try:
            # Create PDF document
            doc = SimpleDocTemplate(temp_path, pagesize=A4)
            story = []
            
            # Get styles
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                alignment=1  # Center
            )
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                spaceAfter=12,
                textColor=colors.darkblue
            )
            
            # Title
            story.append(Paragraph("🔒 Advanced Pentesting Report", title_style))
            story.append(Paragraph(f"Target: {self.target}", styles['Heading2']))
            story.append(Paragraph(f"Scan Date: {self.scan_date}", styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Executive Summary
            story.append(Paragraph("Executive Summary", heading_style))
            summary = self._generate_executive_summary()
            story.append(Paragraph(summary, styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Attack Surface Mapping
            story.append(Paragraph("Attack Surface Mapping", heading_style))
            attack_surface = self._generate_attack_surface_section()
            story.append(Paragraph(attack_surface, styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Discovered Assets
            story.append(Paragraph("Discovered Assets", heading_style))
            assets = self._generate_assets_section()
            story.append(Paragraph(assets, styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Vulnerability Findings
            story.append(Paragraph("Vulnerability Findings", heading_style))
            vuln_data = self._generate_vulnerability_table()
            if vuln_data:
                table = Table(vuln_data)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                story.append(table)
            else:
                story.append(Paragraph("No vulnerabilities detected.", styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Attack Path Analysis
            story.append(Paragraph("Attack Path Analysis", heading_style))
            attack_paths = self._generate_attack_paths_section()
            story.append(Paragraph(attack_paths, styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Recommendations
            story.append(Paragraph("Security Recommendations", heading_style))
            recommendations = self._generate_recommendations_section()
            story.append(Paragraph(recommendations, styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Footer
            story.append(PageBreak())
            story.append(Paragraph("Report generated by AI Security Tester", styles['Normal']))
            story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            
            # Build PDF
            doc.build(story)
            return temp_path
            
        except Exception as e:
            # Clean up on error
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise e
    
    def generate_doc_report(self) -> str:
        """Generate DOC report"""
        if not DOC_AVAILABLE:
            raise ImportError("DOC generation requires python-docx. Install with: pip install python-docx")
        
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.docx')
        temp_path = temp_file.name
        temp_file.close()
        
        try:
            # Create document
            doc = Document()
            
            # Title
            title = doc.add_heading('🔒 Advanced Pentesting Report', 0)
            title.alignment = WD_ALIGN_PARAGRAPH.CENTER
            
            # Target info
            doc.add_heading('Target Information', level=1)
            p = doc.add_paragraph()
            p.add_run('Target: ').bold = True
            p.add_run(f'{self.target}\n')
            p.add_run('Scan Date: ').bold = True
            p.add_run(f'{self.scan_date}')
            
            # Executive Summary
            doc.add_heading('Executive Summary', level=1)
            summary = self._generate_executive_summary()
            doc.add_paragraph(summary)
            
            # Attack Surface Mapping
            doc.add_heading('Attack Surface Mapping', level=1)
            attack_surface = self._generate_attack_surface_section()
            doc.add_paragraph(attack_surface)
            
            # Discovered Assets
            doc.add_heading('Discovered Assets', level=1)
            assets = self._generate_assets_section()
            doc.add_paragraph(assets)
            
            # Vulnerability Findings
            doc.add_heading('Vulnerability Findings', level=1)
            vuln_data = self._generate_vulnerability_table()
            if vuln_data:
                table = doc.add_table(rows=len(vuln_data), cols=len(vuln_data[0]))
                table.style = 'Table Grid'
                
                # Add data to table
                for i, row in enumerate(vuln_data):
                    for j, cell_data in enumerate(row):
                        table.cell(i, j).text = str(cell_data)
                        if i == 0:  # Header row
                            table.cell(i, j).paragraphs[0].runs[0].bold = True
            else:
                doc.add_paragraph('No vulnerabilities detected.')
            
            # Attack Path Analysis
            doc.add_heading('Attack Path Analysis', level=1)
            attack_paths = self._generate_attack_paths_section()
            doc.add_paragraph(attack_paths)
            
            # Recommendations
            doc.add_heading('Security Recommendations', level=1)
            recommendations = self._generate_recommendations_section()
            doc.add_paragraph(recommendations)
            
            # Footer
            doc.add_paragraph('\nReport generated by AI Security Tester')
            doc.add_paragraph(f'Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
            
            # Save document
            doc.save(temp_path)
            return temp_path
            
        except Exception as e:
            # Clean up on error
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise e
    
    def _generate_executive_summary(self) -> str:
        """Generate executive summary"""
        attack_surface = self.scan_results.get('attack_surface_mapping', {})
        vulnerabilities = self.scan_results.get('vulnerability_findings', {})
        ai_analysis = self.scan_results.get('ai_reasoning_analysis', {})
        
        total_vulns = sum(len(vulns) for vulns in vulnerabilities.values())
        risk_level = ai_analysis.get('risk_level', 'Unknown')
        
        summary = f"""
This advanced pentesting assessment was conducted against {self.target}. 
The scan discovered {len(attack_surface.get('subdomains', []))} subdomains, 
{len(attack_surface.get('historical_urls', []))} historical URLs, and 
{total_vulns} vulnerabilities. 

Overall risk level: {risk_level}. 
{self._get_risk_description(risk_level)}
        """.strip()
        
        return summary
    
    def _generate_attack_surface_section(self) -> str:
        """Generate attack surface section"""
        attack_surface = self.scan_results.get('attack_surface_mapping', {})
        
        section = f"""
Subdomains Discovered: {len(attack_surface.get('subdomains', []))}
Historical URLs: {len(attack_surface.get('historical_urls', []))}
API Endpoints: {len(attack_surface.get('api_endpoints', []))}
Hidden Assets: {len(attack_surface.get('hidden_assets', []))}
        """.strip()
        
        return section
    
    def _generate_assets_section(self) -> str:
        """Generate assets section"""
        assets = self.scan_results.get('asset_verification', {})
        endpoints = self.scan_results.get('endpoint_discovery', {})
        ports = self.scan_results.get('port_scanning_results', {})
        
        section = f"""
Live Hosts: {len(assets.get('hosts', []))}
Admin Panels: {len(endpoints.get('admin_panels', []))}
Backup Files: {len(endpoints.get('backup_files', []))}
Open Ports: {sum(len(port_list) for port_list in ports.values())}
        """.strip()
        
        return section
    
    def _generate_vulnerability_table(self) -> List[List[str]]:
        """Generate vulnerability table data"""
        vulnerabilities = self.scan_results.get('vulnerability_findings', {})
        table_data = [['URL', 'Type', 'Severity', 'Description']]
        
        for target, vulns in vulnerabilities.items():
            for vuln in vulns:
                table_data.append([
                    target,
                    vuln.get('type', 'Unknown'),
                    vuln.get('severity', 'Unknown'),
                    vuln.get('description', 'No description')
                ])
        
        return table_data if len(table_data) > 1 else []
    
    def _generate_attack_paths_section(self) -> str:
        """Generate attack paths section"""
        attack_paths = self.scan_results.get('attack_path_analysis', {}).get('attack_paths', [])
        
        if not attack_paths:
            return "No attack paths identified."
        
        section = f"Attack Paths Identified: {len(attack_paths)}\n\n"
        
        for i, path in enumerate(attack_paths[:5], 1):  # Limit to 5 paths
            section += f"Path {i}: {path.get('name', 'Unknown')}\n"
            section += f"Risk: {path.get('risk', 'Unknown')}\n"
            section += f"Likelihood: {path.get('likelihood', 'Unknown')}\n\n"
        
        return section.strip()
    
    def _generate_recommendations_section(self) -> str:
        """Generate recommendations section"""
        ai_analysis = self.scan_results.get('ai_reasoning_analysis', {})
        recommendations = ai_analysis.get('recommendations', [])
        
        if not recommendations:
            return "No specific recommendations generated."
        
        section = ""
        for i, rec in enumerate(recommendations, 1):
            section += f"{i}. {rec}\n"
        
        return section.strip()
    
    def _get_risk_description(self, risk_level: str) -> str:
        """Get risk level description"""
        descriptions = {
            'Critical': 'Critical vulnerabilities requiring immediate attention.',
            'High': 'High-risk issues that should be addressed promptly.',
            'Medium': 'Medium-risk issues that should be addressed in the near future.',
            'Low': 'Low-risk issues that should be addressed when possible.'
        }
        return descriptions.get(risk_level, 'Risk level assessment not available.')
    
    def generate_html_report(self) -> str:
        """Generate enhanced HTML report"""
        report = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Pentesting Report - {self.target}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f8f9fa;
            color: #333;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid #007bff;
            padding-bottom: 30px;
            margin-bottom: 40px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            margin: -30px -30px 40px -30px;
            padding: 40px 30px 30px 30px;
            border-radius: 10px 10px 0 0;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header h2 {{
            margin: 10px 0 0 0;
            font-size: 1.5em;
            font-weight: 400;
            opacity: 0.9;
        }}
        .section {{
            margin-bottom: 40px;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            overflow: hidden;
        }}
        .section-header {{
            background: linear-gradient(135deg, #007bff 0%, #0056b3 100%);
            color: white;
            padding: 20px;
            font-weight: 600;
            font-size: 1.3em;
        }}
        .section-content {{
            padding: 25px;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .metric-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #007bff;
        }}
        .metric-value {{
            font-size: 2em;
            font-weight: bold;
            color: #007bff;
            margin-bottom: 5px;
        }}
        .metric-label {{
            color: #6c757d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .vulnerability {{
            border-left: 4px solid #dc3545;
            padding: 20px;
            margin: 15px 0;
            background: #fff5f5;
            border-radius: 0 8px 8px 0;
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
            letter-spacing: 1px;
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
            color: #212529;
        }}
        .severity.low {{
            background: #28a745;
            color: white;
        }}
        .attack-path {{
            background: #e3f2fd;
            border: 1px solid #2196f3;
            border-radius: 8px;
            padding: 20px;
            margin: 15px 0;
        }}
        .attack-path h4 {{
            color: #1976d2;
            margin-top: 0;
        }}
        .step {{
            background: #f5f5f5;
            padding: 10px 15px;
            margin: 8px 0;
            border-radius: 5px;
            border-left: 3px solid #2196f3;
        }}
        .recommendations {{
            background: #e8f5e8;
            border: 1px solid #28a745;
            border-radius: 8px;
            padding: 20px;
        }}
        .recommendations h4 {{
            color: #155724;
            margin-top: 0;
        }}
        .recommendation-item {{
            background: white;
            padding: 12px 15px;
            margin: 8px 0;
            border-radius: 5px;
            border-left: 3px solid #28a745;
        }}
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        .data-table th, .data-table td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }}
        .data-table th {{
            background: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }}
        .data-table tr:hover {{
            background: #f8f9fa;
        }}
        .risk-indicator {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 25px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-size: 0.9em;
        }}
        .risk-critical {{
            background: #dc3545;
            color: white;
        }}
        .risk-high {{
            background: #fd7e14;
            color: white;
        }}
        .risk-medium {{
            background: #ffc107;
            color: #212529;
        }}
        .risk-low {{
            background: #28a745;
            color: white;
        }}
        .footer {{
            text-align: center;
            margin-top: 50px;
            padding-top: 30px;
            border-top: 1px solid #dee2e6;
            color: #6c757d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Advanced Pentesting Report</h1>
            <h2>Target: {self.target}</h2>
            <p>Scan Date: {self.scan_date}</p>
        </div>

        {self._generate_executive_summary_html()}
        {self._generate_metrics_html()}
        {self._generate_attack_surface_html()}
        {self._generate_assets_html()}
        {self._generate_vulnerabilities_html()}
        {self._generate_attack_paths_html()}
        {self._generate_recommendations_html()}

        <div class="footer">
            <p>Report generated by AI Security Tester</p>
            <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>
        """
        return report
    
    def _generate_executive_summary_html(self) -> str:
        """Generate executive summary HTML"""
        ai_analysis = self.scan_results.get('ai_reasoning_analysis', {})
        risk_level = ai_analysis.get('risk_level', 'Unknown')
        
        return f"""
        <div class="section">
            <div class="section-header">📊 Executive Summary</div>
            <div class="section-content">
                <div class="risk-indicator risk-{risk_level.lower()}">
                    Overall Risk Level: {risk_level}
                </div>
                <p style="margin-top: 20px;">
                    {self._generate_executive_summary()}
                </p>
            </div>
        </div>
        """
    
    def _generate_metrics_html(self) -> str:
        """Generate metrics dashboard HTML"""
        attack_surface = self.scan_results.get('attack_surface_mapping', {})
        assets = self.scan_results.get('asset_verification', {})
        endpoints = self.scan_results.get('endpoint_discovery', {})
        ports = self.scan_results.get('port_scanning_results', {})
        vulnerabilities = self.scan_results.get('vulnerability_findings', {})
        
        # Get open ports details if available
        open_ports_details = self.scan_results.get('openPortsDetails', [])
        open_ports_count = len(open_ports_details) if open_ports_details else self.scan_results.get('openPorts', 0)
        
        return f"""
        <div class="section">
            <div class="section-header">📈 Scan Metrics</div>
            <div class="section-content">
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-value">{len(attack_surface.get('subdomains', []))}</div>
                        <div class="metric-label">Subdomains</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{len(attack_surface.get('historical_urls', []))}</div>
                        <div class="metric-label">Historical URLs</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{len(assets.get('hosts', []))}</div>
                        <div class="metric-label">Live Hosts</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{open_ports_count}</div>
                        <div class="metric-label">Open Ports</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{sum(len(vulns) for vulns in vulnerabilities.values())}</div>
                        <div class="metric-label">Vulnerabilities</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{len(self.scan_results.get('attack_path_analysis', {}).get('attack_paths', []))}</div>
                        <div class="metric-label">Attack Paths</div>
                    </div>
                </div>
                
                {self._generate_open_ports_details_html() if open_ports_details else ''}
            </div>
        </div>
        """
    
    def _generate_open_ports_details_html(self) -> str:
        """Generate open ports details HTML"""
        open_ports_details = self.scan_results.get('openPortsDetails', [])
        
        if not open_ports_details:
            return ""
        
        ports_html = ""
        for port in open_ports_details:
            risk_color = {
                'critical': '#dc3545',
                'high': '#fd7e14',
                'medium': '#ffc107',
                'low': '#28a745'
            }.get(port.get('risk', 'low'), '#6c757d')
            
            ports_html += f"""
            <tr>
                <td>{port.get('port', 'N/A')}</td>
                <td>{port.get('protocol', 'N/A')}</td>
                <td>{port.get('service', 'N/A')}</td>
                <td>{port.get('version', 'N/A')}</td>
                <td><span style="color: {risk_color}; font-weight: bold;">{port.get('risk', 'N/A')}</span></td>
            </tr>
            """
        
        return f"""
        <div class="subsection" style="margin-top: 30px;">
            <h4>🔌 Open Ports Details</h4>
            <table style="width: 100%; border-collapse: collapse; margin-top: 15px;">
                <thead>
                    <tr style="background-color: #f8f9fa;">
                        <th style="padding: 10px; border: 1px solid #dee2e6;">Port</th>
                        <th style="padding: 10px; border: 1px solid #dee2e6;">Protocol</th>
                        <th style="padding: 10px; border: 1px solid #dee2e6;">Service</th>
                        <th style="padding: 10px; border: 1px solid #dee2e6;">Version</th>
                        <th style="padding: 10px; border: 1px solid #dee2e6;">Risk</th>
                    </tr>
                </thead>
                <tbody>
                    {ports_html}
                </tbody>
            </table>
        </div>
        """
    
    def _generate_attack_surface_html(self) -> str:
        """Generate attack surface HTML"""
        attack_surface = self.scan_results.get('attack_surface_mapping', {})
        
        subdomains = attack_surface.get('subdomains', [])[:10]  # Limit to 10
        urls = attack_surface.get('historical_urls', [])[:10]  # Limit to 10
        
        subdomain_html = ""
        for subdomain in subdomains:
            subdomain_html += f"<div style='padding: 5px 0;'>{subdomain}</div>"
        
        url_html = ""
        for url in urls:
            url_html += f"<div style='padding: 5px 0; word-break: break-all;'>{url}</div>"
        
        return f"""
        <div class="section">
            <div class="section-header">🗺️ Attack Surface Mapping</div>
            <div class="section-content">
                <h4>Subdomains Discovered ({len(attack_surface.get('subdomains', []))} total)</h4>
                {subdomain_html or "<p>No subdomains discovered</p>"}
                
                <h4 style="margin-top: 30px;">Historical URLs ({len(attack_surface.get('historical_urls', []))} total)</h4>
                {url_html or "<p>No historical URLs discovered</p>"}
            </div>
        </div>
        """
    
    def _generate_assets_html(self) -> str:
        """Generate assets HTML"""
        assets = self.scan_results.get('asset_verification', {}).get('hosts', [])
        endpoints = self.scan_results.get('endpoint_discovery', {})
        ports = self.scan_results.get('port_scanning_results', {})
        
        assets_html = ""
        for asset in assets[:10]:  # Limit to 10
            assets_html += f"<div style='padding: 8px 0; border-bottom: 1px solid #eee;'>{asset.get('url', 'N/A')} - {asset.get('status_code', 'N/A')}</div>"
        
        return f"""
        <div class="section">
            <div class="section-header">🎯 Discovered Assets</div>
            <div class="section-content">
                <h4>Live Hosts ({len(assets)} total)</h4>
                {assets_html or "<p>No live hosts discovered</p>"}
                
                <h4 style="margin-top: 30px;">Admin Panels ({len(endpoints.get('admin_panels', []))})</h4>
                {self._format_endpoints(endpoints.get('admin_panels', []))}
                
                <h4 style="margin-top: 30px;">Backup Files ({len(endpoints.get('backup_files', []))})</h4>
                {self._format_endpoints(endpoints.get('backup_files', []))}
            </div>
        </div>
        """
    
    def _generate_vulnerabilities_html(self) -> str:
        """Generate vulnerabilities HTML"""
        vulnerabilities = self.scan_results.get('vulnerability_findings', {})
        
        if not vulnerabilities:
            return """
            <div class="section">
                <div class="section-header">🔍 Vulnerability Findings</div>
                <div class="section-content">
                    <p>No vulnerabilities detected.</p>
                </div>
            </div>
            """
        
        vuln_html = ""
        for target, vulns in vulnerabilities.items():
            for vuln in vulns[:5]:  # Limit to 5 per target
                severity = vuln.get('severity', 'low')
                vuln_html += f"""
                <div class="vulnerability {severity}">
                    <h4>{vuln.get('type', 'Unknown')} <span class="severity {severity}">{severity}</span></h4>
                    <p><strong>URL:</strong> {target}</p>
                    <p><strong>Description:</strong> {vuln.get('description', 'No description')}</p>
                </div>
                """
        
        return f"""
        <div class="section">
            <div class="section-header">🔍 Vulnerability Findings</div>
            <div class="section-content">
                {vuln_html}
            </div>
        </div>
        """
    
    def _generate_attack_paths_html(self) -> str:
        """Generate attack paths HTML"""
        attack_paths = self.scan_results.get('attack_path_analysis', {}).get('attack_paths', [])
        
        if not attack_paths:
            return """
            <div class="section">
                <div class="section-header">🛤️ Attack Path Analysis</div>
                <div class="section-content">
                    <p>No attack paths identified.</p>
                </div>
            </div>
            """
        
        paths_html = ""
        for path in attack_paths[:3]:  # Limit to 3 paths
            steps = path.get('steps', [])
            steps_html = ""
            for step in steps:
                steps_html += f"<div class='step'>{step}</div>"
            
            paths_html += f"""
            <div class="attack-path">
                <h4>{path.get('name', 'Unknown Attack Path')}</h4>
                <p><strong>Risk:</strong> {path.get('risk', 'Unknown')} | <strong>Likelihood:</strong> {path.get('likelihood', 'Unknown')}</p>
                {steps_html}
            </div>
            """
        
        return f"""
        <div class="section">
            <div class="section-header">🛤️ Attack Path Analysis</div>
            <div class="section-content">
                {paths_html}
            </div>
        </div>
        """
    
    def _generate_recommendations_html(self) -> str:
        """Generate recommendations HTML"""
        ai_analysis = self.scan_results.get('ai_reasoning_analysis', {})
        recommendations = ai_analysis.get('recommendations', [])
        
        if not recommendations:
            return """
            <div class="section">
                <div class="section-header">💡 Security Recommendations</div>
                <div class="section-content">
                    <p>No specific recommendations generated.</p>
                </div>
            </div>
            """
        
        rec_html = ""
        for rec in recommendations[:10]:  # Limit to 10
            rec_html += f"<div class='recommendation-item'>{rec}</div>"
        
        return f"""
        <div class="section">
            <div class="section-header">💡 Security Recommendations</div>
            <div class="section-content">
                <div class="recommendations">
                    <h4>Priority Actions Required</h4>
                    {rec_html}
                </div>
            </div>
        </div>
        """
    
    def _format_endpoints(self, endpoints: List[str]) -> str:
        """Format endpoints list"""
        if not endpoints:
            return "<p>No endpoints discovered</p>"
        
        html = ""
        for endpoint in endpoints[:5]:  # Limit to 5
            html += f"<div style='padding: 5px 0; word-break: break-all;'>{endpoint}</div>"
        
        return html
