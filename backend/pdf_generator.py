#!/usr/bin/env python3
"""
PDF Report Generator
Generates professional PDF reports for pentesting results
"""

from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
import html
from datetime import datetime

def generate_pdf_report(scan_data: dict) -> bytes:
    """Generate professional PDF report from scan data"""
    from io import BytesIO
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
    
    # Get styles
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#2c3e50')
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        spaceAfter=12,
        spaceBefore=20,
        textColor=colors.HexColor('#34495e'),
        borderWidth=1,
        borderColor=colors.HexColor('#3498db'),
        borderPadding=5
    )
    
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=6,
        textColor=colors.HexColor('#2c3e50')
    )
    
    # Build story
    story = []
    
    # Title
    story.append(Paragraph("🛡️ Professional Security Scan Report", title_style))
    story.append(Spacer(1, 12))
    
    # Scan Information
    story.append(Paragraph("📊 Scan Information", heading_style))
    
    scan_info = [
        ['Scan ID:', scan_data.get('id', 'N/A')],
        ['Domain:', scan_data.get('domain', 'N/A')],
        ['Status:', scan_data.get('status', 'N/A')],
        ['Start Time:', scan_data.get('startTime', 'N/A')],
        ['End Time:', scan_data.get('endTime', 'N/A')],
        ['Risk Level:', scan_data.get('riskLevel', 'N/A')],
        ['Real Scan Data:', '✅ Yes' if scan_data.get('real_scan_data') else '❌ No']
    ]
    
    info_table = Table(scan_info, colWidths=[2*inch, 4*inch])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#ffffff')),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    story.append(info_table)
    story.append(Spacer(1, 20))
    
    # Scan Statistics
    story.append(Paragraph("📈 Scan Statistics", heading_style))
    
    stats = scan_data.get('scan_metadata', {})
    stats_info = [
        ['Duration:', stats.get('duration', 'N/A')],
        ['Total Vulnerabilities:', str(stats.get('total_vulnerabilities', 'N/A'))],
        ['Critical Vulnerabilities:', str(stats.get('critical_vulnerabilities', 'N/A'))],
        ['High Vulnerabilities:', str(stats.get('high_vulnerabilities', 'N/A'))],
        ['Medium Vulnerabilities:', str(stats.get('medium_vulnerabilities', 'N/A'))],
        ['Low Vulnerabilities:', str(stats.get('low_vulnerabilities', 'N/A'))],
        ['Open Ports:', str(scan_data.get('openPorts', 'N/A'))],
        ['Technologies Detected:', str(stats.get('technologies_detected', 'N/A'))],
        ['Subdomains Found:', str(stats.get('subdomains_found', 'N/A'))],
        ['Directories Found:', str(stats.get('directories_found', 'N/A'))],
        ['Commands Executed:', str(stats.get('commands_executed', 'N/A'))]
    ]
    
    stats_table = Table(stats_info, colWidths=[2.5*inch, 3.5*inch])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8f5e8')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#ffffff')),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    story.append(stats_table)
    story.append(Spacer(1, 20))
    
    # Open Ports
    open_ports = scan_data.get('openPortsDetails', [])
    if open_ports:
        story.append(Paragraph("🔌 Open Ports Details", heading_style))
        
        ports_data = [['Port', 'Protocol', 'Service', 'Version', 'State', 'Risk']]
        for port in open_ports[:20]:  # Limit to first 20 ports
            ports_data.append([
                str(port.get('port', 'N/A')),
                port.get('protocol', 'N/A'),
                port.get('service', 'N/A'),
                port.get('version', 'N/A'),
                port.get('state', 'N/A'),
                port.get('risk', 'N/A')
            ])
        
        ports_table = Table(ports_data, colWidths=[0.8*inch, 1*inch, 1.2*inch, 1.5*inch, 1*inch, 1*inch])
        ports_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ffffff')),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(ports_table)
        story.append(Spacer(1, 20))
    
    # Technologies
    technologies = scan_data.get('technologies', [])
    if technologies:
        story.append(Paragraph("🔍 Technologies Detected", heading_style))
        
        tech_text = ", ".join(technologies[:10])  # Limit to first 10
        story.append(Paragraph(f"<b>Technologies:</b> {tech_text}", normal_style))
        story.append(Spacer(1, 20))
    
    # Security Findings
    findings = scan_data.get('findings', [])
    if findings:
        story.append(Paragraph("🚨 Security Findings", heading_style))
        
        for finding in findings[:15]:  # Limit to first 15 findings
            severity = finding.get('severity', 'unknown').lower()
            severity_color = {
                'critical': colors.HexColor('#e74c3c'),
                'high': colors.HexColor('#f39c12'),
                'medium': colors.HexColor('#f1c40f'),
                'low': colors.HexColor('#27ae60')
            }.get(severity, colors.black)
            
            finding_title = finding.get('title', finding.get('type', 'Unknown Finding'))
            finding_desc = finding.get('description', 'No description available')
            finding_tool = finding.get('tool', 'Unknown')
            finding_cve = finding.get('cve', finding.get('cve_reference', 'N/A'))
            
            # Finding header
            story.append(Paragraph(f"<b>{finding_title}</b>", ParagraphStyle(
                'FindingTitle',
                parent=normal_style,
                fontSize=12,
                textColor=severity_color,
                spaceAfter=6
            )))
            
            # Finding details
            story.append(Paragraph(f"<b>Severity:</b> {severity.upper()}", normal_style))
            story.append(Paragraph(f"<b>Tool:</b> {finding_tool}", normal_style))
            if finding_cve != 'N/A':
                story.append(Paragraph(f"<b>CVE:</b> {finding_cve}", normal_style))
            story.append(Paragraph(f"<b>Description:</b> {finding_desc}", normal_style))
            story.append(Spacer(1, 12))
    
    # Commands Executed
    commands = scan_data.get('commands_executed', [])
    if commands:
        story.append(Paragraph("🔧 Commands Executed", heading_style))
        
        for cmd in commands[:10]:  # Limit to first 10 commands
            tool = cmd.get('tool', 'Unknown')
            command = cmd.get('command', 'N/A')
            timestamp = cmd.get('timestamp', 'N/A')
            success = cmd.get('success', True)
            
            status = "✅ Success" if success else "❌ Failed"
            
            story.append(Paragraph(f"<b>{tool}</b> - {status}", normal_style))
            story.append(Paragraph(f"<i>{command}</i>", normal_style))
            story.append(Paragraph(f"<small>Time: {timestamp}</small>", normal_style))
            story.append(Spacer(1, 12))
    
    # Footer
    story.append(PageBreak())
    story.append(Paragraph("📋 Report Summary", heading_style))
    story.append(Paragraph(f"<b>Report Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    story.append(Paragraph("<b>Generated by:</b> AI Security Tester - Professional Pentesting Scanner", normal_style))
    story.append(Paragraph("<b>Security Tools Used:</b> Nmap, Nuclei, Nikto, SQLMap, Hydra, SSLScan, WhatWeb, Gobuster, Amass", normal_style))
    story.append(Spacer(1, 20))
    story.append(Paragraph("🔒 This report contains sensitive security information. Handle with appropriate security measures.", normal_style))
    
    # Build PDF
    doc.build(story)
    
    # Get PDF content
    pdf_content = buffer.getvalue()
    buffer.close()
    
    return pdf_content

def generate_orchestrator_pdf_report(scan_data: dict) -> bytes:
    """Generate professional PDF report for orchestrator scan"""
    # Similar to above but with orchestrator-specific fields
    return generate_pdf_report(scan_data)

if __name__ == "__main__":
    # Test the PDF generator
    test_data = {
        'id': 'test-scan-123',
        'domain': 'example.com',
        'status': 'completed',
        'startTime': '2024-01-01T10:00:00',
        'endTime': '2024-01-01T10:05:00',
        'riskLevel': 'medium',
        'real_scan_data': True,
        'scan_metadata': {
            'duration': '0:05:00',
            'total_vulnerabilities': 5,
            'critical_vulnerabilities': 1,
            'high_vulnerabilities': 2,
            'medium_vulnerabilities': 1,
            'low_vulnerabilities': 1,
            'technologies_detected': 4,
            'subdomains_found': 8,
            'directories_found': 5,
            'commands_executed': 9
        },
        'openPortsDetails': [
            {'port': 80, 'protocol': 'TCP', 'service': 'HTTP', 'version': 'Apache 2.4.41', 'state': 'open', 'risk': 'medium'},
            {'port': 443, 'protocol': 'TCP', 'service': 'HTTPS', 'version': 'Apache 2.4.41', 'state': 'open', 'risk': 'medium'}
        ],
        'technologies': ['Apache httpd 2.4.41', 'PHP 7.4.15', 'WordPress 5.7', 'MySQL 8.0.21'],
        'findings': [
            {'title': 'SQL Injection', 'severity': 'high', 'description': 'SQL injection vulnerability found', 'tool': 'SQLMap', 'cve': 'CVE-2023-1234'},
            {'title': 'XSS Vulnerability', 'severity': 'medium', 'description': 'Cross-site scripting vulnerability', 'tool': 'Nikto', 'cve': 'N/A'}
        ],
        'commands_executed': [
            {'tool': 'Nmap', 'command': 'nmap -sS -sV example.com', 'timestamp': '2024-01-01T10:00:01', 'success': True},
            {'tool': 'Nuclei', 'command': 'nuclei -target example.com', 'timestamp': '2024-01-01T10:01:00', 'success': True}
        ]
    }
    
    pdf_content = generate_pdf_report(test_data)
    print(f"Generated PDF: {len(pdf_content)} bytes")
    
    # Save test PDF
    with open('test_report.pdf', 'wb') as f:
        f.write(pdf_content)
    print("Test PDF saved as 'test_report.pdf'")
