import os
import io
import csv
import json
from datetime import datetime
from flask import Flask, render_template, request, Response
from flask_socketio import SocketIO, emit
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Preformatted
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter

from scanner import VulnerabilityScanner

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_very_secret_key_change_me_in_production'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variable to hold the scanner instance and results
active_scanner = None
scan_results_store = {}

@app.route('/')
def index():
    """Serves the main HTML page."""
    return render_template('index.html')

@socketio.on('start_scan')
def handle_start_scan(data):
    """Starts the vulnerability scan in a background thread."""
    global active_scanner, scan_results_store
    
    if active_scanner:
        active_scanner.stop_scan = True
        
    target_url = data['url']
    options = {
        'depth': int(data.get('depth', 2)),
    }
    
    emit('log', {'message': f"Scan initiated for {target_url}", 'type': 'success'})
    
    active_scanner = VulnerabilityScanner(target_url, options, emit)
    
    thread = threading.Thread(target=active_scanner.run)
    thread.daemon = True
    thread.start()

@socketio.on('stop_scan')
def handle_stop_scan():
    """Signals the active scan to stop."""
    global active_scanner
    if active_scanner:
        active_scanner.stop_scan = True
        emit('log', {'message': 'Stop signal sent to scanner.', 'type': 'warning'})

@app.route('/download/pdf')
def download_pdf():
    """Generates and serves a PDF report with proof from Nmap."""
    if not scan_results_store:
        return "No scan results available to generate a report.", 404

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
    story = []
    styles = getSampleStyleSheet()

    # --- Report Content ---
    story.append(Paragraph("WebVulnX Pro - Full Penetration Test Report", styles['h1']))
    story.append(Spacer(1, 12))
    
    p_text = f"""
    <b>Target URL:</b> {scan_results_store.get('target', 'N/A')}<br/>
    <b>Scan Date:</b> {scan_results_store.get('date', 'N/A')}<br/>
    """
    story.append(Paragraph(p_text, styles['BodyText']))
    story.append(Spacer(1, 12))

    # --- Network Reconnaissance Section (The "Proof") ---
    if scan_results_store.get('recon_results'):
        recon = scan_results_store['recon_results']
        story.append(Paragraph("Stage 1: Network Reconnaissance Findings", styles['h2']))
        
        # OS Info
        story.append(Paragraph(f"<b>Detected OS:</b> {recon.get('os_info', 'N/A')}", styles['BodyText']))
        story.append(Spacer(1, 6))
        
        # Open Ports Table
        open_ports = recon.get('open_ports', [])
        if open_ports:
            port_data = [['Port', 'Service']]
            for p in open_ports:
                port_data.append([str(p), 'N/A']) # Service parsing would require more complex XML parsing
            port_table = Table(port_data, hAlign="LEFT", colWidths=[1*inch, 3*inch])
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#C41E3A")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(port_table)
        story.append(Spacer(1, 12))

        # Script Scan Output (as a preformatted text block)
        script_output = recon.get('script_output', '')
        if script_output:
            story.append(Paragraph("<b>Script Scan Output (Proof):</b>", styles['h3']))
            code_style = styles['Code']
            # Truncate output to prevent PDF issues
            truncated_output = script_output[:2000] + "..." if len(script_output) > 2000 else script_output
            pre = Preformatted(truncated_output, code_style)
            story.append(pre)
        story.append(Spacer(1, 12))

    # --- Web Vulnerabilities Section ---
    story.append(Paragraph("Stage 2: Web Application Vulnerabilities", styles['h2']))
    vulns = scan_results_store.get('vulnerabilities', [])
    if vulns:
        data = [['Type', 'URL', 'Parameter', 'Payload']]
        for vuln in vulns:
            data.append([vuln.get('type', 'N/A'), vuln.get('url', 'N/A'), vuln.get('param', 'N/A'), vuln.get('payload', 'N/A')])
        
        table = Table(data, hAlign="LEFT")
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#C41E3A")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#F5F5F5")),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(table)
    else:
        story.append(Paragraph("No critical web vulnerabilities were found.", styles['BodyText']))

    doc.build(story)
    buf.seek(0)
    return Response(buf.read(), mimetype="application/pdf", headers={"Content-Disposition": f"attachment; filename=report_{scan_results_store.get('date', 'unknown').replace(':', '-')}.pdf"})

@app.route('/download/csv')
def download_csv():
    """Generates and serves a CSV report."""
    if not scan_results_store:
        return "No scan results available to generate a report.", 404

    output = io.StringIO()
    writer = csv.writer(output)
    
    header = ['Type', 'URL', 'Parameter', 'Payload']
    writer.writerow(header)
    
    for vuln in scan_results_store.get('vulnerabilities', []):
        writer.writerow([
            vuln.get('type', 'N/A'),
            vuln.get('url', 'N/A'),
            vuln.get('param', 'N/A'),
            vuln.get('payload', 'N/A')
        ])
    
    output.seek(0)
    mem = io.BytesIO()
    mem.write(output.getvalue().encode('utf-8'))
    mem.seek(0)
    output.close()

    return Response(mem.read(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename=report_{scan_results_store.get('date', 'unknown').replace(':', '-')}.csv"})

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
