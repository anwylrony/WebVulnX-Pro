# app.py
# ... (keep all other imports and routes) ...

@app.route('/download/pdf')
def download_pdf():
    """Generates and serves a PDF report with proof from Nmap."""
    if not scan_results_store.get('vulnerabilities') and not scan_results_store.get('recon_results'):
        return "No scan results available to generate a report.", 404

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
    story = []
    styles = getSampleStyleSheet()

    # --- Report Content ---
    story.append(Paragraph("WebVulnX Pro - Full Penetration Test Report", styles['h1']))
    story.append(Spacer(1, 12))
    
    p_text = f"""
    <b>Target URL:</b> {scan_results_store['target']}<br/>
    <b>Scan Date:</b> {scan_results_store['date']}<br/>
    """
    story.append(Paragraph(p_text, styles['BodyText']))
    story.append(Spacer(1, 12))

    # --- Network Reconnaissance Section (The "Proof") ---
    if scan_results_store.get('recon_results'):
        recon = scan_results_store['recon_results']
        story.append(Paragraph("Stage 1: Network Reconnaissance Findings", styles['h2']))
        
        # OS Info
        story.append(Paragraph(f"<b>Detected OS:</b> {recon.get('os_info', 'N/A')}", styles['BodyText']))
        
        # Open Ports Table
        open_ports = recon.get('open_ports', [])
        if open_ports:
            port_data = [['Port', 'Service']]
            # We would need to parse the nmap output to get service info, for now, just ports
            for p in open_ports:
                port_data.append([str(p), 'N/A'])
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
            # Add output in a code-like style
            from reportlab.platypus import Preformatted
            code_style = styles['Code']
            pre = Preformatted(script_output[:2000] + "..." if len(script_output) > 2000 else script_output, code_style)
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
    return Response(buf.read(), mimetype="application/pdf", headers={"Content-Disposition": f"attachment; filename=report_{scan_results_store['date'].replace(':', '-')}.pdf"})

# ... (keep the rest of app.py) ...
