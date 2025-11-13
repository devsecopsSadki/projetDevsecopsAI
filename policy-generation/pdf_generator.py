#!/usr/bin/env python3
"""
AI Security Policy PDF Generator
Generates professional, formatted PDF documents from JSON policy files.
"""

import json
import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak,
    Table, TableStyle, ListFlowable, ListItem
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from PyPDF2 import PdfMerger
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics

pdfmetrics.registerFont(
    TTFont('DejaVuSans', '/usr/share/fonts/dejavu-sans-fonts/DejaVuSans.ttf')
)

# ============================================================================
# STYLE CONFIGURATION
# ============================================================================

def create_styles():
    """Create professional document styles."""
    styles = getSampleStyleSheet()
    
    # Title for cover page
    styles.add(ParagraphStyle(
        name='CoverTitle',
        parent=styles['Title'],
        fontSize=24,
        textColor=colors.HexColor('#1a202c'),
        spaceAfter=16,
        alignment=TA_CENTER,
        fontName='DejaVuSans'
    ))
    
    # Subtitle
    styles.add(ParagraphStyle(
        name='Subtitle',
        fontSize=14,
        textColor=colors.HexColor('#4a5568'),
        spaceAfter=12,
        alignment=TA_CENTER,
        fontName='DejaVuSans'
    ))
    
    # Section heading
    styles.add(ParagraphStyle(
        name='SectionHeading',
        fontSize=14,
        textColor=colors.HexColor('#2d3748'),
        spaceAfter=10,
        spaceBefore=14,
        fontName='DejaVuSans'
    ))
    
    # Subsection heading
    styles.add(ParagraphStyle(
        name='SubsectionHeading',
        fontSize=12,
        textColor=colors.HexColor('#2d3748'),
        spaceAfter=6,
        spaceBefore=8,
        fontName='DejaVuSans'
    ))
    
    # Body text
    styles.add(ParagraphStyle(
        name='Body',
        fontSize=10,
        leading=14,
        alignment=TA_JUSTIFY,
        spaceAfter=6,
        fontName='DejaVuSans'
    ))
    
    # Small text
    styles.add(ParagraphStyle(
        name='Small',
        fontSize=9,
        leading=11,
        textColor=colors.HexColor('#718096'),
        spaceAfter=4,
        fontName='DejaVuSans'
    ))
    
    # Metadata
    styles.add(ParagraphStyle(
        name='Metadata',
        fontSize=9,
        textColor=colors.HexColor('#718096'),
        alignment=TA_CENTER,
        fontName='DejaVuSans'
    ))
    
    return styles


# ============================================================================
# TABLE CREATION FUNCTIONS
# ============================================================================

def create_metadata_table(metadata):
    """Create formatted metadata table."""
    data = [
        ['Policy ID', metadata.get('policy_id', 'N/A')],
        ['Status', metadata.get('status', 'N/A')],
        ['Created Date', metadata.get('created_date', 'N/A')],
        ['Last Updated', metadata.get('last_updated', 'N/A')],
        ['Author', metadata.get('author', 'N/A')]
    ]
    
    table = Table(data, colWidths=[2*inch, 4*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f7fafc')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2d3748')),
        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0'))
    ]))
    
    return table


def create_risk_table(risk_data):
    """Create formatted risk assessment table."""
    data = [
        ['Risk Metric', 'Value'],
        ['Overall Risk Level', risk_data.get('overall_risk_level', 'N/A')],
        ['Critical Risks', str(risk_data.get('critical_count', 0))],
        ['High Risks', str(risk_data.get('high_count', 0))],
        ['Medium Risks', str(risk_data.get('medium_count', 0))],
        ['Low Risks', str(risk_data.get('low_count', 0))],
        ['Likelihood', risk_data.get('likelihood', 'N/A')]
        #['Business Impact', risk_data.get('business_impact', 'N/A')]
    ]
    
    table = Table(data, colWidths=[2.5*inch, 3.5*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2d3748')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0'))
    ]))
    
    return table


def create_compliance_table(compliance_data, styles):
    """Create formatted compliance mapping table."""
    nist_items = compliance_data.get('nist_csf_categories', [])
    iso_items = compliance_data.get('iso27001_controls', [])
    
    data = [['Framework', 'Controls']]
    
    if nist_items:
        nist_bullets = '\n'.join([f'• {item}' for item in nist_items])
        data.append(['NIST CSF', Paragraph(nist_bullets, styles['Small'])])
    
    if iso_items:
        iso_bullets = '\n'.join([f'• {item}' for item in iso_items])
        data.append(['ISO 27001', Paragraph(iso_bullets, styles['Small'])])
    
    table = Table(data, colWidths=[1.5*inch, 4.5*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2d3748')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f7fafc')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0'))
    ]))
    
    return table


# ============================================================================
# CONTENT BUILDING FUNCTIONS
# ============================================================================

def add_cover_page(elements, title, description, styles):
    """Add cover page to document."""
    elements.append(Spacer(1, 2*inch))
    elements.append(Paragraph(title, styles['CoverTitle']))
    elements.append(Spacer(1, 0.2*inch))
    elements.append(Paragraph("AI Security Policy Framework", styles['Subtitle']))
    elements.append(Spacer(1, 0.4*inch))
    
    if description:
        truncated = description[:250] + "..." if len(description) > 250 else description
        elements.append(Paragraph(truncated, styles['Body']))
        elements.append(Spacer(1, 0.3*inch))
    
    date_str = datetime.now().strftime('%B %d, %Y')
    elements.append(Paragraph(f"Generated: {date_str}", styles['Metadata']))
    elements.append(PageBreak())


def add_section(elements, title, styles):
    """Add section heading."""
    elements.append(Paragraph(title, styles['SectionHeading']))


def add_subsection(elements, title, styles):
    """Add subsection heading."""
    elements.append(Paragraph(title, styles['SubsectionHeading']))


def add_paragraph(elements, text, styles, style_name='Body'):
    """Add formatted paragraph."""
    if text:
        elements.append(Paragraph(text, styles[style_name]))
        elements.append(Spacer(1, 8))


def add_list(elements, items, styles, numbered=False):
    """Add bullet or numbered list."""
    if not items:
        return
    
    bullet_type = '1' if numbered else 'bullet'
    list_items = [ListItem(Paragraph(str(item), styles['Body'])) for item in items]
    elements.append(ListFlowable(list_items, bulletType=bullet_type, leftIndent=20))
    elements.append(Spacer(1, 8))


def add_control(elements, control, styles):
    """Add security control with implementation steps."""
    # Control header
    title = f"{control.get('control_id', 'N/A')}: {control.get('title', 'Untitled')}"
    elements.append(Paragraph(f"<b>{title}</b>", styles['Body']))
    
    # Description
    description = control.get('description', '')
    if description:
        elements.append(Paragraph(description, styles['Small']))
        elements.append(Spacer(1, 4))
    
    # Implementation steps
    steps = control.get('implementation_steps', [])
    if steps:
        step_items = [ListItem(Paragraph(step, styles['Small'])) for step in steps]
        elements.append(ListFlowable(step_items, bulletType='bullet', leftIndent=30))
    
    elements.append(Spacer(1, 10))


def add_remediation(elements, action, styles):
    """Add remediation action."""
    priority = action.get('priority', 'N/A')
    title = action.get('title', 'Untitled')
    
    # Action header
    elements.append(Paragraph(f"<b>{priority}: {title}</b>", styles['Body']))
    
    # Details
    owner = action.get('owner', 'N/A')
    timeline = action.get('timeline', 'N/A')
    elements.append(Paragraph(f"Owner: {owner} | Timeline: {timeline}", styles['Small']))
    
    # Affected assets
    assets = action.get('affected_assets', [])
    if assets:
        elements.append(Paragraph("Affected Assets:", styles['Small']))
        add_list(elements, assets, styles)
    
    # Success criteria
    criteria = action.get('success_criteria', '')
    if criteria:
        elements.append(Paragraph(f"Success Criteria: {criteria}", styles['Small']))
    
    elements.append(Spacer(1, 10))


# ============================================================================
# EXECUTIVE SUMMARY PDF GENERATION
# ============================================================================

def generate_executive_summary_pdf(json_files, input_dir, output_path):
    """Generate simplified PDF with problems and solutions only."""
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch
    )
    
    elements = []
    styles = create_styles()
    
    # Cover page
    elements.append(Spacer(1, 2*inch))
    elements.append(Paragraph("AI Security Policies", styles['CoverTitle']))
    elements.append(Spacer(1, 0.2*inch))
    elements.append(Paragraph("Executive Summary - Problems & Solutions", styles['Subtitle']))
    elements.append(Spacer(1, 0.4*inch))
    date_str = datetime.now().strftime('%B %d, %Y')
    elements.append(Paragraph(f"Generated: {date_str}", styles['Metadata']))
    elements.append(PageBreak())
    
    # Process each policy
    for json_file in json_files:
        with open(os.path.join(input_dir, json_file), 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        metadata = data.get('metadata', {})
        policy_name = metadata.get('policy_name', data.get('policy_type', 'Unknown'))
        
        # Policy header
        elements.append(Paragraph(policy_name, styles['Title']))
        elements.append(Spacer(1, 12))
        
        # Problem section
        add_section(elements, "Problem", styles)
        
        # Risk summary
        risk_data = data.get('risk_assessment', {})
        risk_level = risk_data.get('overall_risk_level', 'N/A')
        critical = risk_data.get('critical_count', 0)
        high = risk_data.get('high_count', 0)
        medium = risk_data.get('medium_count', 0)
        low = risk_data.get('low_count', 0)
        
        risk_summary = f"<b>Risk Level:</b> {risk_level} | "
        risk_summary += f"<b>Findings:</b> {critical} Critical, {high} High, {medium} Medium, {low} Low"
        elements.append(Paragraph(risk_summary, styles['Body']))
        elements.append(Spacer(1, 8))
        
        # Business impact
        business_impact = risk_data.get('business_impact', '')
        if business_impact:
            elements.append(Paragraph(f"<b>Impact:</b> {business_impact}", styles['Body']))
            elements.append(Spacer(1, 12))
        
        # Solutions section
        add_section(elements, "Required Actions", styles)
        
        remediation_actions = data.get('remediation_actions', [])
        if remediation_actions:
            for action in remediation_actions:
                priority = action.get('priority', 'N/A')
                title = action.get('title', 'Untitled')
                timeline = action.get('timeline', 'N/A')
                owner = action.get('owner', 'N/A')
                
                # Action header
                elements.append(Paragraph(
                    f"<b>{priority}: {title}</b>",
                    styles['Body']
                ))
                
                # Details
                elements.append(Paragraph(
                    f"Timeline: {timeline} | Owner: {owner}",
                    styles['Small']
                ))
                elements.append(Spacer(1, 8))
        else:
            elements.append(Paragraph("No remediation actions required.", styles['Body']))
            elements.append(Spacer(1, 8))
        
        elements.append(PageBreak())
    
    # Build PDF
    doc.build(elements)
    return output_path


# ============================================================================
# PDF GENERATION
# ============================================================================

def generate_policy_pdf(json_path, output_path):
    """Generate PDF document from JSON policy file."""
    # Load policy data
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Setup document
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch
    )
    
    elements = []
    styles = create_styles()
    
    # Extract metadata
    metadata = data.get('metadata', {})
    policy_name = metadata.get('policy_name', data.get('policy_type', 'Unknown Policy'))
    
    # Build document
    add_cover_page(elements, policy_name, data.get('executive_summary', ''), styles)
    
    # Title
    elements.append(Paragraph(policy_name, styles['Title']))
    elements.append(Spacer(1, 12))
    
    # Metadata
    add_section(elements, "Policy Metadata", styles)
    elements.append(create_metadata_table(metadata))
    elements.append(Spacer(1, 16))
    
    # Executive Summary
    if data.get('executive_summary'):
        add_section(elements, "Executive Summary", styles)
        add_paragraph(elements, data['executive_summary'], styles)
    
    # Policy Statement
    policy_stmt = data.get('policy_statement', {})
    if policy_stmt:
        add_section(elements, "Policy Statement", styles)
        
        for field, label in [
            ('purpose', 'Purpose'),
            ('description', 'Description'),
            ('applicability', 'Applicability'),
            ('enforcement', 'Enforcement'),
            ('exceptions', 'Exceptions')
        ]:
            if policy_stmt.get(field):
                add_subsection(elements, label, styles)
                add_paragraph(elements, policy_stmt[field], styles)
    
    # Objectives
    if data.get('objectives'):
        add_section(elements, "Objectives", styles)
        add_list(elements, data['objectives'], styles, numbered=True)
    
    # Risk Assessment
    if data.get('risk_assessment'):
        add_section(elements, "Risk Assessment", styles)
        elements.append(create_risk_table(data['risk_assessment']))
        elements.append(Spacer(1, 16))
    
    # Security Controls
    if data.get('security_controls'):
        add_section(elements, "Security Controls", styles)
        for control in data['security_controls']:
            add_control(elements, control, styles)
    
    # Remediation Actions
    if data.get('remediation_actions'):
        add_section(elements, "Remediation Actions", styles)
        for action in data['remediation_actions']:
            add_remediation(elements, action, styles)
    
    # Compliance Mapping
    if data.get('compliance_mapping'):
        add_section(elements, "Compliance Mapping", styles)
        elements.append(create_compliance_table(data['compliance_mapping'], styles))
        elements.append(Spacer(1, 16))
    
    # Monitoring Requirements
    if data.get('monitoring_requirements'):
        add_section(elements, "Monitoring Requirements", styles)
        add_list(elements, data['monitoring_requirements'], styles)
    
    # Review Schedule
    if data.get('review_schedule'):
        add_section(elements, "Review Schedule", styles)
        add_paragraph(elements, data['review_schedule'], styles)
    
    # Build PDF
    doc.build(elements)
    return output_path


def merge_policy_pdfs(pdf_files, output_path):
    """Merge multiple PDF files into single document."""
    merger = PdfMerger()
    
    for pdf_file in pdf_files:
        if os.path.exists(pdf_file):
            merger.append(pdf_file)
    
    merger.write(output_path)
    merger.close()


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Generate PDF documents from AI security policy JSON files.'
    )
    parser.add_argument(
        '--input-dir',
        required=True,
        help='Directory containing JSON policy files'
    )
    parser.add_argument(
        '--output-dir',
        required=True,
        help='Directory for generated PDF files'
    )
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Find all JSON files
    json_files = sorted([
        f for f in os.listdir(args.input_dir)
        if f.endswith('.json')
    ])
    
    if not json_files:
        print("No JSON files found in input directory.")
        return
    
    print(f"Found {len(json_files)} policy file(s)\n")
    
    generated_pdfs = []
    
    # Generate individual PDFs
    for json_file in json_files:
        policy_name = os.path.splitext(json_file)[0].replace('_policy', '').upper()
        input_path = os.path.join(args.input_dir, json_file)
        output_path = os.path.join(args.output_dir, f"{policy_name}_Policy.pdf")
        
        try:
            generate_policy_pdf(input_path, output_path)
            generated_pdfs.append(output_path)
            print(f"Generated: {policy_name}_Policy.pdf")
        except Exception as e:
            print(f"Error generating {policy_name}: {str(e)}")
    
    # Generate combined PDF
    if generated_pdfs:
        combined_path = os.path.join(args.output_dir, "AI_Security_Policies_Combined.pdf")
        try:
            merge_policy_pdfs(generated_pdfs, combined_path)
            print(f"\nCombined PDF: AI_Security_Policies_Combined.pdf")
        except Exception as e:
            print(f"Error creating combined PDF: {str(e)}")
    
    # Generate executive summary PDF
    if json_files:
        summary_path = os.path.join(args.output_dir, "Executive_Summary_Problems_Solutions.pdf")
        try:
            generate_executive_summary_pdf(json_files, args.input_dir, summary_path)
            print(f"Executive Summary: Executive_Summary_Problems_Solutions.pdf")
        except Exception as e:
            print(f"Error creating executive summary: {str(e)}")
    
    print(f"\nComplete. Generated {len(generated_pdfs)} policy PDF(s) + 2 summary documents")


if __name__ == '__main__':
    main()
