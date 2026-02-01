#!/usr/bin/env python3
"""
EventFlow CSV to PDF - PROFESSIONAL REPORT WITH LOGO (FIXED)
Modified for Flask integration
"""

import os
import sys
import json
import csv
from datetime import datetime
from pathlib import Path

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.units import inch
except ImportError:
    print("Installing reportlab...")
    os.system("pip install reportlab")
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.units import inch

# Configuration
REPORTS_FOLDER = "reports"
LOGO_PATH = "static/logo/logo.png"
os.makedirs(REPORTS_FOLDER, exist_ok=True)

def check_logo():
    """Check if logo exists and return properly sized image or None."""
    if os.path.exists(LOGO_PATH):
        try:
            # Calculate size based on aspect ratio (1024x267 ≈ 3.83:1)
            # Target width: 5 inches, height: 5/3.83 ≈ 1.3 inches
            logo_width = 5.0 * inch  # 5 inches wide
            logo_height = (267/1024) * logo_width  # Maintain aspect ratio
            img = Image(LOGO_PATH, width=logo_width, height=logo_height)
            return img, logo_width, logo_height
        except Exception as e:
            print(f"⚠️  Warning: Could not load logo from {LOGO_PATH}: {e}")
            return None, None, None
    else:
        print(f"⚠️  Warning: Logo not found at {LOGO_PATH}")
        # Try alternative paths
        alternative_paths = [
            "static/logo.png",
            "logo.png",
            "static/images/logo.png"
        ]
        for alt_path in alternative_paths:
            if os.path.exists(alt_path):
                try:
                    logo_width = 5.0 * inch
                    logo_height = (267/1024) * logo_width
                    img = Image(alt_path, width=logo_width, height=logo_height)
                    return img, logo_width, logo_height
                except:
                    continue
        return None, None, None

def create_professional_report(csv_path, event_name, form_title, logo_img):
    """Create professional report with properly sized logo."""
    try:
        # Read CSV
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            data = list(reader)
        
        if len(data) <= 1:
            return None
        
        # Create filename
        safe_name = event_name.replace(' ', '_')[:30]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{safe_name}_Report_{timestamp}.pdf"
        output_path = os.path.join(REPORTS_FOLDER, filename)
        
        # Create document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            leftMargin=0.5*inch,
            rightMargin=0.5*inch,
            topMargin=0.5*inch,  # Reduced top margin since logo will be at top
            bottomMargin=0.75*inch
        )
        
        # Get styles
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=22,
            textColor=colors.HexColor('#2C3E50'),
            alignment=TA_CENTER,
            spaceAfter=12,
            fontName='Helvetica-Bold'
        )
        
        subtitle_style = ParagraphStyle(
            'SubtitleStyle',
            parent=styles['Heading2'],
            fontSize=18,
            textColor=colors.HexColor('#4361ee'),
            alignment=TA_CENTER,
            spaceAfter=25,
            fontName='Helvetica'
        )
        
        header_style = ParagraphStyle(
            'HeaderStyle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.white,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        cell_style = ParagraphStyle(
            'CellStyle',
            parent=styles['Normal'],
            fontSize=9,
            leading=11,
            alignment=TA_LEFT,
            wordWrap='CJK',
            splitLongWords=True
        )
        
        si_style = ParagraphStyle(
            'SIStyle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#E74C3C'),
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        # Build story
        story = []
        
        # ===== COVER PAGE =====
        # Add centered logo at top
        if logo_img:
            # Center the logo
            logo_img.hAlign = 'CENTER'
            story.append(logo_img)
            story.append(Spacer(1, 0.3*inch))
        else:
            # Add header text if no logo
            header_text = Paragraph("EventFlow Registration System", styles['Heading2'])
            story.append(header_text)
            story.append(Spacer(1, 0.2*inch))
        
        story.append(Spacer(1, 0.8*inch))
        
        # Title
        story.append(Paragraph(event_name, title_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Form title
        story.append(Paragraph(form_title, subtitle_style))
        story.append(Spacer(1, 0.5*inch))
        
        # Report type
        report_type_style = ParagraphStyle(
            'ReportType',
            parent=styles['Normal'],
            fontSize=12,
            textColor=colors.HexColor('#666666'),
            alignment=TA_CENTER,
            spaceAfter=20,
            fontName='Helvetica-Bold'
        )
        story.append(Paragraph("RESPONSES REPORT", report_type_style))
        story.append(Spacer(1, 1*inch))
        
        # Statistics box
        stats_data = [
            ["📊", "Total Responses", f"{len(data)-1}"],
            ["📅", "Report Date", datetime.now().strftime('%d %b, %Y')],
            ["⏰", "Generated Time", datetime.now().strftime('%I:%M %p')],
            ["📋", "Questions", f"{len(data[0])-2}"]
        ]
        
        stats_table = Table(stats_data, colWidths=[0.6*inch, 2.0*inch, 1.8*inch])
        stats_table.setStyle(TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (0,-1), 16),
            ('FONTSIZE', (1,0), (1,-1), 11),
            ('FONTSIZE', (2,0), (2,-1), 12),
            ('FONTNAME', (2,0), (2,-1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (2,0), (2,-1), colors.HexColor('#E74C3C')),
            ('TOPPADDING', (0,0), (-1,-1), 12),
            ('BOTTOMPADDING', (0,0), (-1,-1), 12),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8F9FA')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#DEE2E6')),
        ]))
        
        story.append(stats_table)
        story.append(Spacer(1, 1.5*inch))
        
        # Footer note
        footer_text = f"""
        <para alignment="center">
        <font size=10 color=#666666>
        Generated by EventFlow Registration System<br/>
        Report ID: {str(os.urandom(4).hex()).upper()}<br/>
        {datetime.now().strftime('%d %B, %Y')}
        </font>
        </para>
        """
        story.append(Paragraph(footer_text, styles['Normal']))
        
        story.append(PageBreak())
        
        # ===== DATA TABLE PAGE =====
        # Add centered logo at top of data page too
        if logo_img:
            # Create a new instance of the logo for second page
            logo_img2 = Image(LOGO_PATH, width=5.0*inch, height=(267/1024)*5.0*inch)
            logo_img2.hAlign = 'CENTER'
            story.append(logo_img2)
            story.append(Spacer(1, 0.2*inch))
        
        # Page title
        story.append(Paragraph("Response Details", title_style))
        story.append(Spacer(1, 0.2*inch))
        
        # Get original headers
        original_headers = data[0]
        
        # Create display headers with SI No
        display_headers = ['SI No']
        
        # Clean up and add other headers (skip timestamp and response ID)
        for header in original_headers:
            header_lower = str(header).lower()
            
            # Skip system columns
            if 'timestamp' in header_lower or 'response id' in header_lower:
                continue
            
            # Clean header text
            header_text = str(header)
            
            # Common cleanups
            if header_text.lower() == 'no of people coming':
                header_text = 'No. of People'
            elif header_text.lower() == 'your expectations':
                header_text = 'Expectations'
            elif 'parish' in header_text.lower():
                if '(' in header_text:
                    header_text = 'Parish'
            elif 'name' in header_text.lower():
                header_text = 'Name'
            
            display_headers.append(header_text)
        
        # Prepare table data
        table_data = []
        
        # Add header row
        header_cells = []
        for header in display_headers:
            header_cells.append(Paragraph(str(header), header_style))
        table_data.append(header_cells)
        
        # Calculate column widths
        col_count = len(display_headers)
        
        # Set reasonable column widths based on typical columns
        col_widths = [0.6*inch]  # SI No column
        
        # Check for common columns and set widths
        column_width_map = {
            'Name': 1.8*inch,
            'Parish': 2.2*inch,
            'No. of People': 1.2*inch,
            'Expectations': 3.0*inch,
            'Email': 2.2*inch,
            'Phone': 1.5*inch,
            'Mobile': 1.5*inch,
            'Address': 2.8*inch,
            'Message': 3.5*inch,
            'Comment': 3.0*inch,
            'Feedback': 3.0*inch
        }
        
        # Set widths for known columns
        for header in display_headers[1:]:  # Skip SI No
            if header in column_width_map:
                col_widths.append(column_width_map[header])
            else:
                # Default width for unknown columns
                col_widths.append(1.8*inch)
        
        # Adjust if total width exceeds page
        total_width = sum(col_widths)
        if total_width > doc.width:
            scale = doc.width / total_width
            col_widths = [w * scale for w in col_widths]
        
        # Add data rows
        max_rows = min(35, len(data)-1)  # Fewer rows for better readability
        
        for row_num in range(1, max_rows+1):
            row = data[row_num]
            formatted_row = []
            
            # Add SI Number
            formatted_row.append(Paragraph(str(row_num), si_style))
            
            # Add other columns (skip timestamp and response ID)
            col_idx = 0
            for i in range(len(original_headers)):
                header_lower = str(original_headers[i]).lower()
                
                # Skip system columns
                if 'timestamp' in header_lower or 'response id' in header_lower:
                    col_idx += 1
                    continue
                
                # Get cell value
                if col_idx < len(row):
                    cell_text = str(row[col_idx])
                    
                    # Truncate long text to prevent overlap
                    if len(cell_text) > 120:
                        cell_text = cell_text[:120] + "..."
                    
                    formatted_row.append(Paragraph(cell_text, cell_style))
                else:
                    formatted_row.append(Paragraph("", cell_style))
                
                col_idx += 1
        
            # Pad if needed
            while len(formatted_row) < col_count:
                formatted_row.append(Paragraph("", cell_style))
            
            table_data.append(formatted_row)
        
        # Create table
        table = Table(table_data, colWidths=col_widths, repeatRows=1)
        
        # Apply table styles
        table.setStyle(TableStyle([
            # Header row
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#4361ee')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,0), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 10),
            ('BOTTOMPADDING', (0,0), (-1,0), 10),
            ('TOPPADDING', (0,0), (-1,0), 10),
            ('GRID', (0,0), (-1,0), 1, colors.white),
            
            # Data rows
            ('BACKGROUND', (0,1), (-1,-1), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E0E0E0')),
            ('ALIGN', (0,1), (0,-1), 'CENTER'),  # SI No column centered
            ('ALIGN', (1,1), (-1,-1), 'LEFT'),   # Other columns left-aligned
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('FONTSIZE', (0,1), (-1,-1), 9),
            ('LEADING', (0,1), (-1,-1), 11),
            ('TOPPADDING', (0,1), (-1,-1), 6),
            ('BOTTOMPADDING', (0,1), (-1,-1), 6),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
            
            # SI No column styling
            ('FONTNAME', (0,1), (0,-1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0,1), (0,-1), colors.HexColor('#E74C3C')),
            
            # Alternating row colors
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#F8F9FA'), colors.white]),
            
            # First column border
            ('LINEAFTER', (0,0), (0,-1), 1, colors.HexColor('#4361ee')),
        ]))
        
        story.append(table)
        story.append(Spacer(1, 0.3*inch))
        
        # Page info
        if max_rows < len(data)-1:
            page_info = Paragraph(
                f"<i>Page 1: Showing responses 1-{max_rows} of {len(data)-1} total</i>",
                styles['Italic']
            )
            story.append(page_info)
        
        # Footer
        footer_text = f"""
        <para alignment="center">
        <font size=9 color=#666666>
        Event: {event_name} | Form: {form_title}<br/>
        Generated by EventFlow Registration System | {datetime.now().strftime('%d %b, %Y %I:%M %p')}
        </font>
        </para>
        """
        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph(footer_text, styles['Normal']))
        
        # Build PDF
        doc.build(story)
        
        return output_path
        
    except Exception as e:
        print(f"   ❌ Error: {str(e)[:100]}")
        import traceback
        traceback.print_exc()
        return None

# ============================================================================
# FLASK-INTEGRATED FUNCTIONS
# ============================================================================

def generate_pdf_for_form(csv_path, event_name, form_title):
    """Generate PDF for a specific form - called from Flask"""
    print(f"🎯 GENERATING PDF FOR: {event_name} - {form_title}")
    
    # Check logo
    logo_img, logo_width, logo_height = check_logo()
    
    if logo_img:
        print(f"✅ Logo loaded")
    else:
        print(f"⚠️  No logo found, using text header")
    
    # Generate the PDF
    output_path = create_professional_report(
        csv_path,
        event_name,
        form_title,
        logo_img
    )
    
    if output_path:
        print(f"✅ PDF Generated: {output_path}")
        return output_path
    else:
        print(f"❌ Failed to generate PDF")
        return None

def main():
    """Main function for standalone execution."""
    print("=" * 70)
    print("🎨 EventFlow - Professional PDF Reports with Logo")
    print("=" * 70)
    print(f"📁 Reports will be saved to: {REPORTS_FOLDER}/")
    print(f"🎨 Logo: {LOGO_PATH} (1024x267 pixels)")
    
    # Check logo
    logo_img, logo_width, logo_height = check_logo()
    if logo_img:
        print(f"✅ Logo found and loaded successfully")
        if logo_width and logo_height:
            print(f"   Logo size in PDF: {logo_width/inch:.1f} x {logo_height/inch:.1f} inches")
    else:
        print(f"⚠️  Note: Logo not found. Reports will show text header instead.")
        print(f"   Looking for: {LOGO_PATH}")
    
    # Find CSV files
    print("\n🔍 Scanning for CSV files...")
    csv_files = []
    events_dir = Path("data/events")
    
    if not events_dir.exists():
        print("❌ Error: data/events directory not found!")
        return
    
    # Get all CSV files with event info
    for event_dir in events_dir.iterdir():
        if event_dir.is_dir():
            event_id = event_dir.name
            event_json = events_dir / f"{event_id}.json"
            
            # Load event data
            event_name = "Unknown Event"
            if event_json.exists():
                try:
                    with open(event_json, 'r', encoding='utf-8') as f:
                        event_data = json.load(f)
                        event_name = event_data.get('name', 'Unknown Event')
                except:
                    pass
            
            # Find CSV files
            for csv_file in event_dir.glob("*.csv"):
                csv_files.append({
                    'path': str(csv_file),
                    'event_name': event_name,
                    'filename': csv_file.name
                })
    
    if not csv_files:
        print("❌ No CSV files found!")
        return
    
    print(f"✅ Found {len(csv_files)} CSV file(s)")
    
    # Process files
    print(f"\n🔄 Generating professional reports with logo...")
    print("-" * 70)
    
    success_count = 0
    for i, csv_info in enumerate(csv_files, 1):
        print(f"\n[{i}/{len(csv_files)}] 📋 {csv_info['event_name']}")
        print(f"   📄 File: {csv_info['filename']}")
        
        # Generate PDF
        output_path = generate_pdf_for_form(
            csv_info['path'],
            csv_info['event_name'],
            "Form Responses"
        )
        
        if output_path:
            success_count += 1
            filename = os.path.basename(output_path)
            print(f"   ✅ Generated: {filename}")
            
            # Check file size
            file_size = os.path.getsize(output_path) / 1024
            print(f"   📏 Size: {file_size:.1f} KB")
            
            # Check if logo was included
            if logo_img:
                print(f"   🎨 Logo included: Yes")
            else:
                print(f"   🎨 Logo included: No (using text header)")
        else:
            print(f"   ❌ Failed to generate report")
    
    # Summary
    print("\n" + "=" * 70)
    print("📊 GENERATION SUMMARY")
    print("=" * 70)
    print(f"✅ Successfully generated: {success_count} professional report(s)")
    print(f"📁 Location: {REPORTS_FOLDER}/")
    
    # Show generated files
    pdfs = list(Path(REPORTS_FOLDER).glob("*.pdf"))
    if pdfs:
        print(f"\n📋 Generated report files:")
        for pdf in sorted(pdfs, key=lambda x: x.stat().st_mtime, reverse=True)[:5]:
            size_kb = pdf.stat().st_size / 1024
            mtime = datetime.fromtimestamp(pdf.stat().st_mtime).strftime('%H:%M:%S')
            print(f"  • {pdf.name:<40} ({size_kb:.1f} KB) - {mtime}")
        
        if len(pdfs) > 5:
            print(f"  ... and {len(pdfs)-5} more")
    
    print("\n🎉 Professional report generation completed!")
    print("=" * 70)

if __name__ == "__main__":
    # If called with specific arguments, generate single PDF
    import sys
    
    if len(sys.argv) == 5 and sys.argv[1] == "--single":
        # Called from Flask: python csv_to_pdf.py --single csv_path "Event Name" "Form Title"
        csv_path = sys.argv[2]
        event_name = sys.argv[3]
        form_title = sys.argv[4]
        
        pdf_path = generate_pdf_for_form(csv_path, event_name, form_title)
        
        if pdf_path:
            # Print just the filename for Flask to parse
            print(f"PDF_GENERATED:{os.path.basename(pdf_path)}")
            sys.exit(0)
        else:
            print("PDF_FAILED:Failed to generate PDF")
            sys.exit(1)
    else:
        # Normal standalone execution
        main()
