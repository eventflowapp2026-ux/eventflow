from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import csv
import os
from datetime import datetime

def generate_pdf(event_id, form_id):
    """
    Generate PDF from CSV responses
    """
    csv_path = f'data/events/{event_id}/{form_id}.csv'
    
    if not os.path.exists(csv_path):
        return None
    
    # Create PDF in memory
    from io import BytesIO
    buffer = BytesIO()
    
    # Load event data for title
    event_data = None
    for filename in os.listdir('data/events'):
        if filename.endswith('.json'):
            with open(f'data/events/{filename}', 'r') as f:
                event = json.load(f)
                if event['id'] == event_id:
                    event_data = event
                    break
    
    # Read CSV data
    data = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            data.append(row)
    
    if not data:
        return None
    
    # Create PDF document
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(letter),
        rightMargin=0.5*inch,
        leftMargin=0.5*inch,
        topMargin=0.5*inch,
        bottomMargin=0.5*inch
    )
    
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    if event_data:
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=16,
            alignment=1,
            spaceAfter=12
        )
        elements.append(Paragraph(f"{event_data['name']} - Form Responses", title_style))
    
    # Date and info
    date_style = ParagraphStyle(
        'CustomDate',
        parent=styles['Normal'],
        fontSize=10,
        alignment=1,
        textColor=colors.grey,
        spaceAfter=24
    )
    elements.append(Paragraph(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", date_style))
    
    # Create table from CSV data
    table_data = data
    
    # Create table
    table = Table(table_data)
    
    # Style the table
    table_style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a6baf')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.whitesmoke]),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ])
    
    # Apply alternate row colors
    for i in range(1, len(table_data)):
        if i % 2 == 0:
            bg_color = colors.whitesmoke
        else:
            bg_color = colors.white
        table_style.add('BACKGROUND', (0, i), (-1, i), bg_color)
    
    table.setStyle(table_style)
    
    # Set column widths (adjust based on content)
    col_widths = [doc.width / len(table_data[0])] * len(table_data[0])
    table._argW = col_widths
    
    elements.append(table)
    
    # Summary
    summary_style = ParagraphStyle(
        'CustomSummary',
        parent=styles['Normal'],
        fontSize=10,
        alignment=0,
        spaceBefore=20,
        textColor=colors.grey
    )
    
    summary_text = f"Total Responses: {len(data) - 1}"
    elements.append(Paragraph(summary_text, summary_style))
    
    # Build PDF
    doc.build(elements)
    
    buffer.seek(0)
    return buffer.getvalue()

# For testing
if __name__ == '__main__':
    import json
    
    # Test with sample data
    test_event_id = 'test_event'
    test_form_id = 'test_form'
    
    # Create test directory
    os.makedirs(f'data/events/{test_event_id}', exist_ok=True)
    
    # Create test CSV
    test_csv_path = f'data/events/{test_event_id}/{test_form_id}.csv'
    with open(test_csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Timestamp', 'Response ID', 'Name', 'Email', 'Feedback'])
        writer.writerow(['2024-01-01', '1', 'John Doe', 'john@example.com', 'Great event!'])
        writer.writerow(['2024-01-02', '2', 'Jane Smith', 'jane@example.com', 'Enjoyed it!'])
    
    # Generate PDF
    pdf_data = generate_pdf(test_event_id, test_form_id)
    
    if pdf_data:
        with open('test_output.pdf', 'wb') as f:
            f.write(pdf_data)
        print("PDF generated successfully!")
    else:
        print("Failed to generate PDF!")
