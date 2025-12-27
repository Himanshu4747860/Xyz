# webscan/report.py
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm

def draw_kv(c, x, y, label, value):
    c.setFont("Helvetica-Bold", 11)
    c.drawString(x, y, f"{label}:")
    c.setFont("Helvetica", 11)
    c.drawString(x + 140, y, str(value))

def generate_pdf(pdf_path, domain, summary, checks, artifacts, category_risks,
                 top_risks=None, parameters=None):
    width, height = A4
    c = canvas.Canvas(pdf_path, pagesize=A4)

    y = height - 3*cm

    # Title
    c.setFont("Helvetica-Bold", 18)
    c.drawString(2*cm, y, f"Website Risk Report — {domain}")
    y -= 1.2*cm

    # Summary
    draw_kv(c, 2*cm, y, "Trust score", summary.get("trust_score")); y -= 0.8*cm
    draw_kv(c, 2*cm, y, "Verdict", summary.get("verdict")); y -= 0.8*cm
    draw_kv(c, 2*cm, y, "Severity", summary.get("severity")); y -= 1.0*cm

    # Category risks
    c.setFont("Helvetica-Bold", 14)
    c.drawString(2*cm, y, "Category risks"); y -= 0.8*cm
    c.setFont("Helvetica", 11)
    for cat, r in category_risks.items():
        c.drawString(2.2*cm, y, f"- {cat}: {round(r, 2)}")
        y -= 0.6*cm

    # Top risks
    if top_risks:
        y -= 0.6*cm
        c.setFont("Helvetica-Bold", 14)
        c.drawString(2*cm, y, "Top risks"); y -= 0.8*cm
        c.setFont("Helvetica", 11)
        for item in top_risks[:10]:
            c.drawString(2.2*cm, y, f"- {item}")
            y -= 0.6*cm
            if y < 3*cm:
                c.showPage()
                y = height - 3*cm

    # Parameter details
    if parameters:
        y -= 0.6*cm
        c.setFont("Helvetica-Bold", 14)
        c.drawString(2*cm, y, "Parameter details"); y -= 0.8*cm
        c.setFont("Helvetica", 10)
        for p, v in parameters.items():
            c.drawString(2.2*cm, y, f"{p}: risk={round(v,2)}")
            y -= 0.5*cm
            if y < 3*cm:
                c.showPage()
                y = height - 3*cm

    # ✅ Finalize
    c.showPage()
    c.save()
    return pdf_path
