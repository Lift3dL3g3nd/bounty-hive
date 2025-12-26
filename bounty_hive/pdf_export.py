from __future__ import annotations

from pathlib import Path


def write_pdf_report(title: str, lines: list[str], out_path: Path) -> bool:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
    except Exception:
        return False

    out_path.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(out_path), pagesize=letter)
    width, height = letter  # noqa: F841

    x = 54
    y = height - 54
    c.setTitle(title)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(x, y, title)
    y -= 24

    c.setFont("Helvetica", 10)
    for ln in lines:
        if y < 72:
            c.showPage()
            y = height - 54
            c.setFont("Helvetica", 10)
        safe = (ln or "")[:160]
        c.drawString(x, y, safe)
        y -= 12

    c.save()
    return True
