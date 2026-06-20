"""
reporte_pdf.py
Genera un reporte PDF descargable a partir de un resultado de escaneo.
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from io import BytesIO


# Colores según estado, para usar en la tabla del PDF
COLOR_ESTADO = {
    "ok": colors.HexColor("#15803d"),
    "falla": colors.HexColor("#b91c1c"),
    "alerta": colors.HexColor("#a16207"),
    "info": colors.HexColor("#0369a1"),
}

ETIQUETA_ESTADO = {
    "ok": "OK",
    "falla": "FALLA",
    "alerta": "ALERTA",
    "info": "INFO",
}


def generar_pdf(resultado: dict) -> BytesIO:
    """Construye un PDF en memoria a partir de un diccionario de resultado de escaneo."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
    )

    styles = getSampleStyleSheet()
    titulo_style = ParagraphStyle(
        "TituloReporte", parent=styles["Title"], fontSize=20, spaceAfter=4
    )
    subtitulo_style = ParagraphStyle(
        "Subtitulo", parent=styles["Normal"], fontSize=10, textColor=colors.HexColor("#475569")
    )
    seccion_style = ParagraphStyle(
        "Seccion", parent=styles["Heading2"], fontSize=12, spaceBefore=14, spaceAfter=6
    )
    detalle_style = ParagraphStyle(
        "Detalle", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#334155")
    )
    explicacion_style = ParagraphStyle(
        "Explicacion", parent=styles["Normal"], fontSize=8, textColor=colors.HexColor("#64748b"),
        fontName="Helvetica-Oblique"
    )

    story = []

    # --- Encabezado ---
    story.append(Paragraph("Reporte de Auditoría de Seguridad Web", titulo_style))
    story.append(Paragraph(f"WebScan — generado el {resultado['fecha']}", subtitulo_style))
    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#cbd5e1")))
    story.append(Spacer(1, 12))

    # --- Resumen ---
    puntaje = resultado["puntaje"]
    if puntaje >= 80:
        color_puntaje = colors.HexColor("#15803d")
        nivel = "Bueno"
    elif puntaje >= 50:
        color_puntaje = colors.HexColor("#a16207")
        nivel = "Moderado"
    else:
        color_puntaje = colors.HexColor("#b91c1c")
        nivel = "Crítico"

    resumen_data = [
        ["URL analizada", resultado["url"]],
        ["Puntaje de seguridad", f"{puntaje}/100 ({nivel})"],
        ["Fecha de análisis", resultado["fecha"]],
        ["Total de hallazgos", str(len(resultado["resultados"]))],
    ]
    tabla_resumen = Table(resumen_data, colWidths=[5 * cm, 11 * cm])
    tabla_resumen.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#334155")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TEXTCOLOR", (1, 1), (1, 1), color_puntaje),
        ("FONTNAME", (1, 1), (1, 1), "Helvetica-Bold"),
    ]))
    story.append(tabla_resumen)
    story.append(Spacer(1, 18))

    # --- Detalle de hallazgos ---
    story.append(Paragraph("Detalle de hallazgos", seccion_style))

    for item in resultado["resultados"]:
        estado = item.get("estado", "info")
        color_estado = COLOR_ESTADO.get(estado, colors.grey)
        etiqueta = ETIQUETA_ESTADO.get(estado, estado.upper())

        nombre_style = ParagraphStyle(
            "Nombre", parent=styles["Normal"], fontSize=10, fontName="Helvetica-Bold"
        )

        fila = [
            Paragraph(item["nombre"], nombre_style),
            Paragraph(f'<font color="{color_estado.hexval()}"><b>{etiqueta}</b></font>', detalle_style),
        ]

        tabla_item = Table([fila], colWidths=[12.5 * cm, 3.5 * cm])
        tabla_item.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("LINEBELOW", (0, 0), (-1, 0), 0.5, colors.HexColor("#e2e8f0")),
        ]))

        story.append(tabla_item)
        story.append(Paragraph(item.get("detalle", ""), detalle_style))
        if item.get("explicacion") and item["explicacion"] != "No aplica.":
            story.append(Paragraph(item["explicacion"], explicacion_style))
        story.append(Spacer(1, 8))

    # --- Pie de página ---
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#cbd5e1")))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Generado automáticamente por WebScan. Este reporte refleja una auditoría básica "
        "basada en headers HTTP, cookies y configuración TLS visible públicamente.",
        explicacion_style
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer
