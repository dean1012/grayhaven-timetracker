"""Printer-friendly PDF rendering for immutable invoice snapshots."""

# mypy: disable-error-code="import-untyped"

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import UTC, datetime
from decimal import Decimal
from html import escape
from io import BytesIO
from pathlib import Path
from threading import Lock
from typing import Any
from zoneinfo import ZoneInfo

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .invoice_summary import daily_summary_rows, worker_summary_rows
from .models import Invoice, InvoiceLine

_FONT_LOCK = Lock()


def _text(value: object) -> str:
    return escape(str(value), quote=False)


def _fonts(regular_path: Path | None, bold_path: Path | None) -> tuple[str, str]:
    if regular_path is None and bold_path is None:
        return "Helvetica", "Helvetica-Bold"
    if regular_path is None or bold_path is None:
        raise ValueError("Both regular and bold invoice fonts are required")
    if not regular_path.is_file() or not bold_path.is_file():
        raise ValueError("Invoice font files are unavailable")
    digest = hashlib.sha256(
        f"{regular_path.resolve()}\0{bold_path.resolve()}".encode()
    ).hexdigest()[:12]
    regular_name = f"InvoiceInter-{digest}"
    bold_name = f"InvoiceInterBold-{digest}"
    with _FONT_LOCK:
        if regular_name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(regular_name, str(regular_path)))
        if bold_name not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont(bold_name, str(bold_path)))
        pdfmetrics.registerFontFamily(
            regular_name,
            normal=regular_name,
            bold=bold_name,
            italic=regular_name,
            boldItalic=bold_name,
        )
    return regular_name, bold_name


def _duration(seconds: int) -> str:
    hours, remainder = divmod(seconds, 3600)
    minutes, remaining_seconds = divmod(remainder, 60)
    parts = []
    for value, unit in (
        (hours, "hour"),
        (minutes, "minute"),
        (remaining_seconds, "second"),
    ):
        if value:
            parts.append(f"{value} {unit}{'' if value == 1 else 's'}")
    return " ".join(parts) or "0 seconds"


def _money(cents: int) -> str:
    return f"${Decimal(cents) / Decimal(100):,.2f}"


def _local(value: datetime, timezone: ZoneInfo) -> datetime:
    return value.replace(tzinfo=UTC).astimezone(timezone)


def render_invoice_pdf(
    invoice: Invoice,
    lines: Sequence[InvoiceLine],
    *,
    logo_path: Path | None = None,
    font_regular_path: Path | None = None,
    font_bold_path: Path | None = None,
) -> bytes:
    """Render invoice data to a self-contained, multi-page PDF byte string."""
    regular_font, bold_font = _fonts(font_regular_path, font_bold_path)
    timezone = ZoneInfo(invoice.timezone_name)
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=LETTER,
        rightMargin=0.55 * inch,
        leftMargin=0.55 * inch,
        topMargin=0.45 * inch,
        bottomMargin=0.75 * inch,
        title=f"Invoice {invoice.invoice_number}",
        author="Grayhaven Systems LLC",
    )
    styles = getSampleStyleSheet()
    body = ParagraphStyle(
        "InvoiceBody",
        parent=styles["BodyText"],
        fontName=regular_font,
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#202832"),
    )
    small = ParagraphStyle("InvoiceSmall", parent=body, fontSize=7.5, leading=9.5)
    bold = ParagraphStyle("InvoiceBold", parent=body, fontName=bold_font)
    section_heading = ParagraphStyle(
        "InvoiceSectionHeading",
        parent=bold,
        fontSize=11,
        leading=14,
        spaceAfter=0.1 * inch,
        keepWithNext=1,
    )
    summary_value = ParagraphStyle(
        "InvoiceSummaryValue",
        parent=bold,
        fontSize=8,
        leading=10,
    )
    status_label = {
        "PAID": "PAID",
        "VOID": "VOID",
        "UNPAID": "INVOICE",
    }.get(invoice.status, "INVOICE")
    status_color = {
        "PAID": colors.HexColor("#3FB68B"),
        "VOID": colors.HexColor("#AAB2BF"),
    }.get(invoice.status, colors.HexColor("#17202A"))
    heading = ParagraphStyle(
        "InvoiceHeading",
        parent=body,
        fontName=bold_font,
        fontSize=22,
        leading=25,
        textColor=status_color,
        alignment=TA_CENTER,
    )
    story: list[object] = []
    logo: Any
    if logo_path is not None:
        if not logo_path.is_file():
            raise ValueError("Invoice logo file is unavailable")
        logo = Image(str(logo_path))
        scale = min(
            (2.35 * inch) / logo.imageWidth,
            (0.55 * inch) / logo.imageHeight,
            1,
        )
        logo.drawWidth = logo.imageWidth * scale
        logo.drawHeight = logo.imageHeight * scale
        logo.hAlign = "LEFT"
    else:
        logo = Paragraph("Grayhaven Systems LLC", bold)
    header = Table(
        [[logo, Paragraph(status_label, heading)]],
        colWidths=[4.7 * inch, 2.2 * inch],
    )
    header.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LINEBELOW", (0, 0), (-1, -1), 0.8, colors.HexColor("#596572")),
            ]
        )
    )
    story.extend([header, Spacer(1, 0.22 * inch)])
    issue_date = _local(invoice.issued_at, timezone).date()
    details = Table(
        [
            [
                Paragraph("<b>Bill to</b>", bold),
                Paragraph(
                    f"<b>Invoice Number</b><br/>{_text(invoice.invoice_number)}",
                    body,
                ),
            ],
            [
                Paragraph(
                    f"{_text(invoice.client_name)}<br/>"
                    f"{_text(invoice.contact_name)}<br/>"
                    f"{_text(invoice.contact_email)}",
                    body,
                ),
                Paragraph(
                    f"<b>Issued</b><br/>{issue_date.isoformat()}<br/>"
                    f"<b>Due</b><br/>{invoice.due_date.isoformat()}",
                    body,
                ),
            ],
        ],
        colWidths=[4.75 * inch, 2.15 * inch],
    )
    details.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    range_start = _local(invoice.range_start_utc, timezone)
    range_end = _local(invoice.range_end_utc, timezone)
    story.extend(
        [
            details,
            Spacer(1, 0.15 * inch),
            HRFlowable(width="100%", thickness=0.7, color=colors.HexColor("#AAB2BB")),
            Spacer(1, 0.12 * inch),
            Paragraph(f"<b>Contract:</b> {_text(invoice.project_name)}", body),
            Paragraph(
                f"<b>Service Period:</b> {range_start:%Y-%m-%d %H:%M:%S %Z} "
                f"through {range_end:%Y-%m-%d %H:%M:%S %Z}",
                body,
            ),
            Paragraph(
                f"<b>Rate:</b> {_money(invoice.hourly_rate_cents)} per hour",
                body,
            ),
            Spacer(1, 0.14 * inch),
        ]
    )
    totals = Table(
        [
            [
                Paragraph("Total Time", bold),
                Paragraph(
                    f"<nobr>{_text(_duration(invoice.total_seconds))}</nobr>",
                    summary_value,
                ),
            ],
            [
                Paragraph("Invoice Total", bold),
                Paragraph(_money(invoice.total_cents), summary_value),
            ],
        ],
        colWidths=[1.05 * inch, 2.15 * inch],
        hAlign="RIGHT",
    )
    totals.setStyle(
        TableStyle(
            [
                ("ALIGN", (1, 0), (1, -1), "RIGHT"),
                ("LINEABOVE", (0, 1), (-1, 1), 0.8, colors.HexColor("#17202A")),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.extend([totals, Spacer(1, 0.18 * inch)])
    story.append(Paragraph("Daily Totals", section_heading))
    daily_data: list[list[object]] = [
        [Paragraph(label, bold) for label in ("Day", "Date", "Hours")]
    ]
    for day, hours in daily_summary_rows(invoice, lines, timezone):
        daily_data.append(
            [
                Paragraph(day.strftime("%A"), body),
                Paragraph(day.isoformat(), body),
                Paragraph("-" if hours is None else str(hours), body),
            ]
        )
    daily_table = Table(
        daily_data,
        colWidths=[2.4 * inch, 2.4 * inch, 2.6 * inch],
        repeatRows=1,
        hAlign="LEFT",
    )
    daily_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E5E9ED")),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#BCC4CC")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.extend(
        [
            daily_table,
            Paragraph(
                "Billable hours are rounded daily to the nearest 0.01 hour.", small
            ),
            Spacer(1, 0.2 * inch),
        ]
    )
    worker_data: list[list[object]] = [
        [Paragraph("Worker", bold), Paragraph("Hours", bold)]
    ]
    for worker_name, hours in worker_summary_rows(lines):
        worker_data.append(
            [
                Paragraph(_text(worker_name), body),
                Paragraph(str(hours), body),
            ]
        )
    worker_table = Table(
        worker_data,
        colWidths=[4.4 * inch, 3.0 * inch],
        repeatRows=1,
        hAlign="LEFT",
    )
    worker_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E5E9ED")),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#BCC4CC")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.extend(
        [
            Paragraph("Session Totals by Worker", section_heading),
            worker_table,
            PageBreak(),
            Paragraph("Invoiced Sessions", section_heading),
        ]
    )
    table_data: list[list[object]] = [
        [
            Paragraph("Worker", bold),
            Paragraph("Task / Subtask", bold),
            Paragraph("Start", bold),
            Paragraph("End", bold),
            Paragraph("Duration", bold),
        ]
    ]
    has_early_start = False
    for line in lines:
        started = _local(line.started_at_utc, timezone)
        stopped = _local(line.stopped_at_utc, timezone)
        has_early_start = has_early_start or line.started_before_range
        marker = "*" if line.started_before_range else ""
        work = line.task_name
        if line.subtask_name:
            work = f"{work} → {line.subtask_name}"
        table_data.append(
            [
                Paragraph(_text(line.worker_name), small),
                Paragraph(_text(work), small),
                Paragraph(f"{started:%Y-%m-%d}<br/>{started:%H:%M:%S}{marker}", small),
                Paragraph(f"{stopped:%Y-%m-%d}<br/>{stopped:%H:%M:%S}", small),
                Paragraph(
                    f"<nobr>{_text(_duration(line.total_seconds))}</nobr>", small
                ),
            ]
        )
    line_table = Table(
        table_data,
        colWidths=[
            1.1 * inch,
            1.8 * inch,
            1.25 * inch,
            1.25 * inch,
            2.0 * inch,
        ],
        repeatRows=1,
        hAlign="LEFT",
    )
    line_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E5E9ED")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#17202A")),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#BCC4CC")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.extend([line_table, Spacer(1, 0.12 * inch)])
    if has_early_start:
        story.extend(
            [
                Paragraph(
                    "* This entry started before the selected invoice range and "
                    "finished during it, so the full stopped session is billed.",
                    small,
                ),
                Spacer(1, 0.08 * inch),
            ]
        )
    terms = (
        "Due Immediately"
        if invoice.payment_terms_days == 0
        else (f"Net {invoice.payment_terms_days}")
    )

    def add_page_number(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        canvas.setFillColor(colors.HexColor("#5D6873"))
        canvas.setFont(regular_font, 7)
        canvas.drawString(0.55 * inch, 0.3 * inch, f"Payment Terms: {terms}")
        canvas.setFillColor(colors.black)
        canvas.setFont(bold_font, 7)
        canvas.drawCentredString(
            LETTER[0] / 2, 0.3 * inch, "Thank you for your business"
        )
        canvas.setFont(regular_font, 7)
        canvas.setFillColor(colors.HexColor("#5D6873"))
        canvas.drawRightString(
            LETTER[0] - 0.55 * inch,
            0.3 * inch,
            f"Invoice {invoice.invoice_number}  |  Page {doc.page}",
        )
        canvas.restoreState()

    document.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
    return buffer.getvalue()
