"""Shared HTML and PDF contract report generation."""

from __future__ import annotations

import hashlib
import io
import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import ROUND_FLOOR, ROUND_HALF_UP, Decimal
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr
from zoneinfo import ZoneInfo

from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from .models import Client, Contract, Task, TimeEntry

MONEY_QUANTUM = Decimal("0.01")
BRAND_GUNMETAL = "#2A2F36"
BRAND_SOFT_WHITE = "#E6EAF0"
BRAND_COOL_GREY = "#AAB2BF"
BRAND_PRIMARY_ACCENT = "#58ACE0"
BRAND_STANDARD_HOVER = "#65B7E6"
BRAND_ELEVATED_HOVER = "#74C3EC"
BRAND_LIGHT_SURFACE_ACCENT = "#1F5F87"
BRAND_PALE_STEEL = "#BBC7D3"
BRAND_MUTED_DEEP_ACCENT = "#2E8BC0"
BRAND_DARK_LOGO_CHARCOAL = "#2B333B"
BRAND_MUTED_EMERALD = "#3FB68B"

# The current PDF palette is centralized here without changing the approved
# layout. Its printer-focused visual design will be finalized after UAT.
PDF_BODY_TEXT = "#000000"
PDF_ALTERNATE_ROW = BRAND_SOFT_WHITE
PDF_FONT_REGULAR = "GrayhavenInter"
PDF_FONT_BOLD = "GrayhavenInter-Bold"
PDF_FALLBACK_FONT_REGULAR = "Helvetica"
PDF_FALLBACK_FONT_BOLD = "Helvetica-Bold"
PIE_COLORS = (
    BRAND_PRIMARY_ACCENT,
    BRAND_MUTED_EMERALD,
    BRAND_ELEVATED_HOVER,
    BRAND_MUTED_DEEP_ACCENT,
    BRAND_COOL_GREY,
    BRAND_LIGHT_SURFACE_ACCENT,
    BRAND_PALE_STEEL,
    BRAND_STANDARD_HOVER,
)


# ---------------------------------------------------------------------------
# Report data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReportSession:
    """One immutable session row at the report snapshot time."""

    user_name: str
    label: str
    started_at: datetime
    ended_at: datetime
    seconds: int
    cost: Decimal
    active: bool


@dataclass(frozen=True)
class ReportGroup:
    """Aggregated duration and cost for one task or subtask label."""

    label: str
    seconds: int
    cost: Decimal
    color: str


@dataclass(frozen=True)
class PieSlice:
    """HTML chart geometry and display values for one report group."""

    label: str
    path: str
    color: str
    duration: str
    cost: str


@dataclass(frozen=True)
class ContractReport:
    """Complete shared representation used by the HTML and PDF reports."""

    contract: Contract
    generated_at: datetime
    timezone: ZoneInfo
    sessions: tuple[ReportSession, ...]
    groups: tuple[ReportGroup, ...]
    pie_slices: tuple[PieSlice, ...]
    total_seconds: int
    total_cost: Decimal


@dataclass(frozen=True)
class ClientReport:
    """Complete client-wide report composed of newest-first contract sections."""

    client: Client
    generated_at: datetime
    timezone: ZoneInfo
    contracts: tuple[ContractReport, ...]
    total_seconds: int
    total_cost: Decimal


# ---------------------------------------------------------------------------
# Calculation and formatting
# ---------------------------------------------------------------------------


def utc_now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None, microsecond=0)


def duration_seconds(started_at: datetime, ended_at: datetime) -> int:
    return max(0, int((ended_at - started_at).total_seconds()))


def calculate_cost(seconds: int, hourly_rate_cents: int) -> Decimal:
    dollars = Decimal(seconds * hourly_rate_cents) / Decimal(360000)
    return dollars.quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def allocate_session_costs(
    durations: list[int], hourly_rate_cents: int
) -> tuple[Decimal, ...]:
    """Allocate rounded cents so session costs reconcile to their group total."""
    if not durations:
        return ()
    exact_cents = [
        Decimal(seconds * hourly_rate_cents) / Decimal(3600) for seconds in durations
    ]
    allocated_cents = [
        int(value.to_integral_value(rounding=ROUND_FLOOR)) for value in exact_cents
    ]
    target_cents = int(calculate_cost(sum(durations), hourly_rate_cents) * 100)
    cents_remaining = target_cents - sum(allocated_cents)
    priority = sorted(
        range(len(durations)),
        key=lambda index: (
            -(exact_cents[index] - allocated_cents[index]),
            index,
        ),
    )
    for index in priority[:cents_remaining]:
        allocated_cents[index] += 1
    return tuple(Decimal(cents) / Decimal(100) for cents in allocated_cents)


def format_duration(seconds: int) -> str:
    hours, remainder = divmod(int(seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours}:{minutes:02d}:{seconds:02d}"


def format_datetime(value: datetime, display_timezone: ZoneInfo) -> str:
    localized = value.replace(tzinfo=UTC).astimezone(display_timezone)
    return localized.strftime("%Y-%m-%d %I:%M:%S %p %Z")


def format_money(value: Decimal) -> str:
    return f"${value:,.2f}"


def report_state_etag(report: ContractReport | ClientReport) -> str:
    """Fingerprint report structure while excluding a running timer's age."""
    sections = (report,) if isinstance(report, ContractReport) else report.contracts
    state = {
        "client": [
            report.contract.client.id,
            report.contract.client.name,
        ]
        if isinstance(report, ContractReport)
        else [report.client.id, report.client.name],
        "contracts": [
            {
                "contract": [
                    section.contract.id,
                    section.contract.name,
                    section.contract.hourly_rate_cents,
                ],
                "sessions": [
                    [
                        item.user_name,
                        item.label,
                        item.started_at.isoformat(),
                        None if item.active else item.ended_at.isoformat(),
                    ]
                    for item in section.sessions
                ],
            }
            for section in sections
        ],
    }
    serialized = json.dumps(
        state,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(serialized).hexdigest()


def _pie_path(start_angle: float, end_angle: float) -> str:
    """Build an SVG sector path, including the full-circle special case."""
    center = 100.0
    radius = 86.0
    start_x = center + radius * math.cos(start_angle)
    start_y = center + radius * math.sin(start_angle)
    end_x = center + radius * math.cos(end_angle)
    end_y = center + radius * math.sin(end_angle)
    if end_angle - start_angle >= (2 * math.pi) - 1e-9:
        middle_angle = start_angle + math.pi
        middle_x = center + radius * math.cos(middle_angle)
        middle_y = center + radius * math.sin(middle_angle)
        return (
            f"M {center:.3f} {center:.3f} L {start_x:.3f} {start_y:.3f} "
            f"A {radius:.3f} {radius:.3f} 0 1 1 "
            f"{middle_x:.3f} {middle_y:.3f} "
            f"A {radius:.3f} {radius:.3f} 0 1 1 "
            f"{start_x:.3f} {start_y:.3f} Z"
        )
    large_arc = 1 if end_angle - start_angle > math.pi else 0
    return (
        f"M {center:.3f} {center:.3f} L {start_x:.3f} {start_y:.3f} "
        f"A {radius:.3f} {radius:.3f} 0 {large_arc} 1 "
        f"{end_x:.3f} {end_y:.3f} Z"
    )


def _build_pie_slices(groups: tuple[ReportGroup, ...]) -> tuple[PieSlice, ...]:
    total = sum(group.seconds for group in groups)
    if total <= 0:
        return ()
    angle = -math.pi / 2
    slices: list[PieSlice] = []
    for index, group in enumerate(groups):
        next_angle = (
            angle + (2 * math.pi * group.seconds / total)
            if index < len(groups) - 1
            else 3 * math.pi / 2
        )
        slices.append(
            PieSlice(
                label=group.label,
                path=_pie_path(angle, next_angle),
                color=group.color,
                duration=format_duration(group.seconds),
                cost=format_money(group.cost),
            )
        )
        angle = next_angle
    return tuple(slices)


# ---------------------------------------------------------------------------
# Report assembly and rendering
# ---------------------------------------------------------------------------


def build_contract_report(
    database: Session,
    contract: Contract,
    display_timezone: str,
    *,
    snapshot_at: datetime | None = None,
) -> ContractReport:
    """Snapshot a contract's sessions and reconcile grouped billing totals."""
    generated_at = snapshot_at or utc_now()
    timezone_info = ZoneInfo(display_timezone)
    entries = database.scalars(
        select(TimeEntry)
        .join(TimeEntry.task)
        .where(Task.contract_id == contract.id)
        .options(
            joinedload(TimeEntry.user),
            joinedload(TimeEntry.task),
            joinedload(TimeEntry.subtask),
        )
        .order_by(TimeEntry.started_at, TimeEntry.id)
    ).all()

    group_seconds: dict[str, int] = {}
    group_session_indexes: dict[str, list[int]] = {}
    session_data: list[tuple[str, str, datetime, datetime, int, bool]] = []
    for entry in entries:
        ended_at = entry.stopped_at or max(generated_at, entry.started_at)
        seconds = duration_seconds(entry.started_at, ended_at)
        label = (
            f"{entry.task.name} → {entry.subtask.name}"
            if entry.subtask
            else entry.task.name
        )
        group_seconds[label] = group_seconds.get(label, 0) + seconds
        group_session_indexes.setdefault(label, []).append(len(session_data))
        session_data.append(
            (
                entry.user.full_name,
                label,
                entry.started_at,
                ended_at,
                seconds,
                entry.stopped_at is None,
            )
        )

    session_costs = [Decimal(0)] * len(session_data)
    for indexes in group_session_indexes.values():
        allocated = allocate_session_costs(
            [session_data[index][4] for index in indexes],
            contract.hourly_rate_cents,
        )
        for index, cost in zip(indexes, allocated, strict=True):
            session_costs[index] = cost

    sessions = tuple(
        ReportSession(
            user_name=item[0],
            label=item[1],
            started_at=item[2],
            ended_at=item[3],
            seconds=item[4],
            cost=session_costs[index],
            active=item[5],
        )
        for index, item in enumerate(session_data)
    )

    groups = tuple(
        ReportGroup(
            label=label,
            seconds=seconds,
            cost=calculate_cost(seconds, contract.hourly_rate_cents),
            color=PIE_COLORS[index % len(PIE_COLORS)],
        )
        for index, (label, seconds) in enumerate(group_seconds.items())
    )
    total_seconds = sum(group.seconds for group in groups)
    return ContractReport(
        contract=contract,
        generated_at=generated_at,
        timezone=timezone_info,
        sessions=sessions,
        groups=groups,
        pie_slices=_build_pie_slices(groups),
        total_seconds=total_seconds,
        total_cost=sum((group.cost for group in groups), Decimal(0)),
    )


def build_client_report(
    database: Session,
    client: Client,
    display_timezone: str,
    *,
    snapshot_at: datetime | None = None,
) -> ClientReport:
    """Snapshot client contracts by active work, activity, then creation date."""
    generated_at = snapshot_at or utc_now()
    contracts = database.scalars(
        select(Contract)
        .where(Contract.client_id == client.id)
        .options(joinedload(Contract.client))
        .order_by(Contract.created_at.desc(), Contract.id.desc())
    ).all()
    unsorted_sections = tuple(
        build_contract_report(
            database,
            contract,
            display_timezone,
            snapshot_at=generated_at,
        )
        for contract in contracts
    )
    sections = tuple(
        sorted(
            unsorted_sections,
            key=lambda section: (
                not any(session.active for session in section.sessions),
                -max(
                    (
                        (
                            session.ended_at if not session.active else generated_at
                        ).timestamp()
                        for session in section.sessions
                    ),
                    default=float("-inf"),
                ),
                -(
                    section.contract.created_at.timestamp()
                    if section.contract.created_at is not None
                    else float("-inf")
                ),
                -section.contract.id,
            ),
        )
    )
    return ClientReport(
        client=client,
        generated_at=generated_at,
        timezone=ZoneInfo(display_timezone),
        contracts=sections,
        total_seconds=sum(section.total_seconds for section in sections),
        total_cost=sum((section.total_cost for section in sections), Decimal(0)),
    )


def build_pdf_legacy(
    report: ContractReport | ClientReport, branding_path: Path, contact_url: str
) -> io.BytesIO:
    """Render a client-wide or legacy contract report as a branded PDF."""
    sections = (report,) if isinstance(report, ContractReport) else report.contracts
    client = (
        report.contract.client if isinstance(report, ContractReport) else report.client
    )
    total_seconds = report.total_seconds
    total_cost = report.total_cost
    flattened_groups = tuple(
        ReportGroup(
            label=f"{section.contract.name} · {group.label}",
            seconds=group.seconds,
            cost=group.cost,
            color=group.color,
        )
        for section in sections
        for group in section.groups
    )
    buffer = io.BytesIO()
    font_regular, font_bold = _pdf_font_names(branding_path)
    page_size = landscape(letter)
    document = SimpleDocTemplate(
        buffer,
        pagesize=page_size,
        leftMargin=0.55 * inch,
        rightMargin=0.55 * inch,
        topMargin=0.45 * inch,
        bottomMargin=0.5 * inch,
        title=(f"Grayhaven Systems LLC - Client Time Report | {client.name}"),
        author="Grayhaven Systems LLC",
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="GrayhavenTitle",
            parent=styles["Title"],
            textColor=colors.HexColor(BRAND_DARK_LOGO_CHARCOAL),
            fontName=font_bold,
            fontSize=24,
            leading=28,
            alignment=0,
        )
    )
    styles.add(
        ParagraphStyle(
            name="GrayhavenBody",
            parent=styles["BodyText"],
            textColor=colors.HexColor(PDF_BODY_TEXT),
            fontName=font_regular,
            fontSize=9,
            leading=12,
        )
    )
    styles.add(
        ParagraphStyle(
            name="GrayhavenRight",
            parent=styles["GrayhavenBody"],
            alignment=TA_RIGHT,
        )
    )
    body = styles["GrayhavenBody"]
    heading = styles["GrayhavenTitle"]
    story: list[object] = []

    wordmark_path = branding_path / "grayhaven-logo-wordmark-light.png"
    if wordmark_path.is_file():
        logo: object = Image(str(wordmark_path), width=2.65 * inch, height=0.63 * inch)
    else:
        logo = Paragraph("<b>Grayhaven Systems LLC</b>", body)
    header = Table(
        [
            [
                logo,
                Paragraph(
                    "<b>CONFIDENTIAL</b><br/>Client Time Report",
                    styles["GrayhavenRight"],
                ),
            ]
        ],
        colWidths=[7.8 * inch, 2.1 * inch],
    )
    header.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                (
                    "LINEBELOW",
                    (0, 0),
                    (-1, -1),
                    0.8,
                    colors.HexColor(BRAND_PRIMARY_ACCENT),
                ),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    story.extend(
        [
            header,
            Spacer(1, 0.22 * inch),
            Paragraph("Client Time Report", heading),
            Paragraph(
                f"<b>Client:</b> {escape(client.name)}<br/>"
                f"<b>Contracts:</b> {len(sections)}<br/>"
                f"<b>Generated:</b> "
                f"{format_datetime(report.generated_at, report.timezone)}",
                body,
            ),
            Spacer(1, 0.2 * inch),
        ]
    )

    summary_header: list[object] = [
        "Task / Subtask",
        "Duration",
        "Cost",
    ]
    summary_group_rows: list[list[object]] = [
        [
            Paragraph(escape(group.label), body),
            format_duration(group.seconds),
            format_money(group.cost),
        ]
        for group in flattened_groups
    ]
    if not flattened_groups:
        summary_group_rows.append(["No time recorded", "0:00:00", "$0.00"])
    total_row: list[object] = [
        "Total",
        format_duration(total_seconds),
        format_money(total_cost),
    ]
    preview_limit = 8
    has_continuation = len(summary_group_rows) > preview_limit
    preview_rows = [summary_header, *summary_group_rows[:preview_limit]]
    if not has_continuation:
        preview_rows.append(total_row)
    preview_table = Table(
        preview_rows,
        colWidths=[4.3 * inch, 1.1 * inch, 1.35 * inch],
        repeatRows=1,
    )
    preview_table.setStyle(
        _pdf_table_style(
            font_regular,
            font_bold,
            highlight_last_row=not has_continuation,
        )
    )

    chart = Drawing(220, 205)
    pie = Pie()
    pie.x = 35
    pie.y = 15
    pie.width = 160
    pie.height = 160
    chart_groups = [group for group in flattened_groups if group.seconds > 0]
    pie.data = [group.seconds for group in chart_groups] or [1]
    pie.labels = None
    pie.slices.strokeWidth = 0.5
    for index, group in enumerate(chart_groups):
        pie.slices[index].fillColor = colors.HexColor(group.color)
    if not chart_groups:
        pie.slices[0].fillColor = colors.HexColor(BRAND_COOL_GREY)
    chart.add(pie)
    chart.add(
        String(
            0,
            194,
            "Time distribution",
            fontName=font_bold,
            fontSize=10,
            fillColor=colors.HexColor(PDF_BODY_TEXT),
        )
    )
    overview = Table([[preview_table, chart]], colWidths=[6.8 * inch, 3.1 * inch])
    overview.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(overview)
    if has_continuation:
        continuation_rows = [
            summary_header,
            *summary_group_rows[preview_limit:],
            total_row,
        ]
        continuation_table = Table(
            continuation_rows,
            colWidths=[7.3 * inch, 1.1 * inch, 1.35 * inch],
            repeatRows=1,
        )
        continuation_table.setStyle(
            _pdf_table_style(
                font_regular,
                font_bold,
                highlight_last_row=True,
            )
        )
        story.extend(
            [
                Spacer(1, 0.18 * inch),
                Paragraph("Summary continued", body),
                Spacer(1, 0.08 * inch),
                continuation_table,
            ]
        )
    story.extend(
        [
            Spacer(1, 0.18 * inch),
            Paragraph(
                "Questions or concerns? "
                f"<a href={quoteattr(contact_url)} "
                f'color="{BRAND_LIGHT_SURFACE_ACCENT}">'
                "Schedule a meeting with us</a>, and we will be happy to help.",
                body,
            ),
            PageBreak(),
            Paragraph("Detailed Session Log", heading),
        ]
    )
    detail_rows: list[list[object]] = [
        ["User", "Task / Subtask", "Start", "End", "Duration", "Cost"]
    ]
    for section in sections:
        for item in section.sessions:
            end_text = format_datetime(item.ended_at, report.timezone)
            if item.active:
                end_text += " (active snapshot)"
            detail_rows.append(
                [
                    Paragraph(escape(item.user_name), body),
                    Paragraph(escape(f"{section.contract.name} · {item.label}"), body),
                    Paragraph(format_datetime(item.started_at, report.timezone), body),
                    Paragraph(end_text, body),
                    format_duration(item.seconds),
                    format_money(item.cost),
                ]
            )
    if not any(section.sessions for section in sections):
        detail_rows.append(["No sessions recorded", "", "", "", "", ""])
    detail_table = Table(
        detail_rows,
        colWidths=[
            1.35 * inch,
            2.55 * inch,
            1.95 * inch,
            2.1 * inch,
            1 * inch,
            0.95 * inch,
        ],
        repeatRows=1,
    )
    detail_table.setStyle(_pdf_table_style(font_regular, font_bold, font_size=7))
    story.append(detail_table)

    def footer(page_canvas: Canvas, _: object) -> None:
        page_canvas.saveState()
        page_canvas.setStrokeColor(colors.HexColor(BRAND_PRIMARY_ACCENT))
        page_canvas.line(0.55 * inch, 0.34 * inch, 10.45 * inch, 0.34 * inch)
        page_canvas.setFillColor(colors.HexColor(BRAND_LIGHT_SURFACE_ACCENT))
        page_canvas.setFont(font_bold, 7)
        page_canvas.drawString(
            0.55 * inch,
            0.19 * inch,
            f"Page {page_canvas.getPageNumber()}",
        )
        page_canvas.drawRightString(10.45 * inch, 0.19 * inch, "CONFIDENTIAL")
        page_canvas.restoreState()

    document.build(story, onFirstPage=footer, onLaterPages=footer)
    buffer.seek(0)
    return buffer


def _pdf_table_style(
    font_regular: str,
    font_bold: str,
    font_size: int = 8,
    *,
    highlight_last_row: bool = False,
) -> TableStyle:
    commands: list[tuple[object, ...]] = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(BRAND_GUNMETAL)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor(BRAND_SOFT_WHITE)),
        ("FONTNAME", (0, 0), (-1, 0), font_bold),
        ("FONTNAME", (0, 1), (-1, -1), font_regular),
        ("FONTSIZE", (0, 0), (-1, -1), font_size),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor(BRAND_PALE_STEEL)),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (-2, 1), (-1, -1), "RIGHT"),
        (
            "ROWBACKGROUNDS",
            (0, 1),
            (-1, -2 if highlight_last_row else -1),
            [colors.white, colors.HexColor(PDF_ALTERNATE_ROW)],
        ),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    if highlight_last_row:
        commands.extend(
            [
                (
                    "BACKGROUND",
                    (0, -1),
                    (-1, -1),
                    colors.HexColor(BRAND_SOFT_WHITE),
                ),
                ("FONTNAME", (0, -1), (-1, -1), font_bold),
            ]
        )
    return TableStyle(commands)


def _pdf_font_names(branding_path: Path) -> tuple[str, str]:
    """Register local Inter fonts when available and return PDF font names."""
    regular_path = branding_path / "fonts" / "inter-400.ttf"
    bold_path = branding_path / "fonts" / "inter-700.ttf"
    if not regular_path.is_file() or not bold_path.is_file():
        return PDF_FALLBACK_FONT_REGULAR, PDF_FALLBACK_FONT_BOLD

    registered = set(pdfmetrics.getRegisteredFontNames())
    if PDF_FONT_REGULAR not in registered:
        pdfmetrics.registerFont(TTFont(PDF_FONT_REGULAR, str(regular_path)))
    if PDF_FONT_BOLD not in registered:
        pdfmetrics.registerFont(TTFont(PDF_FONT_BOLD, str(bold_path)))
    return PDF_FONT_REGULAR, PDF_FONT_BOLD


def _pdf_section_table(
    rows: list[list[object]],
    widths: list[float],
    font_regular: str,
    font_bold: str,
    *,
    numeric_columns: tuple[int, ...] = (),
    font_size: int = 8,
    highlight_total: bool = False,
) -> Table:
    """Build a light, printer-friendly report table with branded headers."""
    table = Table(rows, colWidths=widths, repeatRows=1)
    commands: list[tuple[object, ...]] = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(BRAND_GUNMETAL)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor(BRAND_SOFT_WHITE)),
        ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor(PDF_BODY_TEXT)),
        ("FONTNAME", (0, 0), (-1, 0), font_bold),
        ("FONTNAME", (0, 1), (-1, -1), font_regular),
        ("FONTSIZE", (0, 0), (-1, -1), font_size),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor(BRAND_PALE_STEEL)),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        (
            "ROWBACKGROUNDS",
            (0, 1),
            (-1, -1),
            [colors.white, colors.HexColor(PDF_ALTERNATE_ROW)],
        ),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    commands.extend(
        ("ALIGN", (column, 0), (column, -1), "RIGHT") for column in numeric_columns
    )
    if highlight_total:
        commands.extend(
            [
                ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor(BRAND_SOFT_WHITE)),
                ("FONTNAME", (0, -1), (-1, -1), font_bold),
            ]
        )
    table.setStyle(TableStyle(commands))
    return table


def _pdf_chart_and_legend(
    section: ContractReport,
    font_regular: str,
    font_bold: str,
) -> Table:
    """Render a contract pie chart and a wrapping legend matching the web report."""
    chart = Drawing(250, 230)
    chart.add(
        String(
            125,
            214,
            "Time Distribution",
            fontName=font_bold,
            fontSize=11,
            fillColor=colors.HexColor(BRAND_DARK_LOGO_CHARCOAL),
            textAnchor="middle",
        )
    )
    pie = Pie()
    pie.x = 46
    pie.y = 18
    pie.width = 155
    pie.height = 155
    populated_groups = [group for group in section.groups if group.seconds]
    pie.data = [group.seconds for group in populated_groups] or [1]
    pie.labels = None
    pie.slices.strokeWidth = 0.4
    for index, group in enumerate(populated_groups):
        pie.slices[index].fillColor = colors.HexColor(group.color)
    if not populated_groups:
        pie.slices[0].fillColor = colors.HexColor(BRAND_COOL_GREY)
    chart.add(pie)
    legend_style = ParagraphStyle(
        "Legend",
        fontName=font_regular,
        fontSize=7,
        leading=9,
        textColor=colors.HexColor(PDF_BODY_TEXT),
    )
    legend_limit = 12
    legend_groups = section.groups[:legend_limit]
    legend_rows: list[list[object]] = [
        [
            "",
            Paragraph(escape(group.label), legend_style),
            f"{format_duration(group.seconds)}  {format_money(group.cost)}",
        ]
        for group in legend_groups
    ]
    if len(section.groups) > legend_limit:
        legend_rows.append(
            ["", f"{len(section.groups) - legend_limit} additional items", ""]
        )
    if not legend_rows:
        legend_rows.append(["", "No time recorded", "0:00:00  $0.00"])
    legend = Table(legend_rows, colWidths=[0.13 * inch, 1.7 * inch, 1.15 * inch])
    legend_commands: list[tuple[object, ...]] = [
        ("FONTNAME", (0, 0), (-1, -1), font_regular),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor(PDF_BODY_TEXT)),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (-1, 0), (-1, -1), "RIGHT"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for index, group in enumerate(legend_groups):
        legend_commands.append(
            ("BACKGROUND", (0, index), (0, index), colors.HexColor(group.color))
        )
    legend.setStyle(TableStyle(legend_commands))
    overview = Table([[chart, legend]], colWidths=[3.5 * inch, 3.1 * inch])
    overview.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    return overview


def build_pdf(
    report: ContractReport | ClientReport, branding_path: Path, contact_url: str
) -> io.BytesIO:
    """Render a client-wide, per-contract PDF snapshot for color and B/W output."""
    sections = (report,) if isinstance(report, ContractReport) else report.contracts
    client = (
        report.contract.client if isinstance(report, ContractReport) else report.client
    )
    buffer = io.BytesIO()
    font_regular, font_bold = _pdf_font_names(branding_path)
    document = SimpleDocTemplate(
        buffer,
        pagesize=landscape(letter),
        leftMargin=0.55 * inch,
        rightMargin=0.55 * inch,
        topMargin=0.9 * inch,
        bottomMargin=0.65 * inch,
        title=f"Grayhaven Systems LLC - Client Time Report | {client.name}",
        author="Grayhaven Systems LLC",
    )
    styles = getSampleStyleSheet()
    heading = ParagraphStyle(
        "PdfHeading",
        parent=styles["Heading1"],
        fontName=font_bold,
        fontSize=18,
        leading=22,
        textColor=colors.HexColor(BRAND_LIGHT_SURFACE_ACCENT),
    )
    section_heading = ParagraphStyle(
        "PdfSectionHeading",
        parent=heading,
        fontSize=14,
        leading=18,
    )
    body = ParagraphStyle(
        "PdfBody",
        parent=styles["BodyText"],
        fontName=font_regular,
        fontSize=9,
        leading=12,
        textColor=colors.HexColor(PDF_BODY_TEXT),
    )
    story: list[object] = []
    for index, section in enumerate(sections):
        story.extend(
            [
                Paragraph("Client Time Report", heading),
                Paragraph(
                    (
                        f"<b>Contract:</b> {escape(section.contract.name)}<br/>"
                        f"<b>Generated:</b> "
                        f"{format_datetime(report.generated_at, report.timezone)}"
                    ),
                    body,
                ),
                Spacer(1, 0.16 * inch),
                Paragraph(section.contract.name, section_heading),
                Spacer(1, 0.08 * inch),
            ]
        )
        summary_rows: list[list[object]] = [["Task / Subtask", "Duration", "Cost"]]
        summary_rows.extend(
            [
                [
                    Paragraph(escape(group.label), body),
                    format_duration(group.seconds),
                    format_money(group.cost),
                ]
                for group in section.groups
            ]
        )
        if not section.groups:
            summary_rows.append(["No time recorded", "0:00:00", "$0.00"])
        summary_rows.append(
            [
                "Total",
                format_duration(section.total_seconds),
                format_money(section.total_cost),
            ]
        )
        story.append(
            _pdf_section_table(
                summary_rows,
                [4.0 * inch, 1.25 * inch, 1.2 * inch],
                font_regular,
                font_bold,
                numeric_columns=(2,),
                highlight_total=True,
            )
        )
        story.extend(
            [
                Spacer(1, 0.16 * inch),
                _pdf_chart_and_legend(section, font_regular, font_bold),
                PageBreak(),
                Paragraph(section.contract.name, section_heading),
                Paragraph("Detailed Session Log", heading),
                Spacer(1, 0.1 * inch),
            ]
        )
        detail_rows: list[list[object]] = [
            ["User", "Task / Subtask", "Start", "End", "Duration", "Cost"]
        ]
        for item in section.sessions:
            end_value = format_datetime(item.ended_at, report.timezone)
            if item.active:
                end_value += " (active snapshot)"
            detail_rows.append(
                [
                    Paragraph(escape(item.user_name), body),
                    Paragraph(escape(item.label), body),
                    Paragraph(format_datetime(item.started_at, report.timezone), body),
                    Paragraph(end_value, body),
                    format_duration(item.seconds),
                    format_money(item.cost),
                ]
            )
        if not section.sessions:
            detail_rows.append(["No sessions recorded", "", "", "", "", ""])
        story.append(
            _pdf_section_table(
                detail_rows,
                [
                    1.25 * inch,
                    2.25 * inch,
                    1.75 * inch,
                    1.75 * inch,
                    0.85 * inch,
                    0.85 * inch,
                ],
                font_regular,
                font_bold,
                numeric_columns=(5,),
                font_size=7,
            )
        )
        if index < len(sections) - 1:
            story.append(PageBreak())

    wordmark = branding_path / "grayhaven-logo-wordmark-light.png"

    def header_and_footer(page_canvas: Canvas, _: object) -> None:
        page_canvas.saveState()
        if wordmark.is_file():
            page_canvas.drawImage(
                str(wordmark),
                0.55 * inch,
                7.08 * inch,
                width=2.2 * inch,
                height=0.52 * inch,
                mask="auto",
            )
        page_canvas.setStrokeColor(colors.HexColor(BRAND_PRIMARY_ACCENT))
        page_canvas.line(0.55 * inch, 6.96 * inch, 10.45 * inch, 6.96 * inch)
        page_canvas.line(0.55 * inch, 0.42 * inch, 10.45 * inch, 0.42 * inch)
        page_canvas.setFillColor(colors.HexColor(BRAND_LIGHT_SURFACE_ACCENT))
        page_canvas.setFont(font_bold, 7)
        page_canvas.drawString(0.55 * inch, 0.24 * inch, "CONFIDENTIAL")
        page_canvas.setFillColor(colors.HexColor(PDF_BODY_TEXT))
        page_canvas.setFont(font_regular, 6.5)
        message = (
            "Questions or concerns? Schedule a meeting with us or email your "
            "point of contact and we will be happy to help."
        )
        page_canvas.drawCentredString(5.5 * inch, 0.24 * inch, message)
        page_canvas.linkURL(
            contact_url,
            (3.58 * inch, 0.18 * inch, 4.72 * inch, 0.33 * inch),
            relative=0,
        )
        page_canvas.setFillColor(colors.HexColor(BRAND_LIGHT_SURFACE_ACCENT))
        page_canvas.setFont(font_bold, 7)
        page_canvas.drawRightString(
            10.45 * inch,
            0.24 * inch,
            f"{client.name} - Page {page_canvas.getPageNumber()}",
        )
        page_canvas.restoreState()

    document.build(story, onFirstPage=header_and_footer, onLaterPages=header_and_footer)
    buffer.seek(0)
    return buffer
