"""Shared HTML and PDF client report generation."""

from __future__ import annotations

import hashlib
import io
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import ROUND_FLOOR, ROUND_HALF_UP, Decimal
from pathlib import Path
from xml.sax.saxutils import escape
from zoneinfo import ZoneInfo

from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
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
BRAND_PRIMARY_ACCENT = "#58ACE0"
BRAND_LIGHT_SURFACE_ACCENT = "#1F5F87"
BRAND_PALE_STEEL = "#BBC7D3"
PDF_BODY_TEXT = "#000000"
PDF_ALTERNATE_ROW = BRAND_SOFT_WHITE
PDF_FONT_REGULAR = "GrayhavenInter"
PDF_FONT_BOLD = "GrayhavenInter-Bold"
PDF_FALLBACK_FONT_REGULAR = "Helvetica"
PDF_FALLBACK_FONT_BOLD = "Helvetica-Bold"


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


@dataclass(frozen=True)
class ContractReport:
    """Complete contract report representation shared by HTML and PDF output."""

    contract: Contract
    generated_at: datetime
    timezone: ZoneInfo
    sessions: tuple[ReportSession, ...]
    groups: tuple[ReportGroup, ...]
    total_seconds: int
    total_cost: Decimal


@dataclass(frozen=True)
class ClientReport:
    """Client-wide report composed of consistently ordered contract sections."""

    client: Client
    generated_at: datetime
    timezone: ZoneInfo
    contracts: tuple[ContractReport, ...]
    total_seconds: int
    total_cost: Decimal


def utc_now() -> datetime:
    """Return the current UTC instant as a naive, second-precision value."""
    return datetime.now(UTC).replace(tzinfo=None, microsecond=0)


def duration_seconds(started_at: datetime, ended_at: datetime) -> int:
    """Return a non-negative elapsed duration."""
    return max(0, int((ended_at - started_at).total_seconds()))


def calculate_cost(seconds: int, hourly_rate_cents: int) -> Decimal:
    """Calculate a rounded dollar cost for a duration at a contract rate."""
    dollars = Decimal(seconds * hourly_rate_cents) / Decimal(360000)
    return dollars.quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def allocate_session_costs(
    durations: list[int], hourly_rate_cents: int
) -> tuple[Decimal, ...]:
    """Allocate cents so session costs reconcile to their containing group."""
    if not durations:
        return ()
    exact_cents = [
        Decimal(seconds * hourly_rate_cents) / Decimal(3600) for seconds in durations
    ]
    allocated_cents = [
        int(value.to_integral_value(rounding=ROUND_FLOOR)) for value in exact_cents
    ]
    target_cents = int(calculate_cost(sum(durations), hourly_rate_cents) * 100)
    priority = sorted(
        range(len(durations)),
        key=lambda index: (-(exact_cents[index] - allocated_cents[index]), index),
    )
    for index in priority[: target_cents - sum(allocated_cents)]:
        allocated_cents[index] += 1
    return tuple(Decimal(cents) / Decimal(100) for cents in allocated_cents)


def format_duration(seconds: int) -> str:
    """Format seconds as hours, minutes, and seconds."""
    hours, remainder = divmod(int(seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours}:{minutes:02d}:{seconds:02d}"


def format_datetime(value: datetime, display_timezone: ZoneInfo) -> str:
    """Format a stored UTC timestamp in the configured reporting timezone."""
    localized = value.replace(tzinfo=UTC).astimezone(display_timezone)
    return localized.strftime("%Y-%m-%d %I:%M:%S %p %Z")


def format_money(value: Decimal) -> str:
    """Format a dollar amount for the application UI and reports."""
    return f"${value:,.2f}"


def report_state_etag(report: ContractReport | ClientReport) -> str:
    """Fingerprint report structure while excluding a running timer's age."""
    sections = (report,) if isinstance(report, ContractReport) else report.contracts
    client = (
        report.contract.client if isinstance(report, ContractReport) else report.client
    )
    state = {
        "client": [client.id, client.name],
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
    return hashlib.sha256(
        json.dumps(
            state, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode()
    ).hexdigest()


def build_contract_report(
    database: Session,
    contract: Contract,
    display_timezone: str,
    *,
    snapshot_at: datetime | None = None,
) -> ContractReport:
    """Snapshot one contract's sessions and reconcile grouped billing totals."""
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
        costs = allocate_session_costs(
            [session_data[index][4] for index in indexes],
            contract.hourly_rate_cents,
        )
        for index, cost in zip(indexes, costs, strict=True):
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
        )
        for label, seconds in group_seconds.items()
    )
    return ContractReport(
        contract=contract,
        generated_at=generated_at,
        timezone=timezone_info,
        sessions=sessions,
        groups=groups,
        total_seconds=sum(group.seconds for group in groups),
        total_cost=sum((group.cost for group in groups), Decimal(0)),
    )


def build_client_report(
    database: Session,
    client: Client,
    display_timezone: str,
    *,
    snapshot_at: datetime | None = None,
) -> ClientReport:
    """Build a client report ordered by active work, activity, then creation."""
    generated_at = snapshot_at or utc_now()
    contracts = database.scalars(
        select(Contract)
        .where(Contract.client_id == client.id)
        .options(joinedload(Contract.client))
        .order_by(Contract.created_at.desc(), Contract.id.desc())
    ).all()
    sections = [
        build_contract_report(
            database, contract, display_timezone, snapshot_at=generated_at
        )
        for contract in contracts
    ]
    sections.sort(
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
        )
    )
    return ClientReport(
        client=client,
        generated_at=generated_at,
        timezone=ZoneInfo(display_timezone),
        contracts=tuple(sections),
        total_seconds=sum(section.total_seconds for section in sections),
        total_cost=sum((section.total_cost for section in sections), Decimal(0)),
    )


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


def _pdf_table(
    rows: list[list[object]],
    widths: list[float],
    font_regular: str,
    font_bold: str,
    *,
    numeric_columns: tuple[int, ...] = (),
    font_size: int = 8,
    highlight_total: bool = False,
) -> Table:
    """Build a full-width, light-background report table."""
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


def _pdf_outline(section: ContractReport, font_regular: str, font_bold: str) -> Table:
    """Create the contract duration, cost, and billable-rate outline."""
    table = Table(
        [
            ["Contract Duration", "Cost", "Billable Rate"],
            [
                format_duration(section.total_seconds),
                format_money(section.total_cost),
                f"{format_money(section.contract.hourly_rate)} per hour",
            ],
        ],
        colWidths=[3.3 * inch, 3.3 * inch, 3.3 * inch],
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(PDF_ALTERNATE_ROW)),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor(BRAND_PALE_STEEL)),
                ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor(BRAND_PALE_STEEL)),
                ("FONTNAME", (0, 0), (-1, 0), font_bold),
                ("FONTNAME", (0, 1), (-1, -1), font_regular),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor(PDF_BODY_TEXT)),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return table


def build_pdf(
    report: ContractReport | ClientReport, branding_path: Path, contact_url: str
) -> io.BytesIO:
    """Render an overview and full-width summary/detail pages per contract."""
    sections = (report,) if isinstance(report, ContractReport) else report.contracts
    client = (
        report.contract.client if isinstance(report, ContractReport) else report.client
    )
    buffer = io.BytesIO()
    font_regular, font_bold = _pdf_font_names(branding_path)
    page_width, page_height = landscape(letter)

    def body_frame() -> Frame:
        """Create a fresh frame for each template without shared layout state."""
        return Frame(
            0.55 * inch,
            0.68 * inch,
            page_width - 1.1 * inch,
            page_height - 2.53 * inch,
            id="report-body",
        )

    wordmark = branding_path / "grayhaven-logo-wordmark-light.png"

    def draw_page(canvas: Canvas, _: object, contract: Contract | None) -> None:
        canvas.saveState()
        if wordmark.is_file():
            canvas.drawImage(
                str(wordmark),
                0.55 * inch,
                7.05 * inch,
                width=2.15 * inch,
                height=0.51 * inch,
                mask="auto",
            )
        canvas.setStrokeColor(colors.HexColor(BRAND_PRIMARY_ACCENT))
        canvas.line(0.55 * inch, 6.92 * inch, 10.45 * inch, 6.92 * inch)
        canvas.setFillColor(colors.HexColor(BRAND_LIGHT_SURFACE_ACCENT))
        canvas.setFont(font_bold, 10)
        canvas.drawString(3.0 * inch, 7.39 * inch, "Client Time Report")
        if contract is not None:
            canvas.setFont(font_bold, 8)
            canvas.drawString(3.0 * inch, 7.17 * inch, f"{contract.name} Contract")
        canvas.setFont(font_regular, 7)
        canvas.drawString(
            3.0 * inch,
            7.0 * inch,
            f"Generated: {format_datetime(report.generated_at, report.timezone)}",
        )
        canvas.setStrokeColor(colors.HexColor(BRAND_PRIMARY_ACCENT))
        canvas.line(0.55 * inch, 0.42 * inch, 10.45 * inch, 0.42 * inch)
        canvas.setFillColor(colors.HexColor(BRAND_LIGHT_SURFACE_ACCENT))
        canvas.setFont(font_bold, 7)
        canvas.drawString(0.55 * inch, 0.24 * inch, "CONFIDENTIAL")
        canvas.setFillColor(colors.HexColor(PDF_BODY_TEXT))
        canvas.setFont(font_regular, 6.5)
        footer = (
            "Questions or concerns? Schedule a meeting with us or email your "
            "point of contact and we will be happy to help."
        )
        canvas.drawCentredString(5.5 * inch, 0.24 * inch, footer)
        canvas.linkURL(
            contact_url,
            (3.58 * inch, 0.18 * inch, 4.72 * inch, 0.33 * inch),
            relative=0,
        )
        canvas.setFillColor(colors.HexColor(BRAND_LIGHT_SURFACE_ACCENT))
        canvas.setFont(font_bold, 7)
        canvas.drawRightString(
            10.45 * inch,
            0.24 * inch,
            f"{client.name} - Page {canvas.getPageNumber()}",
        )
        canvas.restoreState()

    templates = [
        PageTemplate(
            id="overview",
            frames=[body_frame()],
            onPage=lambda c, d: draw_page(c, d, None),
        )
    ]
    for section in sections:
        templates.extend(
            [
                PageTemplate(
                    id=f"contract-summary-{section.contract.id}",
                    frames=[body_frame()],
                    onPage=lambda c, d, item=section.contract: draw_page(c, d, item),
                ),
                PageTemplate(
                    id=f"contract-detail-{section.contract.id}",
                    frames=[body_frame()],
                    onPage=lambda c, d, item=section.contract: draw_page(c, d, item),
                ),
            ]
        )
    document = BaseDocTemplate(
        buffer,
        pagesize=landscape(letter),
        pageTemplates=templates,
        title=f"Grayhaven Systems LLC - Client Time Report | {client.name}",
        author="Grayhaven Systems LLC",
    )
    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        "PdfTitle",
        parent=styles["Heading1"],
        fontName=font_bold,
        fontSize=18,
        leading=22,
        textColor=colors.HexColor(BRAND_LIGHT_SURFACE_ACCENT),
    )
    section_title = ParagraphStyle(
        "PdfSection",
        parent=title,
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
    story: list[object] = [
        _pdf_table(
            [
                ["Total Duration", "Cost", "Contracts"],
                [
                    format_duration(report.total_seconds),
                    format_money(report.total_cost),
                    str(len(sections)),
                ],
            ],
            [3.3 * inch, 3.3 * inch, 3.3 * inch],
            font_regular,
            font_bold,
            numeric_columns=(1,),
        ),
        Spacer(1, 0.22 * inch),
        Paragraph("Contract Overview", section_title),
        Spacer(1, 0.08 * inch),
    ]
    overview_rows: list[list[object]] = [
        ["Contract", "Duration", "Cost", "Billable Rate"]
    ]
    overview_rows.extend(
        [
            section.contract.name,
            format_duration(section.total_seconds),
            format_money(section.total_cost),
            f"{format_money(section.contract.hourly_rate)} per hour",
        ]
        for section in sections
    )
    if not sections:
        overview_rows.append(
            ["No contracts created", "0:00:00", "$0.00", "$0.00 per hour"]
        )
    story.append(
        _pdf_table(
            overview_rows,
            [4.6 * inch, 1.5 * inch, 1.5 * inch, 2.3 * inch],
            font_regular,
            font_bold,
            numeric_columns=(2,),
        )
    )
    for index, section in enumerate(sections):
        if index == 0:
            story.extend(
                [
                    NextPageTemplate(f"contract-summary-{section.contract.id}"),
                    PageBreak(),
                ]
            )
        story.extend(
            [
                Paragraph(f"{escape(section.contract.name)} Contract", section_title),
                Spacer(1, 0.1 * inch),
                _pdf_outline(section, font_regular, font_bold),
                Spacer(1, 0.18 * inch),
            ]
        )
        summary_rows: list[list[object]] = [["Task / Subtask", "Duration", "Cost"]]
        summary_rows.extend(
            [
                Paragraph(escape(group.label), body),
                format_duration(group.seconds),
                format_money(group.cost),
            ]
            for group in section.groups
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
        story.extend(
            [
                _pdf_table(
                    summary_rows,
                    [6.4 * inch, 1.7 * inch, 1.8 * inch],
                    font_regular,
                    font_bold,
                    numeric_columns=(2,),
                    highlight_total=True,
                ),
                NextPageTemplate(f"contract-detail-{section.contract.id}"),
                PageBreak(),
                Paragraph(f"{escape(section.contract.name)} Contract", section_title),
                Paragraph("Detailed Session Log", title),
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
            _pdf_table(
                detail_rows,
                [
                    1.25 * inch,
                    2.5 * inch,
                    1.85 * inch,
                    1.85 * inch,
                    1.15 * inch,
                    1.3 * inch,
                ],
                font_regular,
                font_bold,
                numeric_columns=(5,),
                font_size=7,
            )
        )
        if index < len(sections) - 1:
            next_contract = sections[index + 1].contract
            story.extend(
                [
                    NextPageTemplate(f"contract-summary-{next_contract.id}"),
                    PageBreak(),
                ]
            )
    document.build(story)
    buffer.seek(0)
    return buffer
