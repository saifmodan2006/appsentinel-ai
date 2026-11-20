import json
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

NAVY = colors.HexColor("#10243a")
SLATE = colors.HexColor("#465a71")
TEAL = colors.HexColor("#006374")
LINE = colors.HexColor("#d8e4ec")
FILL = colors.HexColor("#edf5f8")


def render_pdf(report):
    target = BytesIO()
    doc = SimpleDocTemplate(
        target,
        title="AppTrust Sentinel security report",
        author="AppTrust Sentinel",
        leftMargin=48,
        rightMargin=48,
        topMargin=50,
        bottomMargin=57,
    )
    title = ParagraphStyle(
        "Brand", fontName="Helvetica-Bold", fontSize=24, leading=28, textColor=NAVY
    )
    subtitle = ParagraphStyle(
        "Subtitle", fontName="Helvetica", fontSize=12, leading=17, textColor=SLATE
    )
    heading = ParagraphStyle(
        "Section",
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=18,
        textColor=NAVY,
        spaceBefore=15,
        spaceAfter=5,
        keepWithNext=True,
    )
    item = ParagraphStyle(
        "Finding",
        parent=heading,
        fontSize=10,
        leading=15,
        textColor=TEAL,
        spaceBefore=9,
        spaceAfter=2,
    )
    body = ParagraphStyle(
        "Body",
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=NAVY,
        splitLongWords=True,
        spaceAfter=3,
    )
    field = ParagraphStyle(
        "Field", parent=body, fontName="Helvetica-Bold", textColor=SLATE
    )

    def paragraph(value, style=body):
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False, separators=(", ", ": "))
        clean = "".join(
            c if c >= " " else " "
            for c in str(value if value is not None else "Unavailable")
        )
        return Paragraph(escape(clean), style)

    assessment = report["assessment"]
    metadata = report["metadata"]
    summary = Table(
        [
            [paragraph("APPLICATION", field), paragraph("RISK ASSESSMENT", field)],
            [
                paragraph((metadata.get("label") or metadata["package"])[:200]),
                paragraph(assessment["level"].replace("_", " ").capitalize()),
            ],
            [
                paragraph(metadata["package"][:255]),
                paragraph(report["identity"]["verdict"].replace("_", " ").capitalize()),
            ],
        ],
        colWidths=[doc.width * 0.58, doc.width * 0.42],
        hAlign="LEFT",
    )
    summary.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), FILL),
                ("BOX", (0, 0), (-1, -1), 0.6, LINE),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    elements = [
        paragraph("AppTrust Sentinel", title),
        paragraph("Android application security report", subtitle),
        Spacer(1, 14),
        summary,
    ]

    def section(name):
        elements.append(paragraph(name, heading))

    def rows(mapping):
        if not mapping:
            return [paragraph("None recorded.")]
        lines = []
        for name, value in mapping.items():
            label = name.replace("_", " ").capitalize()
            rendered = (
                json.dumps(value, ensure_ascii=False)
                if isinstance(value, (dict, list))
                else value
            )
            lines.append(
                paragraph(
                    f"{label} · {rendered if rendered is not None else 'Unavailable'}"
                )
            )
        return lines

    def values(mapping):
        elements.extend(rows(mapping))

    section("Assessment")
    elements.extend(paragraph(reason) for reason in assessment["reasons"])
    values(
        {
            key: report[key]
            for key in ("report_id", "scanned_at", "filename", "bytes", "sha256")
        }
    )
    values({"policy_version": assessment["policy_version"]})
    section("Publisher authenticity")
    values(report["identity"])
    section("Signing verification")
    values(
        {key: value for key, value in report["signing"].items() if value is not None}
    )
    section("Security findings")
    if not report["findings"]:
        elements.append(paragraph("No findings from the checks that ran."))
    for finding in report["findings"]:
        finding_title = f"{finding['id']}   {finding['title']}   ·   {finding['severity'].capitalize()}"
        fields = ("evidence", "source", "limitation", "action", "reference", "version")
        elements.append(
            KeepTogether(
                [
                    paragraph(finding_title, item),
                    paragraph(finding["description"]),
                    *rows({key: finding[key] for key in fields}),
                ]
            )
        )
    section("Model and threat intelligence")
    model = report["model"]
    values({"model_status": model["status"], "model_reason": model["reason"]})
    if model["status"] == "experimental":
        values(
            {
                key: value
                for key, value in model.items()
                if key not in {"status", "reason"}
            }
        )
    if threat := report.get("threat_indicators"):
        values(
            {"indicator_status": threat["status"], "indicator_scope": threat["reason"]}
        )
    section("Coverage and limitations")
    for limitation in report["limitations"]:
        elements.append(paragraph(limitation))
    for unavailable in report["missing"]:
        elements.append(paragraph(f"{unavailable['field']} · {unavailable['reason']}"))
    section("APK metadata and inventory")
    values({key: value for key, value in metadata.items() if key != "resource_entries"})
    resources = metadata.get("resource_entries", [])
    if resources:
        values({"resource_sample": resources[:10]})
        if len(resources) > 10:
            elements.append(
                paragraph(
                    f"The JSON export includes all {len(resources)} recorded resource paths."
                )
            )
    section("Code observations")
    values(report["code"])
    section("Analysis versions")
    values(
        {
            **report["tools"],
            "rule_version": report["rule_version"],
            "schema_version": report["schema_version"],
            "analysis_seconds": report["analysis_seconds"],
        }
    )

    def footer(canvas, document):
        canvas.setStrokeColor(LINE)
        canvas.line(48, 46, document.pagesize[0] - 48, 46)
        canvas.setFillColor(SLATE)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(48, 33, f"AppTrust Sentinel  |  {report['report_id']}")
        canvas.drawRightString(document.pagesize[0] - 48, 33, f"Page {document.page}")

    doc.build(elements, onFirstPage=footer, onLaterPages=footer)
    return target.getvalue()
