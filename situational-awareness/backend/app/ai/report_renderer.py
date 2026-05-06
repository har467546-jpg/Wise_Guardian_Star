from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from html import escape
from io import BytesIO
from pathlib import Path
from typing import Any

from app.db.models.enums import ReportScope

WEB_PORTS = {80, 443, 8080, 8443}
SENSITIVE_PORTS = {
    21, 22, 23, 25, 53, 110, 111, 135, 137, 138, 139, 143, 161, 389, 443, 445, 465, 512, 513, 514, 5432, 3306, 3389,
    5900, 6379, 8080, 8443, 9200, 9300, 2375, 2376, 11211, 27017, 50070, 5601, 9090, 10000,
}
WEB_SERVICE_MARKERS = {
    "http",
    "https",
    "apache",
    "nginx",
    "tomcat",
    "php",
    "phpmyadmin",
    "drupal",
    "twiki",
    "iis",
    "jetty",
}
SENSITIVE_SERVICE_MARKERS = {
    "ssh",
    "ftp",
    "telnet",
    "smb",
    "rdp",
    "vnc",
    "mysql",
    "redis",
    "postgres",
    "postgresql",
    "mongodb",
    "docker",
    "kubernetes",
    "elasticsearch",
    "kibana",
    "apache",
    "nginx",
    "tomcat",
    "phpmyadmin",
}
SENSITIVE_MIDDLEWARE_MARKERS = {
    "apache",
    "nginx",
    "tomcat",
    "phpmyadmin",
    "drupal",
    "twiki",
    "mysql",
    "redis",
    "postgres",
    "postgresql",
    "mongodb",
    "docker",
    "kubernetes",
    "elasticsearch",
    "kibana",
    "jenkins",
}
WEAK_PASSWORD_MARKERS = (
    "弱口令",
    "默认凭据",
    "默认口令",
    "默认密码",
    "空密码",
    "匿名登录",
    "anonymous",
    "default creds",
    "default credential",
    "default password",
    "empty password",
)
WEB_FINDING_MARKERS = (
    "http",
    "https",
    "web",
    "网站",
    "站点",
    "apache",
    "nginx",
    "tomcat",
    "phpmyadmin",
    "drupal",
    "twiki",
    ".git",
    "cgi",
    "shellshock",
    "manager/html",
)
SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
}
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass(frozen=True)
class _SectionDefinition:
    number: str
    title: str
    anchor: str
    level: int = 1


@dataclass
class _RenderedSection:
    definition: _SectionDefinition
    blocks: list[dict[str, Any]] = field(default_factory=list)


SECTION_DEFINITIONS = [
    _SectionDefinition("1", "检测结果综述", "section-1"),
    _SectionDefinition("2", "资产总体概览", "section-2"),
    _SectionDefinition("2.1", "资产基本信息", "section-2-1", level=2),
    _SectionDefinition("2.2", "整体漏洞统计", "section-2-2", level=2),
    _SectionDefinition("2.3", "敏感端口/服务", "section-2-3", level=2),
    _SectionDefinition("2.4", "敏感中间件", "section-2-4", level=2),
    _SectionDefinition("3", "资产端口服务信息", "section-3"),
    _SectionDefinition("4", "主机漏洞信息", "section-4"),
    _SectionDefinition("4.1", "主机漏洞统计概况", "section-4-1", level=2),
    _SectionDefinition("4.2", "主机漏洞详情", "section-4-2", level=2),
    _SectionDefinition("5", "WEB漏洞信息", "section-5"),
    _SectionDefinition("5.1", "WEB漏洞统计概况", "section-5-1", level=2),
    _SectionDefinition("5.2", "WEB漏洞详情", "section-5-2", level=2),
    _SectionDefinition("6", "弱口令", "section-6"),
    _SectionDefinition("7", "参考标准", "section-7"),
    _SectionDefinition("7.1", "单一漏洞风险等级评定标准", "section-7-1", level=2),
    _SectionDefinition("7.2", "资产风险等级评定标准", "section-7-2", level=2),
    _SectionDefinition("8", "安全建议", "section-8"),
]


class VulnerabilityReportRenderer:
    def render_html(
        self,
        *,
        scope: ReportScope | str,
        scope_id: str,
        analysis: dict[str, Any],
        report_id: str,
        created_at: datetime | str | None,
    ) -> tuple[str, str]:
        context = self._build_context(scope=scope, scope_id=scope_id, analysis=analysis, report_id=report_id, created_at=created_at)
        template = self._load_html_template()
        toc_html = self._render_source_toc_html()
        main_content_html = self._render_source_main_content_html(context)
        script = self._render_source_chart_script(context)
        html = (
            template
            .replace("__REPORT_TITLE__", escape(context["title"]))
            .replace("__REPORT_SUBTITLE__", escape(context["subtitle"]))
            .replace("__CREATED_AT__", escape(context["created_label"]))
            .replace("__TOC_HTML__", toc_html)
            .replace("__MAIN_CONTENT_HTML__", main_content_html)
            .replace("__REPORT_SCRIPT__", script)
        )
        return self._build_filename(context["scope"], scope_id, context.get("task_id"), "html"), html

    def render_pdf(
        self,
        *,
        scope: ReportScope | str,
        scope_id: str,
        analysis: dict[str, Any],
        report_id: str,
        created_at: datetime | str | None,
    ) -> tuple[str, bytes]:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.cidfonts import UnicodeCIDFont
        from reportlab.platypus import ListFlowable, ListItem, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        context = self._build_context(scope=scope, scope_id=scope_id, analysis=analysis, report_id=report_id, created_at=created_at)
        sections = self._build_sections(context)

        try:
            pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
            font_name = "STSong-Light"
        except Exception:
            font_name = "Helvetica"

        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], fontName=font_name, fontSize=22, leading=28, textColor=colors.HexColor("#10233d")))
        styles.add(ParagraphStyle(name="ReportSubtitle", parent=styles["BodyText"], fontName=font_name, fontSize=10.5, leading=16, textColor=colors.HexColor("#526377")))
        styles.add(ParagraphStyle(name="SectionLevel1", parent=styles["Heading1"], fontName=font_name, fontSize=17, leading=24, textColor=colors.HexColor("#0f766e"), spaceAfter=8, spaceBefore=12))
        styles.add(ParagraphStyle(name="SectionLevel2", parent=styles["Heading2"], fontName=font_name, fontSize=13.5, leading=18, textColor=colors.HexColor("#10233d"), spaceAfter=6, spaceBefore=10))
        styles.add(ParagraphStyle(name="BodyCN", parent=styles["BodyText"], fontName=font_name, fontSize=9.5, leading=14, textColor=colors.HexColor("#132238"), alignment=TA_LEFT))
        styles.add(ParagraphStyle(name="SmallCN", parent=styles["BodyText"], fontName=font_name, fontSize=8.5, leading=12, textColor=colors.HexColor("#5d6b82")))

        class _BookmarkParagraph(Paragraph):
            def __init__(self, text: str, style, bookmark_name: str, outline_level: int) -> None:
                super().__init__(text, style)
                self.bookmark_name = bookmark_name
                self.outline_level = outline_level
                self.outline_text = text

            def draw(self) -> None:
                self.canv.bookmarkPage(self.bookmark_name)
                self.canv.addOutlineEntry(self.outline_text, self.bookmark_name, level=max(0, self.outline_level), closed=False)
                super().draw()

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=landscape(A4),
            leftMargin=15 * mm,
            rightMargin=15 * mm,
            topMargin=12 * mm,
            bottomMargin=12 * mm,
            title=context["title"],
            author="Situational Awareness",
        )
        story: list[Any] = [
            Paragraph(escape(context["title"]), styles["ReportTitle"]),
            Spacer(1, 4 * mm),
            Paragraph(escape(context["subtitle"]), styles["ReportSubtitle"]),
            Spacer(1, 2 * mm),
            Paragraph(f"生成时间：{escape(context['created_label'])}", styles["SmallCN"]),
            Spacer(1, 6 * mm),
            Paragraph("目录", styles["SectionLevel1"]),
        ]
        toc_items = [
            ListItem(Paragraph(f"{escape(section.definition.number)} {escape(section.definition.title)}", styles["BodyCN"]), leftIndent=12 * max(0, section.definition.level - 1))
            for section in sections
        ]
        story.append(ListFlowable(toc_items, bulletType="bullet", start="circle"))
        story.append(Spacer(1, 5 * mm))

        for section in sections:
            heading_style = styles["SectionLevel2"] if section.definition.level == 2 else styles["SectionLevel1"]
            story.append(
                _BookmarkParagraph(
                    f"{escape(section.definition.number)} {escape(section.definition.title)}",
                    heading_style,
                    bookmark_name=section.definition.anchor,
                    outline_level=section.definition.level - 1,
                )
            )
            if not section.blocks:
                story.append(Spacer(1, 4 * mm))
                continue
            for block in section.blocks:
                kind = block.get("kind")
                if kind == "paragraph":
                    story.append(Paragraph(self._paragraph_to_pdf(block.get("text") or ""), styles["BodyCN"]))
                    story.append(Spacer(1, 2.5 * mm))
                elif kind == "kv":
                    table = Table(
                        [[Paragraph(escape(label), styles["SmallCN"]), Paragraph(self._paragraph_to_pdf(value), styles["BodyCN"])] for label, value in block.get("rows", [])],
                        colWidths=[52 * mm, 190 * mm],
                        repeatRows=0,
                    )
                    table.setStyle(
                        TableStyle(
                            [
                                ("FONTNAME", (0, 0), (-1, -1), font_name),
                                ("FONTSIZE", (0, 0), (-1, -1), 9),
                                ("LEADING", (0, 0), (-1, -1), 12),
                                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef4f6")),
                                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#355f5a")),
                                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d7e0ea")),
                                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                                ("TOPPADDING", (0, 0), (-1, -1), 6),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                            ]
                        )
                    )
                    story.append(table)
                    story.append(Spacer(1, 3 * mm))
                elif kind == "table":
                    headers = [Paragraph(escape(str(item)), styles["SmallCN"]) for item in block.get("headers", [])]
                    rows = [
                        [Paragraph(self._paragraph_to_pdf(str(cell)), styles["BodyCN"]) for cell in row]
                        for row in block.get("rows", [])
                    ]
                    table_data = [headers, *rows] if headers else rows
                    col_count = len(block.get("headers", [])) or (len(block.get("rows", [])[0]) if block.get("rows") else 1)
                    col_width = 257 * mm / max(1, col_count)
                    table = Table(table_data, colWidths=[col_width] * col_count, repeatRows=1 if headers else 0)
                    table.setStyle(
                        TableStyle(
                            [
                                ("FONTNAME", (0, 0), (-1, -1), font_name),
                                ("FONTSIZE", (0, 0), (-1, -1), 8.6),
                                ("LEADING", (0, 0), (-1, -1), 11.2),
                                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d7e0ea")),
                                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                                ("TOPPADDING", (0, 0), (-1, -1), 5),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                            ]
                        )
                    )
                    if headers:
                        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#edf5f4")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#1d4b45"))]))
                    story.append(table)
                    story.append(Spacer(1, 3 * mm))
                elif kind == "bullets":
                    items = [
                        ListItem(Paragraph(self._paragraph_to_pdf(str(item)), styles["BodyCN"]), leftIndent=0)
                        for item in block.get("items", [])
                    ]
                    story.append(ListFlowable(items, bulletType="bullet", start="circle"))
                    story.append(Spacer(1, 3 * mm))

        def _on_page(canvas, document) -> None:  # type: ignore[no-untyped-def]
            canvas.saveState()
            canvas.setFont(font_name, 8)
            canvas.setFillColor(colors.HexColor("#5d6b82"))
            canvas.drawRightString(document.pagesize[0] - 15 * mm, 8 * mm, f"第 {document.page} 页")
            canvas.restoreState()

        doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
        return self._build_filename(context["scope"], scope_id, context.get("task_id"), "pdf"), buffer.getvalue()

    def _build_context(
        self,
        *,
        scope: ReportScope | str,
        scope_id: str,
        analysis: dict[str, Any],
        report_id: str,
        created_at: datetime | str | None,
    ) -> dict[str, Any]:
        normalized_scope = getattr(scope, "value", str(scope)).lower()
        asset = analysis.get("asset") if isinstance(analysis.get("asset"), dict) else {}
        job = analysis.get("job") if isinstance(analysis.get("job"), dict) else {}
        if normalized_scope == ReportScope.ASSET.value:
            services = [self._normalize_service_row(item, asset=asset) for item in analysis.get("services", []) if isinstance(item, dict)]
            findings = [self._normalize_finding_row(item, asset=asset) for item in analysis.get("findings", []) if isinstance(item, dict)]
            asset_count = 1
            title = f"资产漏洞报告 - {asset.get('ip') or scope_id}"
            subtitle = f"报告对象：资产 {asset.get('ip') or scope_id}"
        else:
            asset_summaries = analysis.get("asset_summaries") if isinstance(analysis.get("asset_summaries"), list) else []
            services = []
            findings = []
            for item in asset_summaries:
                if not isinstance(item, dict):
                    continue
                current_asset = item.get("asset") if isinstance(item.get("asset"), dict) else {}
                services.extend(self._normalize_service_row(service, asset=current_asset) for service in item.get("services", []) if isinstance(service, dict))
                findings.extend(self._normalize_finding_row(finding, asset=current_asset) for finding in item.get("findings", []) if isinstance(finding, dict))
            asset_count = int(job.get("asset_count") or len({item.get("asset_id") for item in services if item.get("asset_id")}) or 0)
            title = f"任务漏洞报告 - {job.get('cidr') or scope_id}"
            subtitle = f"报告对象：扫描任务 {job.get('cidr') or scope_id}"

        created_label = self._format_datetime(created_at)
        open_findings = [item for item in findings if item.get("status") in {"open", ""}]
        web_findings = [item for item in open_findings if self._is_web_finding(item)]
        weak_password_findings = [item for item in open_findings if self._is_weak_password_finding(item)]
        host_findings = [item for item in open_findings if item not in web_findings and item not in weak_password_findings]
        sensitive_services = [item for item in services if self._is_sensitive_service(item)]
        sensitive_middlewares = self._build_sensitive_middleware_rows(services)
        recommendations = [item for item in analysis.get("recommendations", []) if isinstance(item, dict)]
        risk_summary = analysis.get("risk_summary") if isinstance(analysis.get("risk_summary"), dict) else {}
        risk_priority = analysis.get("risk_priority") if isinstance(analysis.get("risk_priority"), dict) else {}
        return {
            "scope": normalized_scope,
            "scope_id": scope_id,
            "report_id": report_id,
            "task_id": str(analysis.get("task_id") or "") if isinstance(analysis, dict) else "",
            "title": title,
            "subtitle": subtitle,
            "created_label": created_label,
            "asset": asset,
            "job": job,
            "services": self._sort_services(services),
            "open_findings": self._sort_findings(open_findings),
            "host_findings": self._sort_findings(host_findings),
            "web_findings": self._sort_findings(web_findings),
            "weak_password_findings": self._sort_findings(weak_password_findings),
            "sensitive_services": self._sort_services(sensitive_services),
            "sensitive_middlewares": sensitive_middlewares,
            "recommendations": recommendations,
            "risk_summary": risk_summary,
            "risk_priority": risk_priority,
            "usage_hypothesis": analysis.get("usage_hypothesis") if isinstance(analysis.get("usage_hypothesis"), dict) else {},
            "asset_count": asset_count,
        }

    def _build_sections(self, context: dict[str, Any]) -> list[_RenderedSection]:
        definitions = {item.number: item for item in SECTION_DEFINITIONS}
        sections: list[_RenderedSection] = []

        sections.append(
            _RenderedSection(
                definitions["1"],
                blocks=[
                    {
                        "kind": "paragraph",
                        "text": self._build_summary_paragraph(context),
                    },
                    {
                        "kind": "kv",
                        "rows": self._summary_rows(context),
                    },
                ],
            )
        )

        sections.append(_RenderedSection(definitions["2"]))
        sections.append(_RenderedSection(definitions["2.1"], blocks=[{"kind": "kv", "rows": self._asset_basic_info_rows(context)}]))
        sections.append(_RenderedSection(definitions["2.2"], blocks=[{"kind": "kv", "rows": self._overall_stat_rows(context)}]))
        sections.append(
            _RenderedSection(
                definitions["2.3"],
                blocks=self._table_or_empty(
                    headers=self._service_headers(include_asset=context["scope"] != ReportScope.ASSET.value),
                    rows=[self._service_row_values(item, include_asset=context["scope"] != ReportScope.ASSET.value) for item in context["sensitive_services"]],
                ),
            )
        )
        sections.append(
            _RenderedSection(
                definitions["2.4"],
                blocks=self._table_or_empty(
                    headers=["中间件", "版本", "归属资产"],
                    rows=context["sensitive_middlewares"],
                ),
            )
        )
        sections.append(
            _RenderedSection(
                definitions["3"],
                blocks=self._table_or_empty(
                    headers=self._service_headers(include_asset=context["scope"] != ReportScope.ASSET.value),
                    rows=[self._service_row_values(item, include_asset=context["scope"] != ReportScope.ASSET.value) for item in context["services"]],
                ),
            )
        )

        sections.append(_RenderedSection(definitions["4"]))
        sections.append(_RenderedSection(definitions["4.1"], blocks=[{"kind": "kv", "rows": self._finding_stat_rows(context["host_findings"])}]))
        sections.append(
            _RenderedSection(
                definitions["4.2"],
                blocks=self._table_or_empty(
                    headers=self._finding_headers(include_asset=context["scope"] != ReportScope.ASSET.value),
                    rows=[self._finding_row_values(item, include_asset=context["scope"] != ReportScope.ASSET.value) for item in context["host_findings"]],
                ),
            )
        )

        sections.append(_RenderedSection(definitions["5"]))
        sections.append(_RenderedSection(definitions["5.1"], blocks=[{"kind": "kv", "rows": self._finding_stat_rows(context["web_findings"])}]))
        sections.append(
            _RenderedSection(
                definitions["5.2"],
                blocks=self._table_or_empty(
                    headers=self._finding_headers(include_asset=context["scope"] != ReportScope.ASSET.value),
                    rows=[self._finding_row_values(item, include_asset=context["scope"] != ReportScope.ASSET.value) for item in context["web_findings"]],
                ),
            )
        )

        sections.append(
            _RenderedSection(
                definitions["6"],
                blocks=self._table_or_empty(
                    headers=self._finding_headers(include_asset=context["scope"] != ReportScope.ASSET.value),
                    rows=[self._finding_row_values(item, include_asset=context["scope"] != ReportScope.ASSET.value) for item in context["weak_password_findings"]],
                ),
            )
        )

        sections.append(_RenderedSection(definitions["7"]))
        sections.append(_RenderedSection(definitions["7.1"], blocks=[{"kind": "table", "headers": ["等级", "判定标准"], "rows": self._single_finding_standard_rows()}]))
        sections.append(_RenderedSection(definitions["7.2"], blocks=[{"kind": "table", "headers": ["等级", "判定标准"], "rows": self._asset_priority_standard_rows()}]))

        sections.append(
            _RenderedSection(
                definitions["8"],
                blocks=self._bullet_or_empty(self._recommendation_items(context)),
            )
        )
        return sections

    def _load_html_template(self) -> str:
        template_path = Path(__file__).with_name("gemini_report_template.html")
        return template_path.read_text(encoding="utf-8")

    def _render_source_toc_html(self) -> str:
        parts: list[str] = []
        sub_links: list[str] = []
        for definition in SECTION_DEFINITIONS:
            link_html = f'<a href="#{definition.anchor}" class="nav-link">{escape(definition.number)} {escape(definition.title)}</a>'
            if definition.level == 1:
                if sub_links:
                    parts.append(f'<div class="sub-nav">{"".join(sub_links)}</div>')
                    sub_links = []
                parts.append(link_html)
            else:
                sub_links.append(link_html)
        if sub_links:
            parts.append(f'<div class="sub-nav">{"".join(sub_links)}</div>')
        return "".join(parts)

    def _render_source_main_content_html(self, context: dict[str, Any]) -> str:
        definitions = {item.number: item for item in SECTION_DEFINITIONS}
        sections = [
            self._render_source_section_card(
                definitions["1"],
                self._render_source_stats_grid(
                    [
                        ("资产总数", str(context["asset_count"]), "primary"),
                        ("漏洞总数", str(len(context["open_findings"])), "danger" if context["open_findings"] else ""),
                        ("最高风险级别", self._severity_text(context["risk_summary"].get("highest_severity")), "danger" if context["risk_summary"].get("highest_severity") in {"critical", "high"} else "warning"),
                        ("资产风险等级", f"{context['risk_priority'].get('level') or 'P5'} / {context['risk_priority'].get('score') or 0}", "warning"),
                    ]
                )
                + f'<p class="summary-text">{self._html_paragraph(self._build_summary_paragraph(context))}</p>',
            ),
            self._render_source_section_card(
                definitions["2"],
                self._render_source_subsection(
                    definitions["2.1"],
                    self._render_source_info_table(["字段", "内容"], [[label, value] for label, value in self._asset_basic_info_rows(context)]),
                )
                + self._render_source_subsection(
                    definitions["2.2"],
                    self._render_source_stats_grid(
                        [
                            ("严重漏洞", self._overall_stat_value(context, "严重漏洞"), "danger"),
                            ("高危漏洞", self._overall_stat_value(context, "高危漏洞"), "danger"),
                            ("中危漏洞", self._overall_stat_value(context, "中危漏洞"), "warning"),
                            ("低危漏洞", self._overall_stat_value(context, "低危漏洞"), ""),
                        ]
                    )
                    + '<div id="vulnLevelChart" class="chart-container"></div>'
                    + '<div id="vulnTypeChart" class="chart-container"></div>',
                )
                + self._render_source_subsection(
                    definitions["2.3"],
                    self._render_source_info_table(
                        self._service_headers(include_asset=context["scope"] != ReportScope.ASSET.value),
                        [self._service_row_values(item, include_asset=context["scope"] != ReportScope.ASSET.value) for item in context["sensitive_services"]],
                    ),
                )
                + self._render_source_subsection(
                    definitions["2.4"],
                    self._render_source_info_table(["中间件", "版本", "归属资产"], context["sensitive_middlewares"]),
                ),
            ),
            self._render_source_section_card(
                definitions["3"],
                self._render_source_info_table(
                    self._service_headers(include_asset=context["scope"] != ReportScope.ASSET.value),
                    [self._service_row_values(item, include_asset=context["scope"] != ReportScope.ASSET.value) for item in context["services"]],
                ),
            ),
            self._render_source_section_card(
                definitions["4"],
                self._render_source_subsection(
                    definitions["4.1"],
                    self._render_source_stats_grid(
                        [
                            ("主机漏洞总数", str(len(context["host_findings"])), "danger" if context["host_findings"] else ""),
                            ("严重/高危", str(sum(1 for item in context["host_findings"] if item.get("severity") in {"critical", "high"})), "danger"),
                            ("主动验证命中", str(sum(1 for item in context["host_findings"] if item.get("verification_status") == "confirmed")), "warning"),
                            ("本地证据项", str(sum(1 for item in context["host_findings"] if item.get("evidence_scope") == "authorized_local")), ""),
                        ]
                    ),
                )
                + self._render_source_subsection(
                    definitions["4.2"],
                    self._render_source_info_table(
                        self._finding_headers(include_asset=context["scope"] != ReportScope.ASSET.value),
                        [self._finding_row_values(item, include_asset=context["scope"] != ReportScope.ASSET.value) for item in context["host_findings"]],
                    ),
                ),
            ),
            self._render_source_section_card(
                definitions["5"],
                self._render_source_subsection(
                    definitions["5.1"],
                    self._render_source_stats_grid(
                        [
                            ("WEB 漏洞总数", str(len(context["web_findings"])), "danger" if context["web_findings"] else ""),
                            ("严重/高危", str(sum(1 for item in context["web_findings"] if item.get("severity") in {"critical", "high"})), "danger"),
                            ("暴露路径类", str(sum(1 for item in context["web_findings"] if "path" in str(item.get("yaml_rule_id") or "").lower())), "warning"),
                            ("脚本验证类", str(sum(1 for item in context["web_findings"] if str(item.get("match_source") or "") in {"active", "active_only"})), ""),
                        ]
                    ),
                )
                + self._render_source_subsection(
                    definitions["5.2"],
                    self._render_source_info_table(
                        self._finding_headers(include_asset=context["scope"] != ReportScope.ASSET.value),
                        [self._finding_row_values(item, include_asset=context["scope"] != ReportScope.ASSET.value) for item in context["web_findings"]],
                    ),
                ),
            ),
            self._render_source_section_card(
                definitions["6"],
                self._render_source_info_table(
                    self._finding_headers(include_asset=context["scope"] != ReportScope.ASSET.value),
                    [self._finding_row_values(item, include_asset=context["scope"] != ReportScope.ASSET.value) for item in context["weak_password_findings"]],
                ),
            ),
            self._render_source_section_card(
                definitions["7"],
                self._render_source_subsection(
                    definitions["7.1"],
                    self._render_source_info_table(["等级", "判定标准"], self._single_finding_standard_rows()),
                )
                + self._render_source_subsection(
                    definitions["7.2"],
                    self._render_source_info_table(["等级", "判定标准"], self._asset_priority_standard_rows()),
                ),
            ),
            self._render_source_section_card(
                definitions["8"],
                self._render_source_bullet_list(self._recommendation_items(context)),
            ),
        ]
        return "".join(sections)

    def _render_source_section_card(self, definition: _SectionDefinition, inner_html: str) -> str:
        return (
            f'<div id="{definition.anchor}" class="section-card">'
            f'<h2 class="section-title">{escape(definition.number)} {escape(definition.title)}</h2>'
            f"{inner_html}"
            "</div>"
        )

    def _render_source_subsection(self, definition: _SectionDefinition, inner_html: str) -> str:
        return f'<h3 id="{definition.anchor}" class="sub-title">{escape(definition.number)} {escape(definition.title)}</h3>{inner_html}'

    def _render_source_stats_grid(self, items: list[tuple[str, str, str]]) -> str:
        cards = "".join(
            f'<div class="data-stat"><div class="label">{escape(label)}</div><div class="value {escape(css_class)}">{escape(value)}</div></div>'
            for label, value, css_class in items
        )
        return f'<div class="data-grid">{cards}</div>'

    def _render_source_info_table(self, headers: list[str], rows: list[list[str]]) -> str:
        if not rows:
            return self._render_source_empty_placeholder()
        thead = "".join(f"<th>{escape(item)}</th>" for item in headers)
        tbody = "".join(
            "<tr>" + "".join(f"<td>{self._html_table_cell(str(cell))}</td>" for cell in row) + "</tr>"
            for row in rows
        )
        return f'<table class="info-table"><thead><tr>{thead}</tr></thead><tbody>{tbody}</tbody></table>'

    def _render_source_bullet_list(self, items: list[str]) -> str:
        if not items:
            return self._render_source_empty_placeholder()
        values = "".join(f"<li>{self._html_paragraph(item)}</li>" for item in items)
        return f'<ul class="bullet-list">{values}</ul>'

    def _render_source_empty_placeholder(self) -> str:
        return '<div class="empty-placeholder"></div>'

    def _overall_stat_value(self, context: dict[str, Any], key: str) -> str:
        for label, value in self._overall_stat_rows(context):
            if label == key:
                return value
        return "0"

    def _render_source_chart_script(self, context: dict[str, Any]) -> str:
        level_counts = self._severity_counts(context["open_findings"])
        level_data = [
            {"value": level_counts["critical"], "name": "严重"},
            {"value": level_counts["high"], "name": "高危"},
            {"value": level_counts["medium"], "name": "中危"},
            {"value": level_counts["low"], "name": "低危"},
        ]
        type_names, type_values = self._finding_type_distribution(context["open_findings"])
        return f"""
        const levelChartEl = document.getElementById('vulnLevelChart');
        if (levelChartEl && window.echarts) {{
            window.vulnLevelChartInstance = echarts.init(levelChartEl);
            window.vulnLevelChartInstance.setOption({{
                tooltip: {{ trigger: 'item' }},
                legend: {{ top: 'bottom' }},
                color: ['#ff4d4f', '#faad14', '#1677ff', '#52c41a'],
                series: [{{
                    name: '漏洞等级',
                    type: 'pie',
                    radius: ['40%', '70%'],
                    avoidLabelOverlap: false,
                    itemStyle: {{ borderRadius: 10, borderColor: '#fff', borderWidth: 2 }},
                    label: {{ show: true, formatter: '{{b}}: {{c}} 个' }},
                    data: {json.dumps(level_data, ensure_ascii=False)}
                }}]
            }});
        }}

        const typeChartEl = document.getElementById('vulnTypeChart');
        if (typeChartEl && window.echarts) {{
            window.vulnTypeChartInstance = echarts.init(typeChartEl);
            window.vulnTypeChartInstance.setOption({{
                tooltip: {{ trigger: 'axis', axisPointer: {{ type: 'shadow' }} }},
                grid: {{ left: '3%', right: '4%', bottom: '3%', containLabel: true }},
                xAxis: {{ type: 'value' }},
                yAxis: {{
                    type: 'category',
                    data: {json.dumps(list(reversed(type_names)), ensure_ascii=False)}
                }},
                series: [{{
                    name: '数量',
                    type: 'bar',
                    data: {json.dumps(list(reversed(type_values)), ensure_ascii=False)},
                    itemStyle: {{ color: '#1677ff', borderRadius: [0, 4, 4, 0] }}
                }}]
            }});
        }}

        window.addEventListener('resize', () => {{
            if (window.vulnLevelChartInstance) {{
                window.vulnLevelChartInstance.resize();
            }}
            if (window.vulnTypeChartInstance) {{
                window.vulnTypeChartInstance.resize();
            }}
        }});
        """

    def _finding_type_distribution(self, findings: list[dict[str, Any]]) -> tuple[list[str], list[int]]:
        counts: dict[str, int] = {}
        for item in findings:
            name = str(item.get("title") or item.get("yaml_rule_id") or "未分类漏洞").strip() or "未分类漏洞"
            counts[name] = counts.get(name, 0) + 1
        ordered = sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))[:5]
        if not ordered:
            ordered = [("未发现漏洞", 0)]
        names = [name for name, _ in ordered]
        values = [value for _, value in ordered]
        return names, values

    def _render_html_section(self, section: _RenderedSection) -> str:
        content = []
        if not section.blocks:
            content.append('<div class="report-empty"></div>')
        else:
            for block in section.blocks:
                kind = block.get("kind")
                if kind == "paragraph":
                    content.append(f'<div class="report-block"><p class="report-paragraph">{self._html_paragraph(block.get("text") or "")}</p></div>')
                elif kind == "kv":
                    rows = block.get("rows", [])
                    if rows:
                        cards = "".join(
                            f'<div class="report-kv-card"><span class="report-kv-label">{escape(str(label))}</span><span class="report-kv-value">{self._html_paragraph(str(value))}</span></div>'
                            for label, value in rows
                        )
                        content.append(f'<div class="report-block"><div class="report-kv-grid">{cards}</div></div>')
                    else:
                        content.append('<div class="report-block"><div class="report-empty"></div></div>')
                elif kind == "table":
                    headers = block.get("headers", [])
                    rows = block.get("rows", [])
                    if rows:
                        thead = "".join(f"<th>{escape(str(item))}</th>" for item in headers)
                        tbody = "".join(
                            "<tr>" + "".join(f"<td>{self._html_table_cell(str(cell))}</td>" for cell in row) + "</tr>"
                            for row in rows
                        )
                        content.append(
                            f'<div class="report-block"><div class="report-table-wrap"><table class="report-table"><thead><tr>{thead}</tr></thead><tbody>{tbody}</tbody></table></div></div>'
                        )
                    else:
                        content.append('<div class="report-block"><div class="report-empty"></div></div>')
                elif kind == "bullets":
                    items = block.get("items", [])
                    if items:
                        bullets = "".join(f"<li>{self._html_paragraph(str(item))}</li>" for item in items)
                        content.append(f'<div class="report-block"><ul class="report-bullets">{bullets}</ul></div>')
                    else:
                        content.append('<div class="report-block"><div class="report-empty"></div></div>')
        return (
            f'<section class="report-section report-section-level-{section.definition.level}" id="{section.definition.anchor}">'
            f'<div class="report-section-header"><span class="report-section-number">{escape(section.definition.number)}</span>'
            f'<h2 class="report-section-title">{escape(section.definition.title)}</h2></div>'
            f'{"".join(content)}</section>'
        )

    def _summary_rows(self, context: dict[str, Any]) -> list[tuple[str, str]]:
        risk_summary = context["risk_summary"]
        risk_priority = context["risk_priority"]
        total_findings = len(context["open_findings"])
        return [
            ("报告编号", context["report_id"]),
            ("检测对象", context["job"].get("cidr") or context["asset"].get("ip") or context["scope_id"]),
            ("资产数量", str(context["asset_count"])),
            ("开放端口/服务数", str(len(context["services"]))),
            ("开放漏洞数", str(total_findings)),
            ("最高风险级别", self._severity_text(risk_summary.get("highest_severity"))),
            ("资产风险等级", str(risk_priority.get("level") or "P5")),
            ("风险评分", str(risk_priority.get("score") or 0)),
        ]

    def _asset_basic_info_rows(self, context: dict[str, Any]) -> list[tuple[str, str]]:
        if context["scope"] == ReportScope.ASSET.value:
            asset = context["asset"]
            return [
                ("资产 ID", str(asset.get("id") or "")),
                ("IP 地址", str(asset.get("ip") or "")),
                ("主机名", str(asset.get("hostname") or "")),
                ("操作系统", str(asset.get("os_name") or "")),
                ("状态", str(asset.get("status") or "")),
                ("MAC / 厂商", " / ".join(part for part in [str(asset.get("mac_address") or ""), str(asset.get("vendor") or "")] if part)),
                ("分区 / VLAN", " / ".join(part for part in [str(asset.get("network_zone") or ""), str(asset.get("network_vlan") or "")] if part)),
                ("楼宇 / 部门", " / ".join(part for part in [str(asset.get("building") or ""), str(asset.get("department") or "")] if part)),
                ("类别 / 角色", " / ".join(part for part in [str(asset.get("asset_category") or ""), str(asset.get("device_role") or "")] if part)),
                ("首次发现", self._format_datetime(asset.get("first_seen_at"))),
                ("最近发现", self._format_datetime(asset.get("last_seen_at"))),
            ]
        job = context["job"]
        return [
            ("任务 ID", str(job.get("id") or "")),
            ("扫描网段", str(job.get("cidr") or "")),
            ("标签", str(job.get("label") or "")),
            ("资产数量", str(context["asset_count"])),
            ("开放服务数", str(len(context["services"]))),
            ("开放漏洞数", str(len(context["open_findings"]))),
            ("最高风险级别", self._severity_text(context["risk_summary"].get("highest_severity"))),
            ("任务风险等级", str(context["risk_priority"].get("level") or "P5")),
        ]

    def _overall_stat_rows(self, context: dict[str, Any]) -> list[tuple[str, str]]:
        counts = self._severity_counts(context["open_findings"])
        return [
            ("严重漏洞", str(counts["critical"])),
            ("高危漏洞", str(counts["high"])),
            ("中危漏洞", str(counts["medium"])),
            ("低危漏洞", str(counts["low"])),
            ("主机漏洞", str(len(context["host_findings"]))),
            ("WEB 漏洞", str(len(context["web_findings"]))),
            ("弱口令", str(len(context["weak_password_findings"]))),
            ("敏感端口/服务", str(len(context["sensitive_services"]))),
            ("敏感中间件", str(len(context["sensitive_middlewares"]))),
        ]

    def _service_headers(self, *, include_asset: bool) -> list[str]:
        headers = ["端口", "协议", "服务", "版本", "状态"]
        if include_asset:
            return ["资产"] + headers
        return headers

    def _service_row_values(self, item: dict[str, Any], *, include_asset: bool) -> list[str]:
        row = [
            str(item.get("port") or ""),
            str(item.get("protocol") or ""),
            str(item.get("service_name") or ""),
            str(item.get("service_version") or ""),
            str(item.get("state") or ""),
        ]
        if include_asset:
            asset_label = " / ".join(part for part in [str(item.get("asset_ip") or ""), str(item.get("asset_hostname") or "")] if part)
            return [asset_label, *row]
        return row

    def _finding_headers(self, *, include_asset: bool) -> list[str]:
        headers = ["风险等级", "漏洞名称", "服务 / 端口", "漏洞说明", "证据摘要"]
        if include_asset:
            return ["资产"] + headers
        return headers

    def _finding_row_values(self, item: dict[str, Any], *, include_asset: bool) -> list[str]:
        service_summary = " / ".join(
            part for part in [str(item.get("service_name") or ""), str(item.get("port") or "")] if part
        )
        row = [
            self._severity_text(item.get("severity")),
            str(item.get("title") or ""),
            service_summary,
            str(item.get("description") or ""),
            self._finding_evidence_summary(item),
        ]
        if include_asset:
            asset_label = " / ".join(part for part in [str(item.get("asset_ip") or ""), str(item.get("asset_hostname") or "")] if part)
            return [asset_label, *row]
        return row

    def _finding_stat_rows(self, findings: list[dict[str, Any]]) -> list[tuple[str, str]]:
        counts = self._severity_counts(findings)
        return [
            ("漏洞总数", str(len(findings))),
            ("严重漏洞", str(counts["critical"])),
            ("高危漏洞", str(counts["high"])),
            ("中危漏洞", str(counts["medium"])),
            ("低危漏洞", str(counts["low"])),
        ]

    def _single_finding_standard_rows(self) -> list[list[str]]:
        return [
            ["严重", "可直接导致系统接管、远程命令执行、大规模数据泄露或关键业务中断，且利用门槛低。"],
            ["高危", "可造成重要权限突破、敏感数据泄露或高影响服务失陷，需要尽快处置。"],
            ["中危", "存在较明确的攻击面或错误配置，会扩大暴露范围或降低防护强度。"],
            ["低危", "影响相对有限，但体现出基线偏差、遗留暴露或局部加固不足。"],
        ]

    def _asset_priority_standard_rows(self) -> list[list[str]]:
        return [
            ["P1", "存在严重漏洞，或综合评分达到 120 以上，应立即处置。"],
            ["P2", "存在高危漏洞，或综合评分达到 40 以上，应优先安排整改。"],
            ["P3", "以中危问题为主，存在一定扩散或叠加风险，应纳入近期计划。"],
            ["P4", "以低危或基线偏差为主，可结合变更窗口统一整改。"],
            ["P5", "当前未识别到开放漏洞，仅建议持续监测与复核。"],
        ]

    def _recommendation_items(self, context: dict[str, Any]) -> list[str]:
        items = []
        for item in context["recommendations"]:
            target = str(item.get("target") or "资产").strip()
            action = str(item.get("action") or "").strip()
            rationale = str(item.get("rationale") or "").strip()
            if action:
                content = f"{target}：{action}"
                if rationale:
                    content = f"{content}。原因：{rationale}"
                items.append(content)
        if items:
            return items
        return [
            "持续复核敏感端口与中间件暴露，确保仅对业务必要范围开放。",
            "优先处理高危与严重漏洞，并在变更窗口内完成验证与回归确认。",
            "对存在认证风险、默认凭据或弱口令的入口执行专项加固和凭据轮换。",
        ]

    def _build_summary_paragraph(self, context: dict[str, Any]) -> str:
        highest_severity = self._severity_text(context["risk_summary"].get("highest_severity"))
        priority = str(context["risk_priority"].get("level") or "P5")
        score = str(context["risk_priority"].get("score") or 0)
        if context["scope"] == ReportScope.ASSET.value:
            target = str(context["asset"].get("ip") or context["scope_id"])
            return (
                f"本报告围绕资产 {target} 生成，当前识别到 {len(context['services'])} 项开放端口/服务、"
                f"{len(context['open_findings'])} 条开放漏洞，最高风险级别为 {highest_severity}，"
                f"综合风险等级为 {priority}（评分 {score}）。"
            )
        target = str(context["job"].get("cidr") or context["scope_id"])
        return (
            f"本报告围绕扫描任务 {target} 生成，当前纳管 {context['asset_count']} 台资产、"
            f"{len(context['services'])} 项开放端口/服务与 {len(context['open_findings'])} 条开放漏洞，"
            f"最高风险级别为 {highest_severity}，综合风险等级为 {priority}（评分 {score}）。"
        )

    def _normalize_service_row(self, item: dict[str, Any], *, asset: dict[str, Any]) -> dict[str, Any]:
        return {
            "asset_id": str(asset.get("id") or ""),
            "asset_ip": str(asset.get("ip") or ""),
            "asset_hostname": str(asset.get("hostname") or ""),
            "port": item.get("port"),
            "protocol": str(item.get("protocol") or ""),
            "service_name": str(item.get("service_name") or ""),
            "service_version": str(item.get("service_version") or ""),
            "state": str(item.get("state") or ""),
            "fingerprint_json": item.get("fingerprint_json") if isinstance(item.get("fingerprint_json"), dict) else {},
        }

    def _normalize_finding_row(self, item: dict[str, Any], *, asset: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": str(item.get("id") or ""),
            "asset_id": str(item.get("asset_id") or asset.get("id") or ""),
            "asset_ip": str(asset.get("ip") or ""),
            "asset_hostname": str(asset.get("hostname") or ""),
            "yaml_rule_id": str(item.get("yaml_rule_id") or ""),
            "severity": str(item.get("severity") or "").lower(),
            "status": str(item.get("status") or "").lower(),
            "title": str(item.get("title") or ""),
            "description": str(item.get("description") or ""),
            "detected_at": item.get("detected_at"),
            "port": item.get("port"),
            "protocol": str(item.get("protocol") or ""),
            "service_name": str(item.get("service_name") or ""),
            "service_version": str(item.get("service_version") or ""),
            "verification_status": str(item.get("verification_status") or ""),
            "match_source": str(item.get("match_source") or ""),
            "evidence_scope": str(item.get("evidence_scope") or ""),
            "evidence_json": item.get("evidence_json") if isinstance(item.get("evidence_json"), dict) else {},
        }

    def _is_sensitive_service(self, item: dict[str, Any]) -> bool:
        port = int(item.get("port") or 0)
        service_name = self._normalized_service_name(item)
        if port in SENSITIVE_PORTS:
            return True
        return any(marker in service_name for marker in SENSITIVE_SERVICE_MARKERS)

    def _build_sensitive_middleware_rows(self, services: list[dict[str, Any]]) -> list[list[str]]:
        dedup: dict[tuple[str, str, str], list[str]] = {}
        for item in services:
            service_name = self._normalized_service_name(item)
            if not service_name or not any(marker in service_name for marker in SENSITIVE_MIDDLEWARE_MARKERS):
                continue
            display_name = str(item.get("service_name") or "").strip() or service_name
            version = str(item.get("service_version") or "").strip()
            asset_label = " / ".join(part for part in [str(item.get("asset_ip") or ""), str(item.get("asset_hostname") or "")] if part)
            key = (display_name.lower(), version, asset_label)
            dedup[key] = [display_name, version, asset_label]
        return [dedup[key] for key in sorted(dedup.keys())]

    def _is_web_finding(self, item: dict[str, Any]) -> bool:
        port = int(item.get("port") or 0)
        service_name = self._normalized_service_name(item)
        text = " ".join(
            [
                str(item.get("yaml_rule_id") or ""),
                str(item.get("title") or ""),
                str(item.get("description") or ""),
                service_name,
                str(item.get("evidence_scope") or ""),
                str(item.get("match_source") or ""),
            ]
        ).lower()
        evidence = item.get("evidence_json") if isinstance(item.get("evidence_json"), dict) else {}
        nse_scripts = evidence.get("nse_scripts") if isinstance(evidence.get("nse_scripts"), list) else []
        if port in WEB_PORTS:
            return True
        if any(marker in service_name for marker in WEB_SERVICE_MARKERS):
            return True
        if any(marker in text for marker in WEB_FINDING_MARKERS):
            return True
        if any(str(script).lower().startswith("http") for script in nse_scripts):
            return True
        for key in ("discovered_paths", "exposed_files", "http_paths"):
            values = evidence.get(key)
            if isinstance(values, list) and values:
                return True
        return False

    def _is_weak_password_finding(self, item: dict[str, Any]) -> bool:
        text = " ".join(
            [
                str(item.get("yaml_rule_id") or ""),
                str(item.get("title") or ""),
                str(item.get("description") or ""),
                str(item.get("service_name") or ""),
            ]
        ).lower()
        return any(marker.lower() in text for marker in WEAK_PASSWORD_MARKERS)

    def _finding_evidence_summary(self, item: dict[str, Any]) -> str:
        evidence = item.get("evidence_json") if isinstance(item.get("evidence_json"), dict) else {}
        parts = []
        if item.get("yaml_rule_id"):
            parts.append(f"规则：{item['yaml_rule_id']}")
        if item.get("verification_status"):
            parts.append(f"验证：{item['verification_status']}")
        if item.get("match_source"):
            parts.append(f"匹配来源：{item['match_source']}")
        if item.get("evidence_scope"):
            parts.append(f"证据范围：{item['evidence_scope']}")
        discovered_paths = evidence.get("discovered_paths")
        if isinstance(discovered_paths, list) and discovered_paths:
            parts.append(f"路径：{', '.join(str(path) for path in discovered_paths[:3])}")
        exposed_files = evidence.get("exposed_files")
        if isinstance(exposed_files, list) and exposed_files:
            parts.append(f"暴露文件：{', '.join(str(path) for path in exposed_files[:3])}")
        nse_scripts = evidence.get("nse_scripts")
        if isinstance(nse_scripts, list) and nse_scripts:
            parts.append(f"NSE：{', '.join(str(item) for item in nse_scripts[:3])}")
        active_detector = evidence.get("active_detector")
        if active_detector:
            parts.append(f"主动探测：{active_detector}")
        if not parts:
            service_version = str(item.get("service_version") or "").strip()
            if service_version:
                parts.append(f"版本：{service_version}")
        return "\n".join(parts)

    def _normalized_service_name(self, item: dict[str, Any]) -> str:
        return str(item.get("service_name") or "").strip().lower()

    def _severity_counts(self, findings: list[dict[str, Any]]) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for item in findings:
            severity = str(item.get("severity") or "").lower()
            if severity in counts:
                counts[severity] += 1
        return counts

    def _sort_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(
            findings,
            key=lambda item: (
                -SEVERITY_ORDER.get(str(item.get("severity") or "").lower(), 0),
                str(item.get("asset_ip") or ""),
                str(item.get("port") or ""),
                str(item.get("title") or ""),
            ),
        )

    def _sort_services(self, services: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(
            services,
            key=lambda item: (
                str(item.get("asset_ip") or ""),
                int(item.get("port") or 0),
                str(item.get("protocol") or ""),
                str(item.get("service_name") or ""),
            ),
        )

    def _build_filename(self, scope: str, scope_id: str, task_id: str | None, suffix: str) -> str:
        normalized_scope = str(scope or "").strip().lower()
        preferred_id = str(scope_id or "").strip()
        if normalized_scope == ReportScope.JOB.value and str(task_id or "").strip():
            preferred_id = str(task_id).strip()
        normalized_id = "".join(char if char.isalnum() or char in {"-", "_", "."} else "-" for char in preferred_id).strip("-") or "report"
        return f"{normalized_id}.{suffix}"

    def _format_datetime(self, value: datetime | str | None) -> str:
        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(value, str) and value.strip():
            normalized = value.strip().replace("Z", "+00:00")
            try:
                return datetime.fromisoformat(normalized).strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                return value.strip()
        return ""

    def _severity_text(self, value: Any) -> str:
        normalized = str(value or "").strip().lower()
        return SEVERITY_LABELS.get(normalized, normalized or "无")

    def _html_paragraph(self, value: str) -> str:
        safe = escape(value)
        for severity, label in SEVERITY_LABELS.items():
            safe = safe.replace(label, f'<span class="report-severity-{severity}">{label}</span>')
        return safe.replace("\n", "<br />")

    def _html_table_cell(self, value: str) -> str:
        return self._html_paragraph(value)

    def _paragraph_to_pdf(self, value: str) -> str:
        return escape(value).replace("\n", "<br/>")

    def _table_or_empty(self, *, headers: list[str], rows: list[list[str]]) -> list[dict[str, Any]]:
        if not rows:
            return []
        return [{"kind": "table", "headers": headers, "rows": rows}]

    def _bullet_or_empty(self, items: list[str]) -> list[dict[str, Any]]:
        if not items:
            return []
        return [{"kind": "bullets", "items": items}]
