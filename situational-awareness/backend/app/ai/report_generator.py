from __future__ import annotations

from typing import Any


class ReportGenerator:
    def build_asset_report(self, analysis: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], str]:
        overview = analysis["risk_summary"]["severity_counts"]
        markdown = self._asset_markdown(analysis)
        return analysis, overview, markdown

    def build_job_report(self, analysis: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], str]:
        overview = analysis["risk_summary"]["severity_counts"]
        markdown = self._job_markdown(analysis)
        return analysis, overview, markdown

    def _asset_markdown(self, analysis: dict[str, Any]) -> str:
        asset = analysis["asset"]
        risk_summary = analysis["risk_summary"]
        priority = analysis["risk_priority"]
        usage = analysis["usage_hypothesis"]
        recommendations = analysis["recommendations"]
        services = analysis["services"]

        lines = [
            f"# 资产风险报告: {asset['ip']}",
            "",
            "## 风险总结",
            f"- 资产: `{asset['id']}`",
            f"- 主机名: {asset.get('hostname') or 'unknown'}",
            f"- 操作系统: {asset.get('os_name') or 'unknown'}",
            f"- 开放发现数: {risk_summary['open_findings']}",
            f"- 最高风险级别: {risk_summary['highest_severity'] or 'none'}",
            f"- 风险统计: {risk_summary['severity_counts']}",
            "",
            "## 风险优先级",
            f"- 优先级: {priority['level']}",
            f"- 评分: {priority['score']}",
        ]
        lines.extend([f"- 原因: {reason}" for reason in priority["reasons"]])
        lines.extend([
            "",
            "## 修复建议",
        ])
        if recommendations:
            lines.extend([f"- [{item['priority']}] {item['target']}: {item['action']} ({item['rationale']})" for item in recommendations])
        else:
            lines.append("- 当前未发现需要立即处置的开放风险。")

        lines.extend([
            "",
            "## 资产用途推测",
            f"- 推测用途: {usage['purpose']}",
            f"- 置信度: {usage['confidence']}",
        ])
        lines.extend([f"- 证据: {item}" for item in usage["evidence"]])

        lines.extend([
            "",
            "## 暴露服务",
        ])
        if services:
            lines.extend([
                f"- {item['port']}/{item['service_name'] or 'unknown'} {item['service_version'] or ''} [{item['state']}]".rstrip()
                for item in services
            ])
        else:
            lines.append("- 未记录开放服务。")

        return "\n".join(lines)

    def _job_markdown(self, analysis: dict[str, Any]) -> str:
        job = analysis["job"]
        risk_summary = analysis["risk_summary"]
        priority = analysis["risk_priority"]
        recommendations = analysis["recommendations"]
        top_assets = risk_summary["top_assets"]

        lines = [
            f"# 任务风险报告: {job['id']}",
            "",
            "## 风险总结",
            f"- 网段: `{job['cidr']}`",
            f"- 标签: {job.get('label') or 'none'}",
            f"- 资产数量: {job['asset_count']}",
            f"- 开放风险数: {risk_summary['total_findings']}",
            f"- 最高风险级别: {risk_summary['highest_severity'] or 'none'}",
            f"- 风险统计: {risk_summary['severity_counts']}",
            "",
            "## 风险优先级",
            f"- 优先级: {priority['level']}",
            f"- 评分: {priority['score']}",
        ]
        lines.extend([f"- 原因: {reason}" for reason in priority["reasons"]])
        lines.extend([
            "",
            "## 修复建议",
        ])
        if recommendations:
            lines.extend([f"- [{item['priority']}] {item['target']}: {item['action']} ({item['rationale']})" for item in recommendations])
        else:
            lines.append("- 当前未发现需要立即处置的开放风险。")

        lines.extend([
            "",
            "## 重点资产",
        ])
        if top_assets:
            lines.extend([
                f"- {item['ip']} ({item.get('hostname') or 'unknown'}): {item['priority']} / score={item['score']} / highest={item['highest_severity'] or 'none'} / open={item['open_findings']}"
                for item in top_assets
            ])
        else:
            lines.append("- 当前任务未关联到资产风险数据。")

        return "\n".join(lines)
