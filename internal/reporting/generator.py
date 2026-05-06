"""Report generator - creates markdown, JSON, and PDF reports."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from internal.config import get_settings
from internal.database.models import (
    Report,
    ScanJob,
    Finding,
    Target,
    Subdomain,
    LiveHost,
    Port,
    Vulnerability,
)
from internal.utils.logging import get_logger

logger = get_logger(module="reporting")


class ReportGenerator:
    """Generates reconnaissance reports in multiple formats."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.settings = get_settings()

    async def generate(self, report: Report) -> tuple[str, str]:
        """Generate report content and save to disk.

        Returns:
            Tuple of (content_string, file_path)
        """
        scan_jobs = await self._get_scan_jobs(report)
        findings = await self._get_findings(report)
        vulnerabilities = await self._get_vulnerabilities(report)
        targets = await self._get_targets(report)
        subdomains = await self._get_subdomains(report)
        live_hosts = await self._get_live_hosts(report)
        ports = await self._get_ports(report)

        if report.format == "json":
            content = self._generate_json(
                report, findings, vulnerabilities, targets,
                subdomains, live_hosts, ports, scan_jobs,
            )
            ext = "json"
        else:
            content = self._generate_markdown(
                report, findings, vulnerabilities, targets,
                subdomains, live_hosts, ports, scan_jobs,
            )
            ext = "md"

        filename = f"report_{report.id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.{ext}"
        file_path = str(Path(self.settings.reports_dir) / filename)
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        Path(file_path).write_text(content, encoding="utf-8")

        logger.info(
            "report_generated",
            report_id=str(report.id),
            format=report.format,
            file_path=file_path,
        )

        return content, file_path

    def _generate_markdown(
        self,
        report: Report,
        findings: list,
        vulnerabilities: list,
        targets: list,
        subdomains: list,
        live_hosts: list,
        ports: list,
        scan_jobs: list,
    ) -> str:
        """Generate a markdown report."""
        lines = []

        lines.append("# FoxRecon Reconnaissance Report\n")
        lines.append(f"**Report:** {report.title}")
        lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
        lines.append(f"**Format:** {report.format}\n")

        # Executive Summary
        lines.append("## Executive Summary\n")
        severity_counts = {}
        for f in findings:
            sev = f.severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines.append("| Metric | Count |")
        lines.append("|--------|-------|")
        lines.append(f"| Targets | {len(targets)} |")
        lines.append(f"| Subdomains | {len(subdomains)} |")
        lines.append(f"| Live Hosts | {len(live_hosts)} |")
        lines.append(f"| Open Ports | {len(ports)} |")
        lines.append(f"| Total Findings | {len(findings)} |")
        lines.append(f"| Critical | {severity_counts.get('critical', 0)} |")
        lines.append(f"| High | {severity_counts.get('high', 0)} |")
        lines.append(f"| Medium | {severity_counts.get('medium', 0)} |")
        lines.append(f"| Low | {severity_counts.get('low', 0)} |")
        lines.append(f"| Info | {severity_counts.get('info', 0)} |")
        lines.append("")

        # Targets
        lines.append("## Targets\n")
        for t in targets:
            lines.append(f"- **{t.name}** (`{t.value}`) - {t.target_type}")
        lines.append("")

        # Subdomains
        if subdomains:
            lines.append("## Discovered Subdomains\n")
            lines.append(f"Total: {len(subdomains)}\n")
            lines.append("| Domain | Source | Resolved IP |")
            lines.append("|--------|--------|-------------|")
            for s in subdomains[:100]:
                lines.append(f"| {s.domain} | {s.source or 'N/A'} | {s.resolved_ip or 'N/A'} |")
            if len(subdomains) > 100:
                lines.append(f"\n*... and {len(subdomains) - 100} more*")
            lines.append("")

        # Live Hosts
        if live_hosts:
            lines.append("## Live Hosts\n")
            lines.append(f"Total: {len(live_hosts)}\n")
            lines.append("| URL | Status | Title | Tech |")
            lines.append("|-----|--------|-------|------|")
            for h in live_hosts[:50]:
                tech = ", ".join(h.tech_stack[:3]) if h.tech_stack else "N/A"
                title = (h.title or "")[:50]
                lines.append(
                    f"| {h.url} | {h.status_code or 'N/A'} | {title} | {tech} |"
                )
            lines.append("")

        # Open Ports
        if ports:
            lines.append("## Open Ports\n")
            lines.append(f"Total: {len(ports)}\n")
            lines.append("| Host | Port | Protocol | Service | Version |")
            lines.append("|------|------|----------|---------|---------|")
            for p in ports[:100]:
                lines.append(
                    f"| {p.host} | {p.port_number} | {p.protocol} | "
                    f"{p.service_name or 'N/A'} | {p.service_version or 'N/A'} |"
                )
            lines.append("")

        # Critical & High Findings
        critical_high = [f for f in findings if f.severity in ("critical", "high")]
        if critical_high:
            lines.append("## Critical & High Findings\n")
            lines.append(f"**{len(critical_high)} findings requiring immediate attention**\n")
            for f in critical_high:
                lines.append(f"### [{f.severity.upper()}] {f.title}\n")
                lines.append(f"- **Host:** {f.host or 'N/A'}")
                lines.append(f"- **URL:** {f.url or 'N/A'}")
                lines.append(f"- **Source:** {f.tool_source or 'N/A'}")
                if f.description:
                    lines.append(f"- **Description:** {f.description}")
                if f.evidence:
                    lines.append(f"- **Evidence:**\n```{f.evidence}```")
                if f.cve_ids:
                    lines.append(f"- **CVEs:** {', '.join(f.cve_ids)}")
                lines.append("")

        # All Vulnerabilities
        if vulnerabilities:
            lines.append("## Vulnerability Details\n")
            lines.append(f"Total: {len(vulnerabilities)}\n")
            for v in vulnerabilities[:50]:
                lines.append(f"### [{v.severity.upper()}] {v.template_name}\n")
                lines.append(f"- **Template:** {v.template_id}")
                lines.append(f"- **Host:** {v.host}")
                if v.matched_url:
                    lines.append(f"- **Matched:** {v.matched_url}")
                if v.cve_ids:
                    lines.append(f"- **CVEs:** {', '.join(v.cve_ids)}")
                if v.cwe_ids:
                    lines.append(f"- **CWEs:** {', '.join(v.cwe_ids)}")
                lines.append("")

        # All findings
        other_findings = [f for f in findings if f.severity not in ("critical", "high")]
        if other_findings:
            lines.append("## Additional Findings\n")
            lines.append("| Severity | Title | Host | Source |")
            lines.append("|----------|-------|------|--------|")
            for f in other_findings[:100]:
                lines.append(
                    f"| {f.severity} | {f.title} | {f.host or 'N/A'} | {f.tool_source or 'N/A'} |"
                )
            lines.append("")

        # Scan History
        if scan_jobs:
            lines.append("## Scan History\n")
            lines.append("| Scan Type | Status | Duration | Subdomains | Hosts | Ports | Findings |")
            lines.append("|-----------|--------|----------|------------|-------|-------|----------|")
            for sj in scan_jobs:
                duration = ""
                if sj.started_at and sj.completed_at:
                    diff = sj.completed_at - sj.started_at
                    duration = f"{diff.total_seconds():.0f}s"
                lines.append(
                    f"| {sj.scan_type} | {sj.status} | {duration} | "
                    f"{sj.subdomains_found} | {sj.live_hosts_found} | "
                    f"{sj.ports_found} | {sj.findings_count} |"
                )
            lines.append("")

        lines.append("---")
        lines.append(f"*Generated by FoxRecon v1.0.0*")

        return "\n".join(lines)

    def _generate_json(
        self,
        report: Report,
        findings: list,
        vulnerabilities: list,
        targets: list,
        subdomains: list,
        live_hosts: list,
        ports: list,
        scan_jobs: list,
    ) -> str:
        """Generate a JSON report."""
        data = {
            "report": {
                "title": report.title,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "format": report.format,
                "report_type": report.report_type,
            },
            "summary": {
                "targets": len(targets),
                "subdomains": len(subdomains),
                "live_hosts": len(live_hosts),
                "open_ports": len(ports),
                "findings": len(findings),
                "vulnerabilities": len(vulnerabilities),
            },
            "targets": [
                {
                    "name": t.name,
                    "value": t.value,
                    "type": t.target_type,
                    "scope": t.scope,
                }
                for t in targets
            ],
            "subdomains": [
                {
                    "domain": s.domain,
                    "source": s.source,
                    "resolved_ip": s.resolved_ip,
                }
                for s in subdomains
            ],
            "live_hosts": [
                {
                    "url": h.url,
                    "host": h.hostname,
                    "ip": h.ip,
                    "status_code": h.status_code,
                    "title": h.title,
                    "tech": h.tech_stack,
                }
                for h in live_hosts
            ],
            "ports": [
                {
                    "host": p.host,
                    "port": p.port_number,
                    "protocol": p.protocol,
                    "service": p.service_name,
                    "version": p.service_version,
                }
                for p in ports
            ],
            "findings": [
                {
                    "severity": f.severity,
                    "type": f.finding_type,
                    "title": f.title,
                    "host": f.host,
                    "url": f.url,
                    "description": f.description,
                    "evidence": f.evidence,
                    "cve_ids": f.cve_ids,
                    "tool": f.tool_source,
                }
                for f in findings
            ],
            "vulnerabilities": [
                {
                    "template_id": v.template_id,
                    "template_name": v.template_name,
                    "severity": v.severity,
                    "host": v.host,
                    "matched_url": v.matched_url,
                    "cve_ids": v.cve_ids,
                    "cwe_ids": v.cwe_ids,
                }
                for v in vulnerabilities
            ],
            "scan_history": [
                {
                    "type": sj.scan_type,
                    "status": sj.status,
                    "started_at": sj.started_at.isoformat() if sj.started_at else None,
                    "completed_at": sj.completed_at.isoformat() if sj.completed_at else None,
                    "subdomains": sj.subdomains_found,
                    "live_hosts": sj.live_hosts_found,
                    "ports": sj.ports_found,
                    "findings": sj.findings_count,
                }
                for sj in scan_jobs
            ],
        }

        return json.dumps(data, indent=2, default=str)

    async def _get_scan_jobs(self, report: Report) -> list:
        if report.scan_job_ids:
            ids = [uuid.UUID(jid) for jid in report.scan_job_ids]
            result = await self.db.execute(
                select(ScanJob).where(ScanJob.id.in_(ids))
            )
            return result.scalars().all()
        if report.target_id:
            result = await self.db.execute(
                select(ScanJob)
                .where(ScanJob.target_id == report.target_id, ScanJob.status == "completed")
                .order_by(ScanJob.created_at.desc())
                .limit(10)
            )
            return result.scalars().all()
        return []

    async def _get_findings(self, report: Report) -> list:
        q = select(Finding).where(Finding.is_duplicate == False)
        if report.target_id:
            q = q.where(Finding.target_id == report.target_id)
        if report.scan_job_ids:
            ids = [uuid.UUID(jid) for jid in report.scan_job_ids]
            q = q.where(Finding.scan_job_id.in_(ids))
        q = q.order_by(
            func.case(
                (Finding.severity == "critical", 0),
                (Finding.severity == "high", 1),
                (Finding.severity == "medium", 2),
                (Finding.severity == "low", 3),
                else_=4,
            )
        )
        result = await self.db.execute(q)
        return result.scalars().all()

    async def _get_vulnerabilities(self, report: Report) -> list:
        q = select(Vulnerability)
        if report.target_id:
            q = q.where(Vulnerability.target_id == report.target_id)
        q = q.order_by(
            func.case(
                (Vulnerability.severity == "critical", 0),
                (Vulnerability.severity == "high", 1),
                else_=2,
            )
        ).limit(200)
        result = await self.db.execute(q)
        return result.scalars().all()

    async def _get_targets(self, report: Report) -> list:
        if report.target_id:
            result = await self.db.execute(
                select(Target).where(Target.id == report.target_id)
            )
            t = result.scalar_one_or_none()
            return [t] if t else []
        return []

    async def _get_subdomains(self, report: Report) -> list:
        q = select(Subdomain).order_by(Subdomain.domain).limit(5000)
        if report.target_id:
            q = q.where(Subdomain.target_id == report.target_id)
        result = await self.db.execute(q)
        return result.scalars().all()

    async def _get_live_hosts(self, report: Report) -> list:
        q = select(LiveHost).where(LiveHost.status_code.isnot(None)).limit(1000)
        if report.target_id:
            q = q.where(LiveHost.target_id == report.target_id)
        result = await self.db.execute(q)
        return result.scalars().all()

    async def _get_ports(self, report: Report) -> list:
        q = select(Port).where(Port.state == "open").limit(2000)
        if report.target_id:
            q = q.where(Port.target_id == report.target_id)
        result = await self.db.execute(q)
        return result.scalars().all()
