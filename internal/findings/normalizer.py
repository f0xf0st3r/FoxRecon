"""Finding normalizer - converts raw tool output to standardized findings."""

from __future__ import annotations

import hashlib
from typing import Any

from internal.database.models import Finding, ScanJob


class FindingNormalizer:
    """Normalizes findings from different tools into a unified format.

    Handles:
    - Deduplication via fingerprinting
    - Severity mapping
    - Standardized classification
    - Evidence extraction
    """

    def normalize_nuclei(
        self,
        raw: dict[str, Any],
        scan_job: ScanJob,
    ) -> Finding:
        """Normalize a nuclei scan result into a Finding."""
        severity = raw.get("severity", "info").lower()
        template_id = raw.get("template_id", "")

        # Map nuclei severity to standard severity
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
        }

        # Extract description
        description = raw.get("description", "")
        if not description:
            description = f"Template {template_id} matched on {raw.get('host', 'unknown')}"

        # Build tags
        tags = raw.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]
        tags.append(raw.get("type", ""))

        # Extract CVEs
        cve_ids = raw.get("cve_ids", [])
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]

        # Build evidence
        evidence_parts = []
        if raw.get("matched_at"):
            evidence_parts.append(f"Matched at: {raw['matched_at']}")
        if raw.get("extracted_results"):
            results = raw["extracted_results"]
            if isinstance(results, list):
                evidence_parts.extend(results[:5])  # Limit evidence size
            else:
                evidence_parts.append(str(results))

        return Finding(
            scan_job_id=scan_job.id,
            target_id=scan_job.target_id,
            finding_type="vulnerability",
            severity=severity_map.get(severity, "info"),
            title=raw.get("template_name", template_id),
            description=description,
            host=raw.get("host"),
            url=raw.get("matched_url") or raw.get("matched_at"),
            evidence="\n".join(evidence_parts) if evidence_parts else None,
            references=raw.get("reference"),
            tags=[t for t in tags if t],
            tool_source="nuclei",
            raw_data=raw,
            cvss_score=raw.get("cvss_score"),
            cve_ids=[c for c in cve_ids if c] if cve_ids else None,
        )

    def fingerprint_finding(self, finding: Finding) -> str:
        """Generate a unique fingerprint for deduplication."""
        parts = [
            finding.finding_type,
            finding.host or "",
            str(finding.port or ""),
            finding.url or "",
            finding.title,
        ]
        raw = "|".join(parts).lower()
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def check_duplicate(
        self,
        finding: Finding,
        existing_findings: list[Finding],
    ) -> Finding | None:
        """Check if a finding is a duplicate of an existing one."""
        fingerprint = self.fingerprint_finding(finding)

        for existing in existing_findings:
            if existing.false_positive or existing.is_duplicate:
                continue
            if self.fingerprint_finding(existing) == fingerprint:
                finding.is_duplicate = True
                finding.duplicate_of = existing.id
                return existing

        return None
