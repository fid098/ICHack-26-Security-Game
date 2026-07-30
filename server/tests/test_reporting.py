from __future__ import annotations

import pytest

from app.integrations.reporting import (
    VULNERABILITY_METADATA,
    build_findings,
    summarize_findings,
)


class TestBuildFindings:
    def test_safe_tasks_are_excluded(self, make_frontend_task):
        tasks = [
            make_frontend_task("t1", is_vulnerable=False, vulnerability_type="SAFE"),
            make_frontend_task("t2", is_vulnerable=True, vulnerability_type="XSS"),
        ]

        findings = build_findings(tasks)

        assert [f.taskId for f in findings] == ["t2"]

    def test_empty_input_produces_no_findings(self):
        assert build_findings([]) == []

    @pytest.mark.parametrize(
        "vuln_type,severity",
        [
            ("XSS", "HIGH"),
            ("SQL_INJECTION", "CRITICAL"),
            ("RCE", "CRITICAL"),
            ("SSRF", "HIGH"),
            ("PATH_TRAVERSAL", "HIGH"),
            ("COMMAND_INJECTION", "CRITICAL"),
            ("INSECURE_DESERIALIZATION", "HIGH"),
        ],
    )
    def test_severity_comes_from_metadata(self, make_frontend_task, vuln_type, severity):
        findings = build_findings(
            [make_frontend_task("t1", is_vulnerable=True, vulnerability_type=vuln_type)]
        )

        assert findings[0].severity == severity

    def test_finding_carries_remediation_and_snippet(self, make_frontend_task):
        task = make_frontend_task("t1", vulnerability_type="SQL_INJECTION", code="SELECT " + "x")

        finding = build_findings([task])[0]

        assert finding.remediation == VULNERABILITY_METADATA["SQL_INJECTION"]["remediation"]
        assert finding.codeSnippet == task.code

    def test_missing_line_number_defaults_to_line_one(self, make_frontend_task):
        task = make_frontend_task("t1", vulnerability_line=None)

        assert build_findings([task])[0].codeLocation == {"line": 1, "column": 1}

    def test_line_number_is_preserved_when_present(self, make_frontend_task):
        task = make_frontend_task("t1", vulnerability_line=42)

        assert build_findings([task])[0].codeLocation == {"line": 42, "column": 1}

    def test_every_metadata_entry_has_the_required_keys(self):
        for vuln_type, metadata in VULNERABILITY_METADATA.items():
            assert set(metadata) == {"severity", "description", "remediation"}, vuln_type
            assert metadata["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


class TestSummarizeFindings:
    def test_no_findings_reports_a_clean_scan(self):
        assert "No vulnerabilities detected" in summarize_findings([])

    def test_single_finding_uses_singular_wording(self, make_frontend_task):
        findings = build_findings([make_frontend_task("t1", vulnerability_type="XSS")])

        summary = summarize_findings(findings)

        assert "1 vulnerability." in summary
        assert "vulnerabilities" not in summary

    def test_multiple_findings_use_plural_wording(self, make_frontend_task):
        findings = build_findings(
            [
                make_frontend_task("t1", vulnerability_type="XSS"),
                make_frontend_task("t2", vulnerability_type="SSRF"),
            ]
        )

        assert "2 vulnerabilities." in summarize_findings(findings)

    def test_critical_and_high_counts_are_reported_separately(self, make_frontend_task):
        findings = build_findings(
            [
                make_frontend_task("t1", vulnerability_type="SQL_INJECTION"),
                make_frontend_task("t2", vulnerability_type="RCE"),
                make_frontend_task("t3", vulnerability_type="XSS"),
            ]
        )

        summary = summarize_findings(findings)

        assert "2 CRITICAL issues" in summary
        assert "1 HIGH severity issue" in summary

    def test_singular_critical_agrees_in_number(self, make_frontend_task):
        findings = build_findings([make_frontend_task("t1", vulnerability_type="RCE")])

        assert "1 CRITICAL issue requires immediate attention." in summarize_findings(findings)

    def test_plural_critical_agrees_in_number(self, make_frontend_task):
        findings = build_findings(
            [
                make_frontend_task("t1", vulnerability_type="RCE"),
                make_frontend_task("t2", vulnerability_type="SQL_INJECTION"),
            ]
        )

        assert "2 CRITICAL issues require immediate attention." in summarize_findings(findings)
