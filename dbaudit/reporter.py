# handles all output formatting: terminal, JSON, HTML

import json
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from dbaudit.models import Finding, Severity

console = Console()

# severity -> rich color
SEVERITY_COLOR = {
    Severity.INFO: "dim",
    Severity.LOW: "blue",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}

def print_results(findings: list[Finding], db: str, db_type: str) -> None:
    # print the full results table to the terminal

    table = Table(title = f"Scan Results — {db} ({db_type})", show_lines = True)
    table.add_column("Status", width=6)
    table.add_column("Severity", width=10)
    table.add_column("Check", width=40)
    table.add_column("Details")

    for f in findings:
        status = "[green]PASS[/green]" if f.passed else "[red]FAIL[/red]"
        color = SEVERITY_COLOR[f.severity]
        table.add_row(
            status,
            f"[{color}]{ f.severity.value }[/{color}]",
            f.title,
            f.description,
        )

    console.print(table)
    _print_summary(findings)

def _print_summary(findings: list[Finding]) -> None:
    # print a severity breakdown summary below the table
    failed = [f for f in findings if not f.passed]

    if not failed:
        console.print("\n[bold green]✔ All checks passed[/bold green]")
        return

    # count failures by severity
    counts: dict[str, int] = {}
    for f in failed:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    console.print(f"\n[bold]✘ {len(failed)} issue(s) found:[/bold]")
    # print in order from most to least severe
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if level in counts:
            color = SEVERITY_COLOR[Severity[level]]
            console.print(f"  [{color}]{level}[/{color}]  { counts[level] }")

def save_json(findings: list[Finding], db: str, db_type: str, output_path: str) -> None:
    # save findings as a JSON file
    data = {
        "meta": {
            "database": db,
            "db_type": db_type,
            "scanned_at": datetime.now().isoformat(),
        },
        "summary": {
            "total": len(findings),
            "passed": sum(1 for f in findings if f.passed),
            "failed": sum(1 for f in findings if not f.passed),
        },
        # convert each finding dataclass to a plain dict
        "findings": [
            {
                "passed": f.passed,
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
            }
            for f in findings
        ],
    }

    path = Path(output_path)
    path.write_text(json.dumps(data, indent = 2), encoding="utf-8")
    console.print(f"\n[green]✔ JSON report saved to {path.resolve()}[/green]")

def save_html(findings: list[Finding], db: str, db_type: str, output_path: str) -> None:
    # save findings as a standalone HTML report

    scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    failed = [f for f in findings if not f.passed]

    # build the table rows as an HTML string
    rows_html = ""
    for f in findings:
        status_class = "pass" if f.passed else "fail"
        status_text = "PASS" if f.passed else "FAIL"
        sev = f.severity.value
        rows_html += f"""
        <tr>
            <td class = "{ status_class }">{ status_text }</td>
            <td class = "sev-{ sev.lower() }">{sev}</td>
            <td>{ f.title }</td>
            <td>{ f.description }</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
                <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <title>dbaudit — {db}</title>
                        <style>
                            body {{ font-family: 'Segoe UI', sans-serif; background: #0f1117; color: #e0e0e0; padding: 2rem; }}
                            h1 {{ color: #00d4ff; }} h2 {{ color: #aaa; font-weight: normal; }}
                            .meta {{ color: #888; margin-bottom: 1.5rem; font-size: 0.9rem; }}
                            table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
                            th {{ background: #1e2230; color: #00d4ff; padding: 10px; text-align: left; }}
                            td {{ padding: 10px; border-bottom: 1px solid #2a2d3e; vertical-align: top; }}
                            tr:hover td {{ background: #1a1d2e; }}
                            .pass {{ color: #4caf50; font-weight: bold; }}
                            .fail {{ color: #f44336; font-weight: bold; }}
                            .sev-critical {{ color: #ff1744; font-weight: bold; }}
                            .sev-high {{ color: #f44336; }}
                            .sev-medium {{ color: #ff9800; }}
                            .sev-low {{ color: #64b5f6; }}
                            .sev-info {{ color: #888; }}
                            .summary {{ margin-top: 1.5rem; padding: 1rem; background: #1e2230; border-radius: 6px; }}
                        </style>
                    </head>
                    <body>
                        <h1>🔍 dbaudit — Scan Report</h1>
                        <h2>{db} ({db_type})</h2>
                        <div class="meta">Scanned at: { scanned_at }</div>
                        <div class="summary">
                            <strong>Total checks:</strong> {len(findings)} &nbsp;|&nbsp;
                            <strong style="color:#4caf50">Passed:</strong> {len(findings) - len(failed)} &nbsp;|&nbsp;
                            <strong style="color:#f44336">Failed:</strong> {len(failed)}
                        </div>
                        <table>
                            <thead><tr><th>Status</th><th>Severity</th><th>Check</th><th>Details</th></tr></thead>
                            <tbody>{ rows_html }</tbody>
                        </table>
                    </body>
                </html>
            """
    
    path = Path(output_path)
    path.write_text(html, encoding = "utf-8")
    console.print(f"\n[green]✔ HTML report saved to { path.resolve() }[/green]")