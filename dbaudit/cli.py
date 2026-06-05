# ===
# the entry point for the entire tool
# pyproject.toml maps 'dbaudit' command to app here
# WHAT IS THIS FILE?
# When we type `dbaudit scan ...` in wer terminal, Python runs THIS file.
# pyproject.toml has this line:
#     dbaudit = "dbaudit.cli:app"
# That means: "find the object called 'app' inside dbaudit/cli.py and run it"
# ===

import typer
from typing import Optional
from rich.console import Console
# from rich.table import Table
from dbaudit.connector import get_engine, test_connection
from dbaudit.reporter import print_results, save_json, save_html
# from dbaudit.models import Severity
from dbaudit.checks.users import check_superusers, check_users_without_password, check_user_count
from dbaudit.checks.permissions import check_public_schema_access, check_excessive_privileges
from dbaudit.checks.config import check_ssl_enabled, check_connection_limit, check_logging_enabled
from dbaudit.checks.columns import check_sensitive_columns, check_sensitive_column_count

# ---
# Typer creates CLI apps the same way Flask/FastAPI create web apps.
# We create an "app" object, then attach commands to it using decorators.
# add_completion = False just disables shell tab-completion for now (keeps it simple).
# ---

# no_args_is_help=True shows help if user types just 'dbaudit' with nothing else
app = typer.Typer(
    name = "dbaudit",
    help = "A database auditing and vulnerability scanner for PostgreSQL and MySQL.",
    add_completion = False,
    no_args_is_help = True,
)

# Rich's Console is a smarter version of print().
# It understands markup like [bold], [red], [cyan] — similar to HTML tags.

console = Console()

# now handled by reporter.py
# # maps severity level to a rich color for terminal output
# SEVERITY_COLOR = {
#     Severity.INFO: "dim",
#     Severity.LOW: "blue",
#     Severity.MEDIUM: "yellow",
#     Severity.HIGH: "red",
#     Severity.CRITICAL: "bold red",
# }

# required — tells Typer this app has subcommands, not just one root command
@app.callback()
def main():
    """DBAudit CLI"""
    pass

# ---
# @app.command() is a "decorator" — it registers the function below it as a
# CLI subcommand. So `scan` becomes `dbaudit scan`.
#
# the function PARAMETERS automatically become CLI options.
# typer reads the type hints (str, int, bool) to know what to expect.
# typer.Option(...) means the flag is REQUIRED — '...' is Python's way of
# saying "no default value".
# ---

@app.command("scan")
def scan(
    host: str = typer.Option(..., help = "DB host, e.g. localhost"),
    port: int = typer.Option(None, help = "Port (default: 5432 PG, 3306 MySQL)"),
    db: str = typer.Option(..., help = "Database name to scan"),
    user: str = typer.Option(..., help = "Username"),
    # prompt = True: Typer asks interactively. hide_input = True: hides typed chars.
    password: str = typer.Option(..., prompt = True, hide_input = True, help = "Password"),
    db_type: str = typer.Option("postgres", help = "'postgres' or 'mysql'"),

    # optional output file — if given, saves a report in that format
    # e.g. --output report.json  or  --output report.html
    output: Optional[str] = typer.Option(None, help="Save report to file (.json or .html)"),
):
    # scan a database for security misconfigurations and vulnerabilities.

    console.print(f"\n[bold cyan]dbaudit[/bold cyan] — starting scan")
    console.print(f"  Target : [bold]{db}[/bold] on {host}:{port or 'default port'}")
    console.print(f"  Engine : {db_type}")
    console.print(f"  User   : {user}\n")

    # test the connection before running any checks
    console.print("[dim]Connecting to database...[/dim]")
    try:
        engine = get_engine(db_type, host, port, db, user, password)
        test_connection(engine)
        console.print("[bold green]✔ Connected successfully[/bold green]\n")
    except Exception as e:
        # show the error in red and exit — no point running checks if we can't connect
        console.print(f"[bold red]✘ Connection failed:[/bold red] {e}")
        raise typer.Exit(code = 1)  # exit code 1 = error (standard CLI convention)

    # run all checks - add new checks to this list
    console.print("[dim]Running checks...[/dim]\n")
    checks = [
        check_superusers,
        check_users_without_password,
        check_user_count,
        check_public_schema_access,
        check_excessive_privileges,
        check_ssl_enabled,
        check_connection_limit,
        check_logging_enabled,
        check_sensitive_columns,
        check_sensitive_column_count, 
    ]

    findings = []
    for check_fn in checks:
        try:
            finding = check_fn(engine, db_type)
            findings.append(finding)
        except Exception as e:
            # if one check crashes, log it n continue - dont abort the whole scan
            console.print(f"[red]Error in {check_fn.__name__}: {e}[/red]")

    # always print to terminal
    print_results(findings, db, db_type)

    # optionally save to file
    if output:
        if output.endswith(".json"):
            save_json(findings, db, db_type, output)
        elif output.endswith(".html"):
            save_html(findings, db, db_type, output)
        else:
            console.print("[red]Unknown output format — use .json or .html[/red]")

    # # build results table using Rich
    # table = Table(title = "Scan Results", show_lines = True)
    # table.add_column("Status", width = 6)
    # table.add_column("Severity", width = 10)
    # table.add_column("Check", width = 40)
    # table.add_column("Details")

    # for f in findings:
    #     status = "[green]PASS[/green]" if f.passed else "[red]FAIL[/red]"
    #     color = SEVERITY_COLOR[f.severity]
    #     table.add_row(status, f"[{color}]{f.severity.value}[/{color}]", f.title, f.description)

    # console.print(table)

    # # summary line
    # failed = [f for f in findings if not f.passed]
    # console.print(f"\n[bold]{'✔ All checks passed' if not failed else f'✘ {len(failed)} issue(s) found'}[/bold]")

# ---
# this block only runs if we execute the file directly with:
#     python dbaudit/cli.py
# it does NOT run when we use the `dbaudit` command (which goes through Typer)
# its a useful fallback for quick testing
# ---

if __name__ == "__main__":
    app()
