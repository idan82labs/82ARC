"""Aegis CLI main entry point.

Provides command-line interface for security testing operations.
"""

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from aegis import __version__
from aegis.core import (
    AegisEngine,
    SQLiteRepository,
    AuthService,
    RedactionService,
    AuditLogger,
    SecurePath,
    RunStatus,
    Severity,
)
from aegis.core.exceptions import (
    AegisError,
    AuthenticationError,
    AuthorizationError,
    ScopeNotFoundError,
)

app = typer.Typer(
    name="aegis",
    help="AI Security Testing Platform for Red & Purple Teams",
    no_args_is_help=True,
)
console = Console()

# Subcommand groups
scope_app = typer.Typer(help="Manage security testing scopes")
run_app = typer.Typer(help="Manage test runs")
pack_app = typer.Typer(help="Manage test packs")
principal_app = typer.Typer(help="Manage principals and authentication")

app.add_typer(scope_app, name="scope")
app.add_typer(run_app, name="run")
app.add_typer(pack_app, name="pack")
app.add_typer(principal_app, name="principal")


def get_engine(db_path: str = "aegis.db", api_key: Optional[str] = None) -> AegisEngine:
    """Initialize the Aegis engine with authentication.

    Args:
        db_path: Path to SQLite database
        api_key: API key for authentication (reads from AEGIS_API_KEY env if not provided)

    Returns:
        Configured AegisEngine instance
    """
    import os

    api_key = api_key or os.environ.get("AEGIS_API_KEY")
    if not api_key:
        console.print("[red]Error:[/red] No API key provided. Set AEGIS_API_KEY or use --api-key")
        raise typer.Exit(1)

    try:
        repository = SQLiteRepository(db_path)
        auth_service = AuthService(repository)
        redaction = RedactionService()
        audit_logger = AuditLogger(repository)

        principal = auth_service.authenticate_api_key(api_key)

        return AegisEngine(
            repository=repository,
            auth_service=auth_service,
            redaction_service=redaction,
            audit_logger=audit_logger,
            principal=principal,
        )
    except AuthenticationError as e:
        console.print(f"[red]Authentication failed:[/red] {e}")
        raise typer.Exit(1)


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", "-v", help="Show version"),
):
    """Aegis - AI Security Testing Platform."""
    if version:
        console.print(f"Aegis v{__version__}")
        raise typer.Exit(0)


# ============================================================================
# Scope Commands
# ============================================================================


@scope_app.command("create")
def scope_create(
    name: str = typer.Argument(..., help="Scope name"),
    targets: str = typer.Option(..., "--targets", "-t", help="Comma-separated target patterns"),
    description: str = typer.Option("", "--description", "-d", help="Scope description"),
    db_path: str = typer.Option("aegis.db", "--db", help="Database path"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="API key"),
):
    """Create a new security testing scope."""
    engine = get_engine(db_path, api_key)

    target_list = [t.strip() for t in targets.split(",")]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task("Creating scope...", total=None)

        try:
            scope = engine.create_scope(
                name=name,
                description=description,
                target_patterns=target_list,
            )
            console.print(Panel(
                f"[green]Scope created successfully[/green]\n\n"
                f"ID: {scope.id}\n"
                f"Name: {scope.name}\n"
                f"Targets: {', '.join(target_list)}\n"
                f"Status: Pending Approval",
                title="Scope Created",
            ))
        except AegisError as e:
            console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(1)


@scope_app.command("list")
def scope_list(
    db_path: str = typer.Option("aegis.db", "--db", help="Database path"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="API key"),
):
    """List all scopes."""
    engine = get_engine(db_path, api_key)

    scopes = engine.list_scopes()

    if not scopes:
        console.print("[yellow]No scopes found[/yellow]")
        return

    table = Table(title="Security Testing Scopes")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="green")
    table.add_column("Targets")
    table.add_column("Approved", style="yellow")
    table.add_column("Expires")

    for scope in scopes:
        target_str = ", ".join(p.pattern for p in scope.targets[:3])
        if len(scope.targets) > 3:
            target_str += f" (+{len(scope.targets) - 3} more)"

        approved = "Yes" if scope.is_approved() else "No"
        expires = scope.time_window.end.strftime("%Y-%m-%d") if scope.time_window else "Never"

        table.add_row(scope.id[:8], scope.name, target_str, approved, expires)

    console.print(table)


@scope_app.command("show")
def scope_show(
    scope_id: str = typer.Argument(..., help="Scope ID"),
    db_path: str = typer.Option("aegis.db", "--db", help="Database path"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="API key"),
):
    """Show scope details."""
    engine = get_engine(db_path, api_key)

    try:
        scope = engine.get_scope(scope_id)

        console.print(Panel(
            f"[cyan]ID:[/cyan] {scope.id}\n"
            f"[cyan]Name:[/cyan] {scope.name}\n"
            f"[cyan]Description:[/cyan] {scope.description or 'N/A'}\n"
            f"[cyan]Created:[/cyan] {scope.created_at}\n"
            f"[cyan]Approved:[/cyan] {'Yes' if scope.is_approved() else 'No'}\n"
            f"[cyan]Approvals:[/cyan] {len(scope.approvals)}/{scope.required_approvals}\n"
            f"\n[cyan]Targets:[/cyan]\n" +
            "\n".join(f"  - {t.pattern}" for t in scope.targets),
            title=f"Scope: {scope.name}",
        ))
    except ScopeNotFoundError:
        console.print(f"[red]Error:[/red] Scope not found: {scope_id}")
        raise typer.Exit(1)


# ============================================================================
# Run Commands
# ============================================================================


@run_app.command("start")
def run_start(
    scope_id: str = typer.Argument(..., help="Scope ID to run tests against"),
    pack: str = typer.Option(..., "--pack", "-p", help="Test pack to execute"),
    db_path: str = typer.Option("aegis.db", "--db", help="Database path"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="API key"),
):
    """Start a new test run."""
    engine = get_engine(db_path, api_key)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Starting test run...", total=None)

        try:
            run = engine.start_run(scope_id=scope_id, pack_name=pack)

            progress.update(task, description="Run started successfully")

            console.print(Panel(
                f"[green]Test run started[/green]\n\n"
                f"Run ID: {run.id}\n"
                f"Pack: {pack}\n"
                f"Scope: {scope_id[:8]}...\n"
                f"Status: {run.status.value}",
                title="Run Started",
            ))
        except AegisError as e:
            console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(1)


@run_app.command("status")
def run_status(
    run_id: str = typer.Argument(..., help="Run ID"),
    db_path: str = typer.Option("aegis.db", "--db", help="Database path"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="API key"),
):
    """Check status of a test run."""
    engine = get_engine(db_path, api_key)

    try:
        run = engine.get_run(run_id)

        status_color = {
            RunStatus.PENDING: "yellow",
            RunStatus.RUNNING: "blue",
            RunStatus.COMPLETED: "green",
            RunStatus.FAILED: "red",
            RunStatus.ABORTED: "magenta",
        }.get(run.status, "white")

        console.print(Panel(
            f"[cyan]Run ID:[/cyan] {run.id}\n"
            f"[cyan]Status:[/cyan] [{status_color}]{run.status.value}[/{status_color}]\n"
            f"[cyan]Pack:[/cyan] {run.pack_name}\n"
            f"[cyan]Started:[/cyan] {run.started_at}\n"
            f"[cyan]Completed:[/cyan] {run.completed_at or 'In progress'}\n"
            f"[cyan]Tests:[/cyan] {run.tests_completed}/{run.tests_total}",
            title=f"Run Status",
        ))
    except AegisError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@run_app.command("list")
def run_list(
    scope_id: Optional[str] = typer.Option(None, "--scope", "-s", help="Filter by scope"),
    status: Optional[str] = typer.Option(None, "--status", help="Filter by status"),
    limit: int = typer.Option(20, "--limit", "-n", help="Max results"),
    db_path: str = typer.Option("aegis.db", "--db", help="Database path"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="API key"),
):
    """List test runs."""
    engine = get_engine(db_path, api_key)

    runs = engine.list_runs(scope_id=scope_id, limit=limit)

    if status:
        runs = [r for r in runs if r.status.value == status]

    if not runs:
        console.print("[yellow]No runs found[/yellow]")
        return

    table = Table(title="Test Runs")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Pack", style="green")
    table.add_column("Status")
    table.add_column("Progress")
    table.add_column("Started")

    for run in runs:
        status_color = {
            RunStatus.PENDING: "yellow",
            RunStatus.RUNNING: "blue",
            RunStatus.COMPLETED: "green",
            RunStatus.FAILED: "red",
            RunStatus.ABORTED: "magenta",
        }.get(run.status, "white")

        progress = f"{run.tests_completed}/{run.tests_total}" if run.tests_total else "0/0"
        started = run.started_at.strftime("%Y-%m-%d %H:%M") if run.started_at else "N/A"

        table.add_row(
            run.id[:8],
            run.pack_name,
            f"[{status_color}]{run.status.value}[/{status_color}]",
            progress,
            started,
        )

    console.print(table)


@run_app.command("abort")
def run_abort(
    run_id: str = typer.Argument(..., help="Run ID to abort"),
    reason: str = typer.Option("Manual abort", "--reason", "-r", help="Abort reason"),
    db_path: str = typer.Option("aegis.db", "--db", help="Database path"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="API key"),
):
    """Abort a running test."""
    engine = get_engine(db_path, api_key)

    try:
        engine.abort_run(run_id, reason=reason)
        console.print(f"[green]Run {run_id[:8]} aborted successfully[/green]")
    except AegisError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


@run_app.command("results")
def run_results(
    run_id: str = typer.Argument(..., help="Run ID"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file (JSON)"),
    db_path: str = typer.Option("aegis.db", "--db", help="Database path"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="API key"),
):
    """View test results for a run."""
    engine = get_engine(db_path, api_key)

    try:
        results = engine.get_run_results(run_id)

        if output:
            # Export to JSON
            data = [r.to_dict() for r in results]
            Path(output).write_text(json.dumps(data, indent=2, default=str))
            console.print(f"[green]Results exported to {output}[/green]")
            return

        if not results:
            console.print("[yellow]No results yet[/yellow]")
            return

        # Summary by severity
        severity_counts = {}
        for result in results:
            sev = result.severity.value if result.severity else "info"
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        console.print(Panel(
            f"[cyan]Total Results:[/cyan] {len(results)}\n"
            f"[red]Critical:[/red] {severity_counts.get('critical', 0)}\n"
            f"[yellow]High:[/yellow] {severity_counts.get('high', 0)}\n"
            f"[blue]Medium:[/blue] {severity_counts.get('medium', 0)}\n"
            f"[green]Low:[/green] {severity_counts.get('low', 0)}\n"
            f"[white]Info:[/white] {severity_counts.get('info', 0)}",
            title="Results Summary",
        ))

        # Detailed table
        table = Table(title="Test Results")
        table.add_column("Test", style="cyan")
        table.add_column("Status")
        table.add_column("Severity")
        table.add_column("Message")

        for result in results[:20]:  # Limit display
            sev_color = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "yellow",
                Severity.MEDIUM: "blue",
                Severity.LOW: "green",
                Severity.INFO: "white",
            }.get(result.severity, "white")

            status = "[green]PASS[/green]" if result.passed else "[red]FAIL[/red]"
            sev = f"[{sev_color}]{result.severity.value if result.severity else 'N/A'}[/{sev_color}]"

            table.add_row(
                result.test_id[:20],
                status,
                sev,
                (result.message or "")[:50],
            )

        console.print(table)

        if len(results) > 20:
            console.print(f"[yellow]...and {len(results) - 20} more results[/yellow]")

    except AegisError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


# ============================================================================
# Pack Commands
# ============================================================================


@pack_app.command("list")
def pack_list(
    packs_dir: str = typer.Option("packs", "--dir", "-d", help="Packs directory"),
):
    """List available test packs."""
    from aegis.core.pack_loader import SecurePackLoader

    packs_path = Path(packs_dir)
    if not packs_path.exists():
        console.print(f"[yellow]Packs directory not found: {packs_dir}[/yellow]")
        return

    loader = SecurePackLoader(packs_path)
    packs = loader.list_packs()

    if not packs:
        console.print("[yellow]No packs found[/yellow]")
        return

    table = Table(title="Available Test Packs")
    table.add_column("Name", style="cyan")
    table.add_column("Version", style="green")
    table.add_column("Description")
    table.add_column("Tests")

    for pack in packs:
        table.add_row(
            pack.name,
            pack.version,
            pack.description[:50] if pack.description else "N/A",
            str(len(pack.test_suites)),
        )

    console.print(table)


@pack_app.command("info")
def pack_info(
    pack_name: str = typer.Argument(..., help="Pack name"),
    packs_dir: str = typer.Option("packs", "--dir", "-d", help="Packs directory"),
):
    """Show pack details."""
    from aegis.core.pack_loader import SecurePackLoader

    loader = SecurePackLoader(Path(packs_dir))

    try:
        pack = loader.load_pack(pack_name)

        console.print(Panel(
            f"[cyan]Name:[/cyan] {pack.name}\n"
            f"[cyan]Version:[/cyan] {pack.version}\n"
            f"[cyan]Description:[/cyan] {pack.description or 'N/A'}\n"
            f"[cyan]Author:[/cyan] {pack.author or 'N/A'}\n"
            f"\n[cyan]Test Suites:[/cyan]\n" +
            "\n".join(f"  - {ts.name} ({len(ts.test_cases)} tests)" for ts in pack.test_suites),
            title=f"Pack: {pack.name}",
        ))
    except Exception as e:
        console.print(f"[red]Error loading pack:[/red] {e}")
        raise typer.Exit(1)


# ============================================================================
# Principal Commands
# ============================================================================


@principal_app.command("create")
def principal_create(
    name: str = typer.Argument(..., help="Principal name"),
    role: str = typer.Option("operator", "--role", "-r", help="Role (admin/operator/auditor)"),
    db_path: str = typer.Option("aegis.db", "--db", help="Database path"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="Admin API key"),
):
    """Create a new principal (requires admin)."""
    engine = get_engine(db_path, api_key)

    if role not in ["admin", "operator", "auditor"]:
        console.print(f"[red]Error:[/red] Invalid role: {role}")
        raise typer.Exit(1)

    try:
        principal, new_api_key = engine.create_principal(name=name, role=role)

        console.print(Panel(
            f"[green]Principal created successfully[/green]\n\n"
            f"ID: {principal.id}\n"
            f"Name: {principal.name}\n"
            f"Role: {role}\n\n"
            f"[yellow]API Key (save this, it won't be shown again):[/yellow]\n"
            f"[cyan]{new_api_key}[/cyan]",
            title="Principal Created",
        ))
    except AuthorizationError as e:
        console.print(f"[red]Authorization Error:[/red] {e}")
        raise typer.Exit(1)


@principal_app.command("list")
def principal_list(
    db_path: str = typer.Option("aegis.db", "--db", help="Database path"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="API key"),
):
    """List principals."""
    engine = get_engine(db_path, api_key)

    principals = engine.list_principals()

    if not principals:
        console.print("[yellow]No principals found[/yellow]")
        return

    table = Table(title="Principals")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="green")
    table.add_column("Roles")
    table.add_column("Status")
    table.add_column("Last Active")

    for p in principals:
        status = "[red]Revoked[/red]" if p.is_revoked else "[green]Active[/green]"
        last_active = p.last_active.strftime("%Y-%m-%d %H:%M") if p.last_active else "Never"

        table.add_row(
            p.id[:8],
            p.name,
            ", ".join(p.roles),
            status,
            last_active,
        )

    console.print(table)


@principal_app.command("init")
def principal_init(
    db_path: str = typer.Option("aegis.db", "--db", help="Database path"),
):
    """Initialize database with first admin user."""
    repository = SQLiteRepository(db_path)

    # Check if any principals exist
    principals = repository.get_all_principals()
    if principals:
        console.print("[yellow]Database already initialized with principals[/yellow]")
        raise typer.Exit(1)

    # Create first admin
    import secrets
    from datetime import datetime
    from aegis.core.models import Principal

    admin = Principal(
        id=secrets.token_hex(16),
        name="admin",
        roles=["admin"],
        api_key_hash="",  # Will be set below
        created_at=datetime.utcnow(),
    )

    # Generate API key
    api_key = f"aegis_{secrets.token_urlsafe(32)}"
    admin.api_key_hash = AuthService.hash_api_key(api_key)

    repository.save_principal(admin)

    console.print(Panel(
        f"[green]Database initialized successfully[/green]\n\n"
        f"Admin Principal Created:\n"
        f"ID: {admin.id}\n"
        f"Name: admin\n\n"
        f"[yellow]API Key (save this, it won't be shown again):[/yellow]\n"
        f"[cyan]{api_key}[/cyan]",
        title="Initialization Complete",
    ))


if __name__ == "__main__":
    app()
