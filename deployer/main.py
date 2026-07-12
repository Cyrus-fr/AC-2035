"""AC-2035 Honeytoken Deployer — CLI entrypoint.

    python deployer/main.py deploy --pod <name> --namespace <ns> --types gcp_key,api_token
    python deployer/main.py rotate --all
    python deployer/main.py status
    python deployer/main.py serve       # run the auto-rotation scheduler in the foreground
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Allow `python deployer/main.py ...` to import the `deployer` package: this
# file's own directory (deployer/) is what Python puts on sys.path for a
# direct script invocation, not the repo root, so `from deployer import ...`
# would otherwise fail.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import typer
from dotenv import load_dotenv
from loguru import logger
from rich.console import Console
from rich.table import Table

from deployer import generator, injector, registry, rotator

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

app = typer.Typer(help="AC-2035 Honeytoken Deployer")
console = Console()


@app.command()
def deploy(
    pod: str = typer.Option(..., "--pod", help="Target pod name"),
    namespace: str = typer.Option(..., "--namespace", help="Target namespace"),
    types: str = typer.Option(
        ...,
        "--types",
        help="Comma-separated token types: gcp_key,gcp_api_key,db_connection,api_token",
    ),
) -> None:
    """Generate honeytokens and inject them into a pod + Secret Manager."""
    project_id = os.getenv("GCP_PROJECT_ID", "")
    token_types = [t.strip() for t in types.split(",") if t.strip()]

    deployed = 0
    for token_type in token_types:
        try:
            token = generator.generate(token_type, target_pod=pod, target_namespace=namespace)
        except ValueError as e:
            logger.warning(str(e))
            continue

        injector.inject_pod_env(pod, namespace, token)
        secret_path = injector.inject_secret_manager(token, project_id)

        token_dict = token.to_dict()
        token_dict["secret_manager_path"] = secret_path
        registry.register(token_dict)
        deployed += 1

    typer.echo(f"Deployed {deployed} tokens to {pod}/{namespace}")


@app.command()
def rotate(
    all_: bool = typer.Option(False, "--all", help="Rotate all active tokens"),
) -> None:
    """Rotate honeytokens."""
    if not all_:
        typer.echo("Nothing to do — pass --all to rotate all active tokens.")
        raise typer.Exit(code=0)

    count = rotator.rotate_all()
    typer.echo(f"{count} tokens rotated")


@app.command()
def status() -> None:
    """Show the honeytoken registry as a table."""
    tokens = registry.get_all()

    table = Table(title="AC-2035 Honeytoken Registry")
    for col in ("token_id", "type", "pod", "namespace", "status", "injected_at", "last_rotated_at"):
        table.add_column(col)

    for t in tokens:
        table.add_row(
            t["token_id"][:8],
            t["token_type"],
            t.get("target_pod") or "-",
            t.get("target_namespace") or "-",
            t["status"],
            t.get("injected_at") or "-",
            t.get("last_rotated_at") or "-",
        )

    console.print(table)


@app.command()
def serve() -> None:
    """Run the auto-rotation scheduler in the foreground (blocking)."""
    scheduler = rotator.build_scheduler()
    try:
        scheduler.start()
    except KeyboardInterrupt:
        logger.info("Rotation scheduler stopped")


if __name__ == "__main__":
    app()
