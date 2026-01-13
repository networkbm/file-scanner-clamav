import argparse
import json
import sys
import time
import threading
from datetime import datetime, timezone

from audit import write_audit_event
from clamav import scan_path
from fedramp import fedramp_mapping

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich import box


console = Console()


def render_banner() -> Panel:
    title = Text()
    title.append("THE FILE SCANNER", style="bold red")
    title.append(" x ", style="bold white")
    title.append("CLAMAV", style="bold red")

    subtitle = Text("made by networkbm", style="bold white")

    body = Text()
    body.append(title)
    body.append("\n")
    body.append(subtitle)

    return Panel(
        body,
        border_style="red",
        box=box.HEAVY,
        padding=(1, 2),
    )


def scanning_view(path: str, dots: str) -> Panel:
    line = Text()
    line.append("Scanning: ", style="bold white")
    line.append(path, style="bold cyan")
    line.append("  ", style="white")
    line.append(dots, style="bold red")

    return Panel(
        line,
        border_style="red",
        box=box.HEAVY,
        padding=(1, 2),
    )


def main():
    parser = argparse.ArgumentParser(description="Local file scanner using ClamAV")
    parser.add_argument("path", help="File or directory path to scan")
    parser.add_argument("--json", dest="json_path", help="Write results to a JSON file (e.g., report.json)")
    args = parser.parse_args()

    console.print(render_banner())

    result_holder = {"result": None}

    def do_scan():
        result_holder["result"] = scan_path(args.path)

    t = threading.Thread(target=do_scan, daemon=True)
    t.start()

    frames = ["●··", "·●·", "··●", "·●·"]
    i = 0

    with Live(scanning_view(args.path, frames[i]), console=console, refresh_per_second=12, transient=True) as live:
        while t.is_alive():
            i = (i + 1) % len(frames)
            live.update(scanning_view(args.path, frames[i]))
            time.sleep(0.15)

    t.join()
    result = result_holder["result"]

    if not result or result.get("status") == "ERROR":
        console.print("\n[bold red]Scan Result[/bold red]")
        console.print("[red]Status:[/red] ERROR")
        console.print(f"[red]Message:[/red] {result.get('message') if result else 'Unknown error'}")
        sys.exit(2)

    fedramp = fedramp_mapping(result)

    clamav = result.get("clamav", {})
    viruses_detected = result.get("viruses_detected", 0)

    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "tool": {
            "name": "filescanner",
            "engine": "clamav"
        },
        "result": result,
        "fedramp_mapping": fedramp
    }

    write_audit_event({
        "event_type": "file_scan",
        "target": result.get("path"),
        "target_type": result.get("type"),
        "status": result.get("status"),
        "viruses_detected": viruses_detected,
        "sha256": result.get("sha256")
    })

    console.print("\n[bold white]Scan Result[/bold white]")
    console.print("[white]-----------[/white]")
    console.print(f"[bold white]Target:[/bold white] [cyan]{result.get('path')}[/cyan]")
    console.print(f"[bold white]Type:[/bold white] {result.get('type')}")

    if result.get("sha256"):
        console.print(f"[bold white]SHA256:[/bold white] {result.get('sha256')}")

    status = result.get("status")
    status_style = "bold green" if status == "CLEAN" else "bold red"
    console.print(f"[bold white]Viruses detected:[/bold white] {viruses_detected}")
    console.print(f"[bold white]Status:[/bold white] [{status_style}]{status}[/{status_style}]\n")

    if result.get("type") == "directory":
        infected = [r for r in clamav.get("file_results", []) if r.get("status") == "INFECTED"]
        if infected:
            console.print("[bold red]Detections[/bold red]")
            console.print("[red]----------[/red]")
            for item in infected:
                sig = item.get("signature") or "UNKNOWN"
                console.print(f"[red]{item.get('path')}[/red] -> [bold red]{sig}[/bold red]")
            console.print()

        summary = clamav.get("summary", {})
        if summary:
            console.print("[bold white]ClamAV Summary[/bold white]")
            console.print("[white]-------------[/white]")
            keys = ["Known viruses", "Engine version", "Scanned directories", "Scanned files", "Infected files", "Data scanned", "Data read", "Time", "Start Date", "End Date"]
            for k in keys:
                if k in summary:
                    console.print(f"[bold white]{k}:[/bold white] {summary[k]}")
            console.print()
    else:
        lines = clamav.get("lines", [])
        if lines:
            for line in lines:
                console.print(line)

    console.print("[bold white]FedRAMP Control Mapping[/bold white]")
    console.print("[white]----------------------[/white]")
    for control, details in fedramp.items():
        supported = details.get("supported")
        supported_str = str(supported)
        sup_style = "bold green" if supported is True else ("bold yellow" if supported == "Partial" else "bold red")
        console.print(f"[bold white]{control}[/bold white] ({details['name']}): [{sup_style}]{supported_str}[/{sup_style}]")
        console.print(f"  [bold white]Evidence:[/bold white] {details['evidence']}")

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        console.print(f"\n[bold green]JSON report written to:[/bold green] {args.json_path}")

    if status == "INFECTED" and int(viruses_detected) > 0:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
