import subprocess
import hashlib
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_clamscan_output(stdout: str) -> dict:
    lines_all = stdout.splitlines()
    summary_marker = "----------- SCAN SUMMARY -----------"

    if summary_marker in lines_all:
        idx = lines_all.index(summary_marker)
        file_lines = lines_all[:idx]
        summary_lines = lines_all[idx + 1 :]
    else:
        file_lines = lines_all
        summary_lines = []

    file_results = []
    for line in file_lines:
        if not line.strip():
            continue
        if ": " not in line:
            continue
        p, rest = line.split(": ", 1)
        rest = rest.strip()
        if rest == "OK":
            file_results.append({
                "path": p,
                "status": "CLEAN",
                "signature": None
            })
        elif rest.endswith(" FOUND"):
            signature = rest[:-6].strip()
            file_results.append({
                "path": p,
                "status": "INFECTED",
                "signature": signature
            })

    summary = {}
    for line in summary_lines:
        if ":" in line:
            k, v = line.split(":", 1)
            summary[k.strip()] = v.strip()

    infected_count = sum(1 for r in file_results if r["status"] == "INFECTED")

    return {
        "file_results": file_results,
        "infected_count": infected_count,
        "summary": summary,
        "raw_output": stdout.strip(),
        "lines": lines_all
    }


def scan_path(path: str) -> dict:
    target = Path(path)

    if not target.exists():
        return {
            "status": "ERROR",
            "message": f"Path does not exist: {path}"
        }

    file_hash = None
    if target.is_file():
        file_hash = sha256_file(target)

    command = ["clamscan"]

    if target.is_dir():
        command.append("-r")

    command.append(str(target))

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    parsed = _parse_clamscan_output(result.stdout)

    if target.is_dir():
        overall_status = "INFECTED" if parsed["infected_count"] > 0 else "CLEAN"
        viruses_detected = parsed["infected_count"]
    else:
        overall_status = "INFECTED" if "FOUND" in result.stdout else "CLEAN"
        viruses_detected = 1 if overall_status == "INFECTED" else 0

    return {
        "path": str(target),
        "type": "directory" if target.is_dir() else "file",
        "sha256": file_hash,
        "status": overall_status,
        "viruses_detected": viruses_detected,
        "clamav": {
            "raw_output": parsed["raw_output"],
            "lines": parsed["lines"],
            "summary": parsed["summary"],
            "file_results": parsed["file_results"],
            "infected_count": parsed["infected_count"]
        }
    }
