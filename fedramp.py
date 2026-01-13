def fedramp_mapping(scan_result: dict) -> dict:
    status = scan_result.get("status")

    return {
        "SI-3": {
            "name": "Malicious Code Protection",
            "supported": True,
            "evidence": "ClamAV on-demand malware scan",
            "result": status
        },
        "AU-2": {
            "name": "Audit Events",
            "supported": True,
            "evidence": "Scan event recorded with target and result"
        },
        "AU-12": {
            "name": "Audit Record Generation",
            "supported": True,
            "evidence": "Timestamped scan output and hash (if file)"
        },
        "SC-7": {
            "name": "Boundary Protection",
            "supported": "Partial",
            "evidence": "Local execution only; no network scanning"
        }
    }
