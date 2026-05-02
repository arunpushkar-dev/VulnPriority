#!/usr/bin/env python3
"""
app.py — FastAPI web UI for the Vulnerability Prioritization pipeline.

Start:  python app.py   (or start.bat on Windows)
Opens:  http://localhost:8000
"""

import asyncio
import csv
import io
import json
import os
import queue
import subprocess
import sys
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

load_dotenv()

app = FastAPI(title="PatchPilot AI API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── In-memory job store ────────────────────────────────────────────────────────
# jobs[job_id] = {
#   "status": "running"|"complete"|"failed",
#   "phases": [{id, name, status, log, started_at, ended_at}],
#   "cve_count": int,
#   "report_path": str|None,
#   "results": [...] | None,
#   "event_queue": queue.Queue,
# }
jobs: dict[str, dict] = {}

PYTHON = sys.executable

PHASES = [
    ("validate",  "Validate CVEs",            "Parsing and deduplicating CVE identifiers"),
    ("nvd",       "NVD Data",                 "Fetching CVSS scores and CWE from NIST NVD"),
    ("osv",       "OSV.dev Lookup",           "Retrieving package-level vulnerability ranges"),
    ("kev",       "CISA KEV Catalog",         "Checking Known Exploited Vulnerabilities list"),
    ("epss",      "EPSS Scores",              "Pulling exploitation probability from FIRST.org"),
    ("exploitdb", "ExploitDB",                "Scanning for public exploits and PoC code"),
    ("attack",    "MITRE ATT&CK",             "Mapping techniques via CWE-to-ATT&CK"),
    ("merge",     "Merge Enrichment",         "Combining all intelligence into unified records"),
    ("score",     "Calculate Scores",         "Applying composite prioritization formula"),
    ("recommend", "Recommendations",          "Generating CISO remediation guidance"),
    ("report",    "Generate Report",          "Rendering final HTML report"),
]


def _phase_idx(phase_id: str, phases: list) -> int:
    for i, p in enumerate(phases):
        if p["id"] == phase_id:
            return i
    return -1


def _emit(job: dict, event: str, data: dict):
    job["event_queue"].put({"event": event, "data": data})


def _run_cmd(cmd: list[str], job: dict, phase_id: str, cwd: str) -> tuple[bool, str]:
    idx = _phase_idx(phase_id, job["phases"])
    if idx >= 0:
        job["phases"][idx]["status"] = "running"
        job["phases"][idx]["started_at"] = datetime.utcnow().isoformat()
    _emit(job, "phase_start", {"phase": phase_id})

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            cwd=cwd, timeout=600,
            encoding="utf-8", errors="replace"
        )
        output = (result.stdout or "") + (result.stderr or "")
        success = result.returncode == 0
    except subprocess.TimeoutExpired:
        output = "Timed out after 600s"
        success = False
    except Exception as e:
        output = str(e)
        success = False

    if idx >= 0:
        job["phases"][idx]["status"] = "done" if success else "error"
        job["phases"][idx]["log"] = output.strip()
        job["phases"][idx]["ended_at"] = datetime.utcnow().isoformat()

    _emit(job, "phase_done", {
        "phase": phase_id,
        "success": success,
        "log": output.strip()[-2000:],
    })
    return success, output


def run_pipeline(job_id: str, cve_list: list[str], skip_exploitdb: bool,
                 skip_attack: bool, title: str, cwd: str):
    job = jobs[job_id]

    def emit(event, data):
        _emit(job, event, data)

    emit("status", {"message": f"Starting pipeline for {len(cve_list)} CVE(s)"})

    # Each job gets its own isolated subdirectory — prevents cross-job contamination
    shared_tmp = Path(cwd) / ".tmp"
    shared_tmp.mkdir(parents=True, exist_ok=True)
    tmp = shared_tmp / job_id
    tmp.mkdir(parents=True, exist_ok=True)

    cve_file = tmp / "input.txt"
    cve_file.write_text("\n".join(cve_list), encoding="utf-8")

    for d in ["nvd_raw", "epss_raw", "osv_raw", "exploitdb_raw",
              "attack_raw", "enriched", "scored", "recommendations"]:
        (tmp / d).mkdir(parents=True, exist_ok=True)

    # KEV cache is shared across jobs (large download, valid 24h)
    kev_cache = shared_tmp / "kev_cache.json"

    nvd_key = os.getenv("NVD_API_KEY", "")
    nvd_delay = "0.65" if nvd_key else "6.0"
    tools = str(Path(cwd) / "tools")

    # Phase 1 – Validate
    ok, _ = _run_cmd([PYTHON, f"{tools}/validate_cves.py",
                      "--input", str(cve_file),
                      "--output", str(tmp / "validated_cves.json")],
                     job, "validate", cwd)
    if not ok:
        job["status"] = "failed"
        emit("failed", {"reason": "CVE validation failed — no valid CVEs found"})
        return

    # Count valid CVEs
    try:
        validated = json.loads((tmp / "validated_cves.json").read_text(encoding="utf-8"))
        job["cve_count"] = validated.get("total_valid", len(cve_list))
        emit("cve_count", {"count": job["cve_count"]})
    except Exception:
        pass

    # Phase 2a – NVD
    nvd_cmd = [PYTHON, f"{tools}/fetch_nvd.py",
               "--batch", str(tmp / "validated_cves.json"),
               "--output-dir", str(tmp / "nvd_raw"),
               "--delay", nvd_delay]
    if nvd_key:
        nvd_cmd += ["--api-key", nvd_key]
    _run_cmd(nvd_cmd, job, "nvd", cwd)

    # Phase 2b – OSV
    _run_cmd([PYTHON, f"{tools}/fetch_osv.py",
              "--batch", str(tmp / "validated_cves.json"),
              "--output-dir", str(tmp / "osv_raw")],
             job, "osv", cwd)

    # Phase 3a – KEV (shared cache, per-job results)
    _run_cmd([PYTHON, f"{tools}/fetch_kev.py",
              "--refresh", "--output", str(kev_cache)],
             job, "kev", cwd)
    _run_cmd([PYTHON, f"{tools}/fetch_kev.py",
              "--batch", str(tmp / "validated_cves.json"),
              "--cache", str(kev_cache),
              "--output", str(tmp / "kev_results.json")],
             job, "kev", cwd)

    # Phase 3b – EPSS
    _run_cmd([PYTHON, f"{tools}/fetch_epss.py",
              "--batch", str(tmp / "validated_cves.json"),
              "--output-dir", str(tmp / "epss_raw")],
             job, "epss", cwd)

    # Phase 3c – ExploitDB (skippable)
    if not skip_exploitdb:
        _run_cmd([PYTHON, f"{tools}/fetch_exploitdb.py",
                  "--batch", str(tmp / "validated_cves.json"),
                  "--output-dir", str(tmp / "exploitdb_raw"),
                  "--delay", "2.0"],
                 job, "exploitdb", cwd)
    else:
        idx = _phase_idx("exploitdb", job["phases"])
        if idx >= 0:
            job["phases"][idx]["status"] = "skipped"
        _emit(job, "phase_done", {"phase": "exploitdb", "success": True, "log": "Skipped"})

    # Phase 4a – ATT&CK (skippable)
    if not skip_attack:
        _run_cmd([PYTHON, f"{tools}/fetch_attack.py",
                  "--batch", str(tmp / "validated_cves.json"),
                  "--nvd-dir", str(tmp / "nvd_raw"),
                  "--output-dir", str(tmp / "attack_raw")],
                 job, "attack", cwd)
    else:
        idx = _phase_idx("attack", job["phases"])
        if idx >= 0:
            job["phases"][idx]["status"] = "skipped"
        _emit(job, "phase_done", {"phase": "attack", "success": True, "log": "Skipped"})

    # Phase 4b – Merge
    merge_cmd = [PYTHON, f"{tools}/merge_enrichment.py",
                 "--cves", str(tmp / "validated_cves.json"),
                 "--nvd-dir", str(tmp / "nvd_raw"),
                 "--osv-dir", str(tmp / "osv_raw"),
                 "--kev", str(tmp / "kev_results.json"),
                 "--epss-dir", str(tmp / "epss_raw"),
                 "--exploitdb-dir", str(tmp / "exploitdb_raw"),
                 "--output-dir", str(tmp / "enriched")]
    if not skip_attack:
        merge_cmd += ["--attack-dir", str(tmp / "attack_raw")]
    _run_cmd(merge_cmd, job, "merge", cwd)

    # Phase 5 – Score
    ok, _ = _run_cmd([PYTHON, f"{tools}/calculate_score.py",
                      "--enriched-dir", str(tmp / "enriched"),
                      "--output-dir", str(tmp / "scored")],
                     job, "score", cwd)
    if not ok:
        job["status"] = "failed"
        emit("failed", {"reason": "Scoring failed"})
        return

    # Phase 6 – Recommendations
    _run_cmd([PYTHON, f"{tools}/generate_recommendations.py",
              "--scored-dir", str(tmp / "scored"),
              "--output-dir", str(tmp / "recommendations")],
             job, "recommend", cwd)

    # Phase 7 – Report
    reports_dir = Path(cwd) / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / f"vuln_report_{job_id}.html"

    ok, _ = _run_cmd([PYTHON, f"{tools}/generate_report.py",
                      "--scored-dir", str(tmp / "scored"),
                      "--recommendations-dir", str(tmp / "recommendations"),
                      "--output", str(report_path),
                      "--title", title],
                     job, "report", cwd)

    # Load results JSON for the UI
    results = _load_results(tmp / "scored", tmp / "recommendations")
    job["results"] = results
    job["report_path"] = str(report_path) if ok else None

    job["status"] = "complete"
    emit("complete", {
        "report_available": ok,
        "cve_count": job["cve_count"],
        "stats": _calc_stats(results),
    })


def _load_results(scored_dir: Path, recs_dir: Path) -> list[dict]:
    results = []
    for f in sorted(scored_dir.glob("CVE-*.json")):
        try:
            scored = json.loads(f.read_text(encoding="utf-8"))
            rec_path = recs_dir / f.name
            rec = json.loads(rec_path.read_text(encoding="utf-8")) if rec_path.exists() else {}
            enriched = scored.get("enriched", {})
            nvd = enriched.get("nvd") or {}
            epss_data = enriched.get("epss") or {}
            kev_data = enriched.get("kev") or {}
            exploit_data = enriched.get("exploit") or {}
            attack_data = enriched.get("attack") or {}
            threat_ctx = enriched.get("threat_context") or {}
            osv_data = enriched.get("osv") or {}
            # Patch links: from merged record, or fall back to per-source fields
            patch_links = enriched.get("patch_links") or []
            if not patch_links:
                patch_links = list(dict.fromkeys(
                    nvd.get("patch_refs", []) + osv_data.get("fix_refs", [])
                ))
            fixed_versions = enriched.get("fixed_versions") or osv_data.get("fixed_versions", [])
            cvss_v31 = nvd.get("cvss_v31") or {}
            cvss_v40 = nvd.get("cvss_v40") or {}
            # Primary CVSS for scoring: prefer v4.0, fall back to v3.1
            cvss_primary = cvss_v40 or cvss_v31
            results.append({
                # Core identity
                "cve_id": scored["cve_id"],
                "composite_score": scored.get("composite_score"),
                "priority_category": scored.get("priority_category", "Unscored"),
                "patch_timeline": scored.get("patch_timeline", "N/A"),
                "score_reasoning": scored.get("score_reasoning", ""),
                "data_flags": scored.get("data_flags", []),
                # NVD base data
                "description": nvd.get("description", ""),
                "vuln_status": nvd.get("vuln_status", "Unknown"),
                "nvd_published": nvd.get("published_date", ""),
                "references": rec.get("references", nvd.get("references", [])),
                # CVSS — both versions exposed separately
                "cvss": cvss_primary.get("baseScore"),
                "cvss_severity": cvss_primary.get("baseSeverity", ""),
                "cvss_vector": cvss_primary.get("vectorString", ""),
                "cvss_v31_score": cvss_v31.get("baseScore"),
                "cvss_v31_severity": cvss_v31.get("baseSeverity", ""),
                "cvss_v31_vector": cvss_v31.get("vectorString", ""),
                "cvss_v40_score": cvss_v40.get("baseScore"),
                "cvss_v40_severity": cvss_v40.get("baseSeverity", ""),
                "cvss_v40_vector": cvss_v40.get("vectorString", ""),
                # Classification
                "cwe_ids": nvd.get("cwe_ids", []),
                "capec_ids": rec.get("capec_ids", nvd.get("capec_ids", [])),
                "cpe_list": rec.get("cpe_list", nvd.get("cpe_list", []))[:10],
                "affected_products": nvd.get("affected_products", [])[:8],
                "system_category": rec.get("system_category", nvd.get("system_category", "IT")),
                # EPSS
                "epss": epss_data.get("epss_score"),
                "epss_not_scored": epss_data.get("epss_not_scored", False),
                "epss_pct": epss_data.get("epss_percentile"),
                # KEV
                "in_kev": kev_data.get("in_kev", False),
                "kev_date_added": kev_data.get("date_added"),
                "kev_due_date": kev_data.get("due_date"),
                "kev_required_action": kev_data.get("required_action"),
                "ransomware": kev_data.get("ransomware_use") == "Known",
                # Exploit intelligence
                "has_exploit": exploit_data.get("has_public_exploit", False),
                "has_poc": exploit_data.get("has_poc_only", False),
                "exploit_maturity": rec.get("exploit_maturity", exploit_data.get("exploit_maturity", "None")),
                "is_weaponized": rec.get("is_weaponized", exploit_data.get("is_weaponized", False)),
                "commercial_exploit": rec.get("commercial_exploit", exploit_data.get("commercial_exploit", False)),
                "exploited_in_wild": rec.get("exploited_in_wild", threat_ctx.get("exploited_in_wild", False)),
                "botnet_use": rec.get("botnet_use", threat_ctx.get("botnet_use", False)),
                "exploit_count": exploit_data.get("exploit_count", 0),
                "exploit_links": exploit_data.get("exploit_links", []),
                # ATT&CK
                "techniques": attack_data.get("techniques", []),
                "technique_names": attack_data.get("technique_names", []),
                "tactics": attack_data.get("tactics", []),
                # Recommendations
                "affected_systems": rec.get("affected_systems", []),
                "attack_surface": rec.get("attack_surface", "Unknown"),
                "ciso_summary": rec.get("ciso_summary", ""),
                "immediate_actions": rec.get("immediate_actions", []),
                "workarounds": rec.get("workarounds", []),
                # Patch intelligence
                "patch_links": patch_links,
                "patch_available": len(patch_links) > 0,
                "fixed_versions": fixed_versions,
                # Score components
                "kev_bonus": scored.get("kev_bonus", 0),
                "exploit_bonus": scored.get("exploit_bonus", 0),
                "ransomware_bonus": scored.get("ransomware_bonus", 0),
                "wild_bonus": scored.get("wild_bonus", 0),
                "cvss_score_raw": scored.get("cvss_score_raw", 0),
                "epss_score_raw": scored.get("epss_score_raw", 0),
            })
        except Exception:
            pass
    results.sort(key=lambda x: (x["composite_score"] or -1), reverse=True)
    return results


def _calc_stats(results: list[dict]) -> dict:
    return {
        "total": len(results),
        "critical": sum(1 for r in results if r["priority_category"] == "Critical"),
        "high":     sum(1 for r in results if r["priority_category"] == "High"),
        "medium":   sum(1 for r in results if r["priority_category"] == "Medium"),
        "low":      sum(1 for r in results if r["priority_category"] == "Low"),
        "unscored": sum(1 for r in results if r["priority_category"] == "Unscored"),
        "in_kev":   sum(1 for r in results if r["in_kev"]),
        "has_exploit": sum(1 for r in results if r["has_exploit"]),
        "ransomware": sum(1 for r in results if r["ransomware"]),
    }


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.post("/api/analyze")
async def analyze(
    cves: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    skip_exploitdb: bool = Form(False),
    skip_attack: bool = Form(False),
    title: Optional[str] = Form(None),
):
    cve_list: list[str] = []

    if file and file.filename:
        content = (await file.read()).decode("utf-8", errors="replace")
        if file.filename.lower().endswith(".csv"):
            reader = csv.reader(io.StringIO(content))
            for row in reader:
                for cell in row:
                    cell = cell.strip()
                    if cell.upper().startswith("CVE-"):
                        cve_list.append(cell.upper())
        else:
            for line in content.splitlines():
                for token in line.split(","):
                    token = token.strip()
                    if token.upper().startswith("CVE-"):
                        cve_list.append(token.upper())

    if cves:
        for token in cves.replace("\n", ",").split(","):
            token = token.strip()
            if token.upper().startswith("CVE-"):
                cve_list.append(token.upper())

    # Deduplicate preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for c in cve_list:
        if c not in seen:
            seen.add(c)
            unique.append(c)

    if not unique:
        raise HTTPException(status_code=400, detail="No valid CVE IDs provided")

    job_id = str(uuid.uuid4())
    cwd = str(Path(__file__).parent)
    report_title = title or f"PatchPilot AI — CVE Assessment {datetime.now().strftime('%Y-%m-%d')}"

    phases_state = [
        {"id": pid, "name": pname, "description": pdesc,
         "status": "pending", "log": "", "started_at": None, "ended_at": None}
        for pid, pname, pdesc in PHASES
    ]

    jobs[job_id] = {
        "status": "running",
        "phases": phases_state,
        "cve_count": len(unique),
        "report_path": None,
        "results": None,
        "event_queue": queue.Queue(),
        "created_at": datetime.utcnow().isoformat(),
    }

    t = threading.Thread(
        target=run_pipeline,
        args=(job_id, unique, skip_exploitdb, skip_attack, report_title, cwd),
        daemon=True,
    )
    t.start()

    return {"job_id": job_id, "cve_count": len(unique)}


@app.get("/api/jobs/{job_id}/stream")
async def stream(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    job = jobs[job_id]

    async def event_generator():
        # Send current phase state snapshot
        yield f"data: {json.dumps({'event': 'snapshot', 'data': {'phases': job['phases'], 'status': job['status']}})}\n\n"

        while True:
            try:
                item = job["event_queue"].get(timeout=0.2)
                yield f"data: {json.dumps(item)}\n\n"
                if item.get("event") in ("complete", "failed"):
                    break
            except queue.Empty:
                if job["status"] in ("complete", "failed"):
                    break
                yield ": heartbeat\n\n"
                await asyncio.sleep(0.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/jobs/{job_id}/results")
async def get_results(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    job = jobs[job_id]
    if job["status"] != "complete":
        raise HTTPException(status_code=202, detail="Job not complete yet")
    results = job["results"] or []
    return {"results": results, "stats": _calc_stats(results)}


@app.get("/api/jobs/{job_id}/download/html")
async def download_html(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    job = jobs[job_id]
    rp = job.get("report_path")
    if not rp or not Path(rp).exists():
        raise HTTPException(status_code=404, detail="Report not available")
    return FileResponse(rp, media_type="text/html",
                        filename=f"vuln_report_{datetime.now().strftime('%Y%m%d')}.html")


@app.get("/api/jobs/{job_id}/download/csv")
async def download_csv(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    job = jobs[job_id]
    results = job.get("results") or []
    if not results:
        raise HTTPException(status_code=404, detail="No results available")

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["CVE ID", "Score", "Priority", "CVSS", "EPSS", "In KEV",
                     "Ransomware", "Has Exploit", "Patch Timeline", "Attack Surface", "CISO Summary"])
    for r in results:
        writer.writerow([
            r["cve_id"], r["composite_score"], r["priority_category"],
            r["cvss"], r["epss"], r["in_kev"], r["ransomware"],
            r["has_exploit"], r["patch_timeline"], r["attack_surface"],
            r["ciso_summary"],
        ])

    return StreamingResponse(
        io.BytesIO(buf.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=vuln_report_{datetime.now().strftime('%Y%m%d')}.csv"},
    )


@app.get("/api/jobs/{job_id}/status")
async def job_status(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    job = jobs[job_id]
    return {
        "status": job["status"],
        "cve_count": job["cve_count"],
        "phases": job["phases"],
    }


# ── Static files ───────────────────────────────────────────────────────────────
static_dir = Path(__file__).parent / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/", response_class=HTMLResponse)
async def root():
    index = static_dir / "index.html"
    if index.exists():
        return HTMLResponse(index.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>static/index.html not found</h1>")


if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("  PatchPilot AI — CVE Intelligence Dashboard")
    print("  http://localhost:8000")
    print("=" * 60)
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False)
