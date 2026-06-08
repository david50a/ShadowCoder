"""
ShadowCoder API v2 — Real-time exploit simulation engine.

New in v2:
  Phase 3 — WebSocket live scan progress, async processing, in-memory cache
  Phase 4 — Multi-step attack chains, enhanced payload + simulation engine
  Phase 5 — AI enrichment (explain / fix / triage) via Anthropic Claude
  Phase 6 — Project-wide analysis: dependency graph, endpoint map, data flows

Endpoints:
  POST /api/scan              Scan code (returns job_id, use WS for progress)
  GET  /api/scan/{job_id}     Poll job status + result
  WS   /ws/{job_id}           Real-time scan progress stream
  POST /api/scan/sync         Synchronous scan (blocks until done)
  POST /api/scan/file         Upload .py file for scanning
  POST /api/ai/explain        AI explanation of a finding
  POST /api/ai/fix            AI fix suggestion for a finding
  POST /api/ai/triage         AI-ranked priority list
  POST /api/project/analyze   Full project directory analysis
  GET  /api/cache/stats       Cache hit ratio and stats
  GET  /api/health            Health check + AI status

Run:
  uvicorn api.server:app --reload --host 0.0.0.0 --port 8000
"""

import asyncio
import logging
import sys
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine import AttackEngine, Reporter
from engine.sandbox_runner import SandboxRunner
from engine.scan_manager import ScanManager, ScanJob, JobStatus, _report_to_dict
from engine.ai_service import AIService, AIServiceSync
from engine.project_analyzer import ProjectAnalyzer, project_report_to_dict
from engine.sabotage_engine import sabotage_source
from engine.multi_vector_engine import MultiVectorEngine, multi_vector_report_to_dict
from engine.architecture_mapper import ArchitectureMapper, arch_map_to_dict
from engine.discovery_engine import LocalhostDiscoveryEngine, AttackSurfaceMapper
from engine.security_checks import SecurityTestModules
from engine.findings_engine import FindingsEngine
from fastapi.responses import Response

# SaaS layer
try:
    from saas.router import router as saas_router
    from saas.database import check_quota, record_scan
    from saas.auth import get_current_user_optional
    from fastapi import Depends
    SAAS_ENABLED = True
except ImportError as e:
    log.warning(f"SaaS layer disabled: {e}")
    SAAS_ENABLED = False

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
log = logging.getLogger("shadowcoder.api")

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="⚔️ ShadowCoder API v3 — SaaS Edition",
    description="Real-time multi-phase exploit simulation engine",
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)
app.add_middleware(GZipMiddleware, minimum_size=1000)

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# Mount SaaS router
if SAAS_ENABLED:
    app.include_router(saas_router, prefix="/api")
    log.info("SaaS layer mounted: auth, billing, CI/CD endpoints active")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Singletons ────────────────────────────────────────────────────────────────

_engine = AttackEngine()
_manager = ScanManager(_engine, max_workers=4)
_ai = AIService()
_ai_sync = AIServiceSync()
_project_analyzer = ProjectAnalyzer()
_mv_engine = MultiVectorEngine(max_workers=6)
_arch_mapper = ArchitectureMapper()

# In-memory store for multi-vector scan results (job_id -> result dict)
_mv_jobs: dict[str, dict] = {}

# In-memory store for unified scan results (job_id -> job dict)
_unified_scan_jobs: dict[str, dict] = {}


# ── Request models ─────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    source_code: str = Field(..., description="Python source code to scan")
    filename: str = Field(default="editor.py")
    skip_ai: bool = Field(default=True, description="Skip Ollama AI enrichment")
    exploit: bool = Field(default=False, description="Run live exploitation payloads")

class ScanRequestUnified(BaseModel):
    target_url: Optional[str] = Field(default=None, description="URL of target to scan dynamically")
    source_code: Optional[str] = Field(default=None, description="Raw source code to scan statically")
    filename: str = Field(default="editor.py")
    project_root: Optional[str] = Field(default=None, description="Directory to scan project-wide")

class MultiVectorScanRequest(BaseModel):
    source_code: str = Field(..., description="Python source code to scan")
    filename: str = Field(default="editor.py")
    vectors: list[str] = Field(
        default=["input", "auth", "api", "dataflow", "config", "dependency"],
        description="Attack vectors to run (input, auth, api, dataflow, config, dependency)"
    )
    parallel: bool = Field(default=True, description="Run vectors in parallel")
    use_ai: bool = Field(default=False, description="Enrich scan results with Ollama AI")

class ArchitectureMapRequest(BaseModel):
    source_code: str = Field(..., description="Python source code to map")
    filename: str = Field(default="editor.py")

class SabotageRequest(BaseModel):
    source_code: str = Field(..., description="Python source code to sabotage")
    use_ai: bool = Field(default=True, description="Whether to use AI or fast rule-based transforms")

class SimulateRequest(BaseModel):
    source_code: str
    payload: str

class AIExplainRequest(BaseModel):
    vulnerability: dict
    code_context: str = ""

class AIFixRequest(BaseModel):
    vulnerability: dict
    source_code: str = ""

class AITriageRequest(BaseModel):
    findings: list[dict]

class ProjectAnalyzeRequest(BaseModel):
    project_root: str = Field(..., description="Absolute or relative path to project root")
    max_files: int = Field(default=50, ge=1, le=200)

class SetApiKeyRequest(BaseModel):
    api_key: str


# ── Static files ──────────────────────────────────────────────────────────────

frontend_path = Path(__file__).resolve().parent.parent / "frontend"
if frontend_path.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_path)), name="static")

    @app.get("/")
    def index():
        # Serve the Dashboard / Login page as the entry point
        return FileResponse(str(frontend_path / "dashboard" / "index.html"))

    @app.get("/app")
    def scanner_app():
        # Serve the main scanner tool at /app
        return FileResponse(str(frontend_path / "index.html"))


# ── Phase 3: WebSocket real-time scan ─────────────────────────────────────────

@app.websocket("/ws/{job_id}")
async def websocket_scan(websocket: WebSocket, job_id: str):
    """
    Real-time scan progress stream.
    Client connects after getting a job_id from POST /api/scan.
    Receives: {type: "stage"|"complete"|"error"|"cached", ...}
    """
    await _manager.ws.connect(job_id, websocket)
    try:
        job = _manager.get_job(job_id)

        # If job is already done (cached or completed before WS connected)
        if job and job.status == JobStatus.CACHED:
            await _manager.ws.broadcast_cached(job_id, job.result)
        elif job and job.status == JobStatus.COMPLETE:
            await _manager.ws.broadcast_complete(job_id, job.result)
        elif job and job.status == JobStatus.FAILED:
            await _manager.ws.broadcast_error(job_id, job.error or "Unknown error")

        # Keep connection alive until client disconnects
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=60.0)
                # Client can send "ping" to keep alive
                if data == "ping":
                    await websocket.send_text('{"type":"pong"}')
            except asyncio.TimeoutError:
                await websocket.send_text('{"type":"heartbeat"}')
    except WebSocketDisconnect:
        pass
    finally:
        _manager.ws.disconnect(job_id, websocket)


@app.post("/api/sabotage")
async def sabotage_code(request: SabotageRequest):
    """
    Inject realistic vulnerabilities into the provided source code.
    Uses Ollama AI when available, falls back to deterministic rule-based
    transforms so this endpoint always works — no Ollama required.
    """
    try:
        should_use_ai = request.use_ai and _ai.is_available
        result = await asyncio.to_thread(
            sabotage_source, request.source_code, should_use_ai
        )
        if not result.get("summary"):
            # No transforms applied — code may already be vulnerable or pattern unsupported
            return {
                "new_code": request.source_code,
                "summary": [],
                "method": result.get("method", "rules"),
                "message": "No sabotage patterns matched this code. Try code with SQL queries, subprocess calls, or hashlib usage.",
            }
        return result
    except Exception as e:
        log.error(f"Sabotage failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ── Unified Scan Background Workers & Endpoints ───────────────────────────────

async def run_dynamic_scan_task(job_id: str, target_url: str):
    _unified_scan_jobs[job_id] = {
        "status": "RUNNING",
        "type": "dynamic",
        "target": target_url,
        "progress": 10,
        "result": None,
        "error": None
    }
    try:
        t0 = time.perf_counter()
        
        # 1. Target Discovery
        _unified_scan_jobs[job_id]["progress"] = 25
        discovery = LocalhostDiscoveryEngine(max_depth=3, max_pages=30)
        discovery_results = discovery.discover(target_url)
        
        # 2. Attack Surface Mapping
        _unified_scan_jobs[job_id]["progress"] = 50
        mapper = AttackSurfaceMapper()
        mapped_surface = mapper.map_surface(target_url, discovery_results)
        
        # 3. Security Checks
        _unified_scan_jobs[job_id]["progress"] = 75
        checker = SecurityTestModules()
        raw_findings = checker.run_all_checks(target_url, mapped_surface)
        
        # 4. Findings Engine
        _unified_scan_jobs[job_id]["progress"] = 85
        findings_engine = FindingsEngine()
        findings = findings_engine.standardize(raw_findings)
        
        # 5. AI Enrichment
        _unified_scan_jobs[job_id]["progress"] = 90
        enriched_findings = []
        for f in findings:
            ai_exp = await _ai.explain(f)
            ai_fix = await _ai.fix(f)
            f["ai_explanation"] = ai_exp
            f["ai_fix"] = ai_fix
            enriched_findings.append(f)
            
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        
        # Compile dynamic scan report
        raw_report = {
            "target_url": target_url,
            "scan_time_ms": elapsed_ms,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "vulnerabilities_found": len(enriched_findings),
            "findings": enriched_findings,
            "pages": discovery_results.get("pages", []),
            "forms": discovery_results.get("forms", []),
            "cookies": mapped_surface.get("cookies", []),
            "graph": mapped_surface.get("graph", {"nodes": [], "edges": []}),
            "summary": f"Dynamic assessment of {target_url} completed. Discovered {len(discovery_results.get('pages', []))} pages, {len(discovery_results.get('forms', []))} forms, and identified {len(enriched_findings)} security issues."
        }
        
        if _ai.is_available:
            summary = await _ai.project_summary(raw_report)
            raw_report["summary"] = summary
            
        _unified_scan_jobs[job_id]["status"] = "COMPLETE"
        _unified_scan_jobs[job_id]["progress"] = 100
        _unified_scan_jobs[job_id]["result"] = raw_report
        
    except Exception as e:
        log.error(f"Dynamic scan job {job_id} failed: {e}", exc_info=True)
        _unified_scan_jobs[job_id]["status"] = "FAILED"
        _unified_scan_jobs[job_id]["error"] = str(e)


async def run_static_scan_task(job_id: str, source_code: str, filename: str):
    _unified_scan_jobs[job_id] = {
        "status": "RUNNING",
        "type": "static",
        "target": filename,
        "progress": 20,
        "result": None,
        "error": None
    }
    try:
        # Submit to existing static scan manager
        manager_job_id = await _manager.submit(
            source_code,
            filename=filename,
            skip_ai=False,
            exploit=False
        )
        
        # Poll static manager job status
        for _ in range(60):
            job = _manager.get_job(manager_job_id)
            if job and job.status in (JobStatus.COMPLETE, JobStatus.CACHED, JobStatus.FAILED):
                break
            await asyncio.sleep(0.5)
            
        job = _manager.get_job(manager_job_id)
        if job and job.status in (JobStatus.COMPLETE, JobStatus.CACHED) and job.result:
            _unified_scan_jobs[job_id]["status"] = "COMPLETE"
            _unified_scan_jobs[job_id]["progress"] = 100
            _unified_scan_jobs[job_id]["result"] = job.result
        else:
            error_msg = job.error if job else "Scan timed out or failed in static manager"
            _unified_scan_jobs[job_id]["status"] = "FAILED"
            _unified_scan_jobs[job_id]["error"] = error_msg
            
    except Exception as e:
        log.error(f"Static scan job {job_id} failed: {e}", exc_info=True)
        _unified_scan_jobs[job_id]["status"] = "FAILED"
        _unified_scan_jobs[job_id]["error"] = str(e)


async def run_project_scan_task(job_id: str, project_root: str, max_files: int):
    _unified_scan_jobs[job_id] = {
        "status": "RUNNING",
        "type": "project",
        "target": project_root,
        "progress": 20,
        "result": None,
        "error": None
    }
    try:
        loop = asyncio.get_event_loop()
        report = await loop.run_in_executor(
            None,
            lambda: _project_analyzer.analyze(project_root, max_files=max_files)
        )
        result_dict = project_report_to_dict(report)
        _unified_scan_jobs[job_id]["status"] = "COMPLETE"
        _unified_scan_jobs[job_id]["progress"] = 100
        _unified_scan_jobs[job_id]["result"] = result_dict
    except Exception as e:
        log.error(f"Project scan job {job_id} failed: {e}", exc_info=True)
        _unified_scan_jobs[job_id]["status"] = "FAILED"
        _unified_scan_jobs[job_id]["error"] = str(e)


@app.post("/scan")
async def start_unified_scan(request: ScanRequestUnified, background_tasks: BackgroundTasks):
    job_id = "JOB-" + uuid.uuid4().hex[:12].upper()
    
    if request.target_url:
        background_tasks.add_task(run_dynamic_scan_task, job_id, request.target_url)
    elif request.source_code:
        background_tasks.add_task(run_static_scan_task, job_id, request.source_code, request.filename)
    elif request.project_root:
        background_tasks.add_task(run_project_scan_task, job_id, request.project_root, 100)
    else:
        raise HTTPException(status_code=400, detail="One of target_url, source_code, or project_root must be provided")
        
    return {
        "job_id": job_id,
        "status": "RUNNING"
    }


@app.get("/scan/{id}")
async def get_unified_scan_status(id: str):
    job = _unified_scan_jobs.get(id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
        
    response = {
        "job_id": id,
        "status": job["status"],
        "progress": job["progress"],
        "error": job["error"]
    }
    if job["status"] == "COMPLETE" and job["result"]:
        response["result"] = job["result"]
    return response


@app.get("/report/{id}")
async def get_unified_report(id: str, format: str = "json"):
    job = _unified_scan_jobs.get(id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
        
    if job["status"] != "COMPLETE" or not job["result"]:
        raise HTTPException(status_code=400, detail="Scan report is not ready or failed")
        
    report_data = job["result"]
    reporter = Reporter()
    
    fmt = format.lower().strip()
    if fmt == "html":
        html_content = reporter.to_html(report_data)
        return Response(content=html_content, media_type="text/html")
    elif fmt == "pdf":
        pdf_bytes = reporter.to_pdf(report_data)
        headers = {
            "Content-Disposition": f"attachment; filename=report_{id}.pdf"
        }
        return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)
    else:
        return report_data


@app.post("/api/scan")
async def scan_async(request: ScanRequest, user: Optional[dict] = Depends(get_current_user_optional if SAAS_ENABLED else lambda: None)):
    """
    Submit a scan job. Returns job_id immediately.
    Connect to /ws/{job_id} for real-time progress.
    """
    if not request.source_code.strip():
        raise HTTPException(status_code=400, detail="source_code cannot be empty")

    user_id = user.get("user_id") if user else None

    if SAAS_ENABLED and user_id:
        quota = check_quota(user_id)
        if not quota["allowed"]:
            raise HTTPException(status_code=429, detail=f"Scan limit reached: {quota.get('reason')}")

    job_id = await _manager.submit(
        request.source_code,
        filename=request.filename,
        skip_ai=request.skip_ai,
        exploit=request.exploit,
        user_id=user_id  # Pass user_id to the manager
    )    
    job = _manager.get_job(job_id)
    return {
        "job_id": job_id,
        "status": job.status if job else "QUEUED",
        "ws_url": f"/ws/{job_id}",
        "poll_url": f"/api/scan/{job_id}",
        "cached": job.status == JobStatus.CACHED if job else False,
    }


@app.get("/api/scan/{job_id}")
async def get_scan_result(job_id: str):
    """Poll scan status and result."""
    job = _manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    response = job.to_status_dict()
    if job.status in (JobStatus.COMPLETE, JobStatus.CACHED) and job.result:
        response["result"] = job.result
    return response


@app.post("/api/scan/sync")
def scan_sync(request: ScanRequest, user: Optional[dict] = Depends(get_current_user_optional if SAAS_ENABLED else lambda: None)):
    """
    Synchronous scan — blocks until complete.
    Use for simple integrations that don't need WebSocket.
    Results are still cached.
    """
    if not request.source_code.strip():
        raise HTTPException(status_code=400, detail="source_code cannot be empty")

    user_id = user.get("user_id") if user else None

    if SAAS_ENABLED and user_id:
        quota = check_quota(user_id)
        if not quota["allowed"]:
            raise HTTPException(status_code=429, detail=f"Scan limit reached: {quota.get('reason')}")

    cache_key = _manager.cache.make_key(request.source_code, request.filename, request.skip_ai, request.exploit)
    cached = _manager.cache.get(cache_key)
    if cached:
        if user_id and SAAS_ENABLED:
            record_scan(user_id, cached)
        return {**cached, "cached": True}

    try:
        t0 = time.perf_counter()
        # For sync scan, we'll just run the engine directly but without easy way to run exploit_engine 
        # unless we refactor. For now, sync scan doesn't support exploit flag easily, 
        # or we just call _run_engine like ScanManager does.
        
        # Actually, let's just make sync scan support it by calling the manager's logic or refactoring.
        # But wait, manager.submit is async. 
        
        # Let's just run the engine scan and then exploit if requested.
        report = _engine.scan(request.source_code, filename=request.filename)
        
        if request.exploit:
            from engine.exploit_engine import ExploitEngine
            exploit_engine = ExploitEngine()
            for ar in report.attack_results:
                if ar.exploitable:
                    res = exploit_engine.run_exploit(request.source_code, ar)
                    if res["confirmed"]:
                        ar.simulation["exploit_confirmed"] = True
                        ar.simulation["exploit_output"] = res["attempts"][0]["output"] if res["attempts"] else ""
                        ar.simulation["exploit_payload"] = res["attempts"][0]["payload"] if res["attempts"] else ""

        elapsed = int((time.perf_counter() - t0) * 1000)
        result = _report_to_dict(report)
        _manager.cache.set(cache_key, result)

        if user_id and SAAS_ENABLED:
            record_scan(user_id, result)

        return {**result, "cached": False}
    except Exception as e:
        log.error(f"Sync scan failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/file")
async def scan_file(file: UploadFile = File(...), skip_ai: bool = True, user: Optional[dict] = Depends(get_current_user_optional if SAAS_ENABLED else lambda: None)):
    if not file.filename or not file.filename.endswith(".py"):
        raise HTTPException(status_code=400, detail="Only .py files accepted")
    content = await file.read()
    try:
        source = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be valid UTF-8")

    user_id = user.get("user_id") if user else None

    if SAAS_ENABLED and user_id:
        quota = check_quota(user_id)
        if not quota["allowed"]:
            raise HTTPException(status_code=429, detail=f"Scan limit reached: {quota.get('reason')}")

    job_id = await _manager.submit(source, filename=file.filename, skip_ai=skip_ai, user_id=user_id)
    return {"job_id": job_id, "ws_url": f"/ws/{job_id}"}

# ── Phase 5: AI endpoints ──────────────────────────────────────────────────────

@app.post("/api/ai/explain")
async def ai_explain(request: AIExplainRequest):
    """AI-powered vulnerability explanation."""
    if not _ai.is_available:
        from engine.ai_service import _fallback_explanation
        return {"explanation": _fallback_explanation(request.vulnerability), "ai_powered": False}
    explanation = await _ai.explain(request.vulnerability, request.code_context)
    return {"explanation": explanation, "ai_powered": True}


@app.post("/api/ai/fix")
async def ai_fix(request: AIFixRequest):
    """AI-generated fix suggestion."""
    if not _ai.is_available:
        from engine.ai_service import _fallback_fix
        return {"fix": _fallback_fix(request.vulnerability), "ai_powered": False}
    fix = await _ai.fix(request.vulnerability, request.source_code)
    return {"fix": fix, "ai_powered": True}


@app.post("/api/ai/triage")
async def ai_triage(request: AITriageRequest):
    """AI-ranked priority list."""
    triage = await _ai.triage(request.findings)
    return {"triage": triage, "ai_powered": _ai.is_available}


@app.post("/api/ai/summary")
async def ai_summary(request: ScanRequest):
    """Full scan + AI executive summary."""
    report_dict = await _run_scan_and_get_result(request)
    summary = await _ai.project_summary(report_dict)
    return {**report_dict, "ai_summary": summary, "ai_powered": _ai.is_available}


async def _run_scan_and_get_result(request: ScanRequest) -> dict:
    job_id = await _manager.submit(request.source_code, request.filename, request.skip_ai)
    # Wait for completion
    for _ in range(60):  # max 30 seconds
        job = _manager.get_job(job_id)
        if job and job.status in (JobStatus.COMPLETE, JobStatus.CACHED, JobStatus.FAILED):
            break
        await asyncio.sleep(0.5)
    if job and job.result:
        return job.result
    raise HTTPException(status_code=500, detail="Scan timed out")


# ── Phase 6: Project-wide analysis ────────────────────────────────────────────

@app.post("/api/project/analyze")
def analyze_project(request: ProjectAnalyzeRequest):
    """
    Full project analysis: dependency graph, endpoint mapping, data flows.
    Provide the path to your Python project root.
    """
    root = Path(request.project_root)
    if not root.exists():
        raise HTTPException(status_code=400, detail=f"Path not found: {request.project_root}")
    if not root.is_dir():
        raise HTTPException(status_code=400, detail="Path must be a directory")
    
    try:
        report = _project_analyzer.analyze(str(root), max_files=request.max_files)
        return project_report_to_dict(report)
    except Exception as e:
        log.error(f"Project analysis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ── Simulation ────────────────────────────────────────────────────────────────

@app.post("/api/simulate")
def simulate_attack(request: SimulateRequest):
    try:
        success, output = SandboxRunner.run_exploit(request.source_code, request.payload)
        return {"success": success, "output": output}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Cache ─────────────────────────────────────────────────────────────────────

@app.get("/api/cache/stats")
def cache_stats():
    return _manager.cache_stats()

@app.delete("/api/cache")
def clear_cache():
    _manager.cache.clear()
    return {"message": "Cache cleared"}


# ── Multi-Vector Attack Simulation Engine ──────────────────────────────────────────

# Multi-vector WS connections: job_id -> set of WebSocket connections
_mv_ws_connections: dict[str, list] = {}


@app.post("/api/multi-vector/scan")
async def multi_vector_scan(request: MultiVectorScanRequest):
    """
    Launch a multi-vector parallel attack simulation.
    Returns a job_id immediately.
    Connect to /ws/multi/{job_id} for real-time per-vector progress events.
    Poll /api/multi-vector/{job_id} to get the full result once complete.
    """
    if not request.source_code.strip():
        raise HTTPException(status_code=400, detail="source_code cannot be empty")

    job_id = uuid.uuid4().hex[:12].upper()
    _mv_jobs[job_id] = {"status": "RUNNING", "result": None, "error": None}

    async def _run():
        def _progress(vector_type: str, result):
            """Called from thread when each vector completes."""
            # Build incremental update
            update = {
                "type": "vector_complete",
                "job_id": job_id,
                "vector_type": vector_type,
                "vector_label": result.vector_label,
                "severity": result.severity,
                "finding_count": len(result.findings),
                "exploitable": result.exploitable,
                "scan_time_ms": result.scan_time_ms,
                "error": result.error,
            }
            # Broadcast to any connected WS clients
            sockets = list(_mv_ws_connections.get(job_id, []))
            if sockets and asyncio.get_event_loop():
                text = __import__("json").dumps(update)
                for ws in sockets:
                    asyncio.run_coroutine_threadsafe(
                        ws.send_text(text), asyncio.get_event_loop()
                    )

        try:
            loop = asyncio.get_event_loop()
            report = await loop.run_in_executor(
                None,
                lambda: _mv_engine.scan(
                    request.source_code,
                    filename=request.filename,
                    vectors=request.vectors,
                    progress_callback=_progress,
                    use_ai=request.use_ai,
                ),
            )
            result_dict = multi_vector_report_to_dict(report)
            _mv_jobs[job_id]["status"] = "COMPLETE"
            _mv_jobs[job_id]["result"] = result_dict

            # Broadcast completion to any WS clients
            sockets = list(_mv_ws_connections.get(job_id, []))
            done_msg = __import__("json").dumps({"type": "complete", "job_id": job_id, "result": result_dict})
            for ws in sockets:
                try:
                    await ws.send_text(done_msg)
                except Exception:
                    pass
        except Exception as e:
            log.error(f"Multi-vector scan {job_id} failed: {e}", exc_info=True)
            _mv_jobs[job_id]["status"] = "FAILED"
            _mv_jobs[job_id]["error"] = str(e)
            sockets = list(_mv_ws_connections.get(job_id, []))
            err_msg = __import__("json").dumps({"type": "error", "job_id": job_id, "error": str(e)})
            for ws in sockets:
                try:
                    await ws.send_text(err_msg)
                except Exception:
                    pass

    asyncio.ensure_future(_run())
    return {
        "job_id": job_id,
        "status": "RUNNING",
        "ws_url": f"/ws/multi/{job_id}",
        "poll_url": f"/api/multi-vector/{job_id}",
        "vectors": request.vectors,
    }


@app.get("/api/multi-vector/{job_id}")
async def get_multi_vector_result(job_id: str):
    """Poll multi-vector scan status and result."""
    job = _mv_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Multi-vector job not found")
    return {
        "job_id": job_id,
        "status": job["status"],
        "result": job.get("result"),
        "error": job.get("error"),
    }


@app.get("/api/multi-vector/{job_id}/graph")
async def get_attack_graph(job_id: str):
    """Get the vis-network attack graph for a completed multi-vector scan."""
    job = _mv_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Multi-vector job not found")
    if job["status"] != "COMPLETE" or not job.get("result"):
        raise HTTPException(status_code=202, detail="Scan not yet complete")
    return job["result"].get("attack_graph", {"nodes": [], "edges": []})


@app.websocket("/ws/multi/{job_id}")
async def websocket_multi_vector(websocket: WebSocket, job_id: str):
    """
    Real-time multi-vector scan progress stream.
    Receives:
      {type: "vector_complete", vector_type, severity, finding_count, exploitable, scan_time_ms}
      {type: "complete", result: {...}}
      {type: "error", error: "..."}
    """
    await websocket.accept()
    _mv_ws_connections.setdefault(job_id, []).append(websocket)
    try:
        # If already done, send result immediately
        job = _mv_jobs.get(job_id)
        if job and job["status"] == "COMPLETE" and job.get("result"):
            await websocket.send_text(
                __import__("json").dumps({"type": "complete", "job_id": job_id, "result": job["result"]})
            )
        elif job and job["status"] == "FAILED":
            await websocket.send_text(
                __import__("json").dumps({"type": "error", "job_id": job_id, "error": job.get("error")})
            )

        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=60.0)
                if data == "ping":
                    await websocket.send_text('{"type":"pong"}')
            except asyncio.TimeoutError:
                await websocket.send_text('{"type":"heartbeat"}')
    except WebSocketDisconnect:
        pass
    finally:
        sockets = _mv_ws_connections.get(job_id, [])
        if websocket in sockets:
            sockets.remove(websocket)


@app.post("/api/architecture/map")
async def architecture_map(request: ArchitectureMapRequest):
    """
    Map the architecture of Python source code.
    Identifies entry points, trust boundaries, data flows, and components.
    """
    if not request.source_code.strip():
        raise HTTPException(status_code=400, detail="source_code cannot be empty")
    try:
        result = await asyncio.to_thread(
            lambda: arch_map_to_dict(
                _arch_mapper.map(request.source_code, filename=request.filename)
            )
        )
        return result
    except Exception as e:
        log.error(f"Architecture mapping failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))



@app.get("/api/file")
def get_file_content(path: str):
    """Retrieve file content for simulation/viewing."""
    p = Path(path)
    if not p.exists() or not p.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    try:
        return {"content": p.read_text(encoding="utf-8")}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "version": "2.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ai_available": _ai.is_available,
        "cache": _manager.cache_stats(),
        "phases": {
            "phase3_realtime": True,
            "phase4_attack_engine": True,
            "phase5_ai": _ai.is_available,
            "phase6_project_analysis": True,
        }
    }
