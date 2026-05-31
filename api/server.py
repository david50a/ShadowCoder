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


# ── Request models ─────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    source_code: str = Field(..., description="Python source code to scan")
    filename: str = Field(default="editor.py")
    skip_ai: bool = Field(default=True, description="Skip Ollama AI enrichment")
    exploit: bool = Field(default=False, description="Run live exploitation payloads")

class SabotageRequest(BaseModel):
    source_code: str = Field(..., description="Python source code to sabotage")

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
        result = await asyncio.to_thread(
            sabotage_source, request.source_code, _ai.is_available
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
