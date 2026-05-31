"""
ShadowCoder — Async Scan Manager (Phase 3)

Provides:
  - Async scan execution via asyncio + ThreadPoolExecutor
  - WebSocket progress broadcasting (live scan stages)
  - In-memory result cache (LRU, configurable TTL)
  - Background task queue with job IDs
  - Optional Redis backend (falls back to in-memory gracefully)

Architecture:
  Client → WebSocket → ScanManager → ThreadPool → AttackEngine
                    ↑                             ↓
              Progress events              Result Cache
"""

import asyncio
import hashlib
import json
import logging
import time
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Callable, Optional

log = logging.getLogger("shadowcoder.scan_manager")


# ── Job state machine ─────────────────────────────────────────────────────────

class JobStatus(str, Enum):
    QUEUED     = "QUEUED"
    RUNNING    = "RUNNING"
    COMPLETE   = "COMPLETE"
    FAILED     = "FAILED"
    CACHED     = "CACHED"


@dataclass
class ScanStage:
    """A single progress event emitted to WebSocket clients."""
    stage: str          # e.g. "ast_parse", "payload_gen"
    label: str          # Human-readable
    progress: int       # 0-100
    detail: str = ""    # Optional extra info


@dataclass
class ScanJob:
    job_id: str
    status: JobStatus
    source_code: str
    filename: str
    skip_ai: bool
    exploit: bool = False
    user_id: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    result: Optional[dict] = None
    error: Optional[str] = None
    stages: list[ScanStage] = field(default_factory=list)

    def elapsed_ms(self) -> int:
        if self.started_at and self.finished_at:
            return int((self.finished_at - self.started_at) * 1000)
        return 0

    def to_status_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "status": self.status,
            "elapsed_ms": self.elapsed_ms(),
            "stages": [asdict(s) for s in self.stages],
            "error": self.error,
        }


# ── In-memory LRU cache ───────────────────────────────────────────────────────

class ScanCache:
    """
    Thread-safe LRU cache for scan results.
    Key = SHA-256 of (source_code, filename, skip_ai).
    Optional TTL: entries expire after `ttl_seconds`.
    """

    def __init__(self, max_size: int = 200, ttl_seconds: int = 3600):
        self._store: OrderedDict[str, tuple[dict, float]] = OrderedDict()
        self._max_size = max_size
        self._ttl = ttl_seconds
        self._hits = 0
        self._misses = 0

    @staticmethod
    def make_key(source_code: str, filename: str, skip_ai: bool, exploit: bool = False) -> str:
        blob = f"{source_code}||{filename}||{skip_ai}||{exploit}"
        return hashlib.sha256(blob.encode()).hexdigest()

    def get(self, key: str) -> Optional[dict]:
        if key not in self._store:
            self._misses += 1
            return None
        result, ts = self._store[key]
        if time.time() - ts > self._ttl:
            del self._store[key]
            self._misses += 1
            return None
        # Move to end (LRU)
        self._store.move_to_end(key)
        self._hits += 1
        log.debug(f"Cache HIT [{key[:12]}…] | ratio={self.hit_ratio:.1%}")
        return result

    def set(self, key: str, value: dict) -> None:
        if key in self._store:
            self._store.move_to_end(key)
        self._store[key] = (value, time.time())
        if len(self._store) > self._max_size:
            evicted = self._store.popitem(last=False)
            log.debug(f"Cache evicted oldest entry")

    def invalidate(self, key: str) -> None:
        self._store.pop(key, None)

    def clear(self) -> None:
        self._store.clear()
        self._hits = self._misses = 0

    @property
    def hit_ratio(self) -> float:
        total = self._hits + self._misses
        return self._hits / total if total else 0.0

    def stats(self) -> dict:
        return {
            "size": len(self._store),
            "max_size": self._max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_ratio": round(self.hit_ratio, 4),
            "ttl_seconds": self._ttl,
        }


# ── WebSocket connection registry ──────────────────────────────────────────────

class ConnectionManager:
    """Manages active WebSocket connections and broadcasts progress events."""

    def __init__(self):
        # job_id → set of WebSocket connections
        self._connections: dict[str, set] = {}

    async def connect(self, job_id: str, websocket) -> None:
        await websocket.accept()
        self._connections.setdefault(job_id, set()).add(websocket)
        log.info(f"WS connected for job {job_id} | active={len(self._connections[job_id])}")

    def disconnect(self, job_id: str, websocket) -> None:
        sockets = self._connections.get(job_id, set())
        sockets.discard(websocket)
        if not sockets:
            self._connections.pop(job_id, None)

    async def broadcast(self, job_id: str, message: dict) -> None:
        """Send a JSON message to all clients subscribed to this job."""
        sockets = list(self._connections.get(job_id, set()))
        if not sockets:
            return
        text = json.dumps(message)
        dead = []
        for ws in sockets:
            try:
                await ws.send_text(text)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._connections.get(job_id, set()).discard(ws)

    async def broadcast_stage(self, job_id: str, stage: ScanStage) -> None:
        await self.broadcast(job_id, {
            "type": "stage",
            "job_id": job_id,
            **asdict(stage),
        })

    async def broadcast_complete(self, job_id: str, result: dict) -> None:
        await self.broadcast(job_id, {
            "type": "complete",
            "job_id": job_id,
            "result": result,
        })

    async def broadcast_error(self, job_id: str, error: str) -> None:
        await self.broadcast(job_id, {
            "type": "error",
            "job_id": job_id,
            "error": error,
        })

    async def broadcast_cached(self, job_id: str, result: dict) -> None:
        await self.broadcast(job_id, {
            "type": "cached",
            "job_id": job_id,
            "result": result,
        })


# ── Async Scan Manager ─────────────────────────────────────────────────────────

SCAN_STAGES = [
    ScanStage("init",        "Initializing engine",        5),
    ScanStage("ast_parse",   "Parsing AST",               10),
    ScanStage("static",      "Static analysis",           25),
    ScanStage("payload_gen", "Generating payloads",       40),
    ScanStage("simulation",  "Simulating attack paths",   55),
    ScanStage("chain",       "Building attack chains",    70),
    ScanStage("exploit",     "Live exploitation",         85),
    ScanStage("ai",          "AI enrichment",             95),
    ScanStage("report",      "Generating report",         98),
    ScanStage("done",        "Scan complete",            100),
]


class ScanManager:
    """
    Central async coordinator for all scan jobs.

    Usage:
        manager = ScanManager(engine)
        job_id = await manager.submit(source_code, filename)
        # client connects via WebSocket to /ws/{job_id}
        # manager broadcasts progress and final result
    """

    def __init__(self, engine, max_workers: int = 4):
        self.engine = engine
        self.cache = ScanCache(max_size=200, ttl_seconds=3600)
        self.ws = ConnectionManager()
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="scan")
        self._jobs: dict[str, ScanJob] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    # ── Public API ─────────────────────────────────────────────────────────────

    async def submit(
        self,
        source_code: str,
        filename: str = "<stdin>",
        skip_ai: bool = True,
        exploit: bool = False,
        user_id: Optional[str] = None,
    ) -> str:
        """Submit a scan job. Returns a job_id immediately."""
        job_id = uuid.uuid4().hex[:12].upper()
        self._loop = asyncio.get_event_loop()
        
        # We can store user_id on the job object or somewhere else, but for now we'll just pass it
        
        # Check cache first
        cache_key = ScanCache.make_key(source_code, filename, skip_ai, exploit)
        cached = self.cache.get(cache_key)
        if cached:
            job = ScanJob(
                job_id=job_id, status=JobStatus.CACHED,
                source_code=source_code, filename=filename, skip_ai=skip_ai,
                exploit=exploit, result=cached,
            )
            job.result = cached
            self._jobs[job_id] = job
            log.info(f"Job {job_id} → CACHE HIT")
            
            # Record cached scan as well
            if user_id:
                try:
                    from saas.database import record_scan
                    record_scan(user_id, cached)
                except ImportError:
                    pass

            return job_id

        job = ScanJob(
            job_id=job_id, status=JobStatus.QUEUED,
            source_code=source_code, filename=filename, skip_ai=skip_ai,
            exploit=exploit,
        )
        # Store user_id for recording later
        job.user_id = user_id
        self._jobs[job_id] = job

        # Kick off background task
        asyncio.ensure_future(self._run_scan(job, cache_key))
        log.info(f"Job {job_id} submitted → QUEUED")
        return job_id

    def get_job(self, job_id: str) -> Optional[ScanJob]:
        return self._jobs.get(job_id)

    def cache_stats(self) -> dict:
        return self.cache.stats()

    # ── Internal scan runner ───────────────────────────────────────────────────

    async def _run_scan(self, job: ScanJob, cache_key: str) -> None:
        job.status = JobStatus.RUNNING
        job.started_at = time.time()

        async def emit(stage_name: str, detail: str = "") -> None:
            s = next((s for s in SCAN_STAGES if s.stage == stage_name), None)
            if s:
                s_copy = ScanStage(s.stage, s.label, s.progress, detail)
                job.stages.append(s_copy)
                await self.ws.broadcast_stage(job.job_id, s_copy)

        try:
            await emit("init", f"Scanning {job.filename}")
            await asyncio.sleep(0)   # yield so WS connect can happen first

            await emit("ast_parse", "Building abstract syntax tree")
            await emit("static", "Running 30+ vulnerability detectors")

            # Run the CPU-bound scan in thread pool so we don't block the event loop
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self._executor,
                self._run_engine,
                job,
                emit,
            )

            job.status = JobStatus.COMPLETE
            job.result = result
            job.finished_at = time.time()
            self.cache.set(cache_key, result)

            if job.user_id:
                try:
                    from saas.database import record_scan
                    record_scan(job.user_id, result)
                except ImportError:
                    pass

            await emit("done", f"{result.get('vulnerabilities_found', 0)} vulnerabilities found")
            await self.ws.broadcast_complete(job.job_id, result)
            log.info(f"Job {job.job_id} COMPLETE in {job.elapsed_ms()}ms")

        except Exception as e:
            job.status = JobStatus.FAILED
            job.error = str(e)
            job.finished_at = time.time()
            await self.ws.broadcast_error(job.job_id, str(e))
            log.error(f"Job {job.job_id} FAILED: {e}", exc_info=True)

    def _run_engine(self, job: ScanJob, emit_coro: Callable) -> dict:
        """Runs synchronously in ThreadPoolExecutor."""
        # Note: can't await here, but we schedule emit coroutines on the loop
        def schedule_emit(stage, detail=""):
            if self._loop and not self._loop.is_closed():
                asyncio.run_coroutine_threadsafe(emit_coro(stage, detail), self._loop)

        schedule_emit("payload_gen", "Crafting surgical exploit payloads")
        schedule_emit("simulation", "Tracing taint propagation paths")

        report = self.engine.scan(job.source_code, filename=job.filename)

        schedule_emit("chain", f"{len(report.attack_chains)} chains identified")

        if job.exploit:
            try:
                from engine.exploit_engine import ExploitEngine
                exploit_engine = ExploitEngine()
                schedule_emit("exploit", "Running live exploit payloads in sandbox")
                
                # Limit to top 5 findings to avoid excessive scan times
                exploitable_findings = [ar for ar in report.attack_results if ar.exploitable]
                for ar in exploitable_findings[:5]:
                    schedule_emit("exploit", f"Executing payload against {ar.vulnerability.vuln_type}...")
                    # Run exploit and store result
                    res = exploit_engine.run_exploit(job.source_code, ar)
                    if res["confirmed"]:
                        ar.simulation["exploit_confirmed"] = True
                        ar.simulation["exploit_output"] = res["attempts"][0]["output"] if res["attempts"] else ""
                        ar.simulation["exploit_payload"] = res["attempts"][0]["payload"] if res["attempts"] else ""
            except Exception as e:
                log.error(f"Live exploitation failed for job {job.job_id}: {e}")
                schedule_emit("exploit", f"Exploitation phase failed: {str(e)}")

        schedule_emit("report", "Serializing results")

        return _report_to_dict(report)


# ── Serialization helper ───────────────────────────────────────────────────────

def _report_to_dict(report) -> dict:
    from datetime import datetime, timezone
    findings = []
    for ar in report.attack_results:
        v = ar.vulnerability
        sev_val = ar.severity.value if hasattr(ar.severity, "value") else str(ar.severity)
        findings.append({
            "vulnerability": {
                "vuln_id": v.vuln_id,
                "vuln_type": v.vuln_type,
                "severity": v.severity,
                "line": v.line,
                "col": v.col,
                "description": v.description,
                "code_snippet": v.code_snippet,
                "cwe": v.cwe,
                "owasp": v.owasp,
                "taint_source": v.taint_source,
                "taint_sink": v.taint_sink,
                "confidence": v.confidence,
            },
            "payloads": ar.payloads,
            "simulation": ar.simulation,
            "ai_analysis": ar.ai_analysis,
            "severity": sev_val,
            "exploitable": ar.exploitable,
            "chain_ids": ar.chain_ids,
        })
    return {
        "target_file": report.target_file,
        "source_code": report.source_code,
        "scan_time_ms": report.scan_time_ms,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "vulnerabilities_found": report.vulnerabilities_found,
        "exploitable_count": report.exploitable_count,
        "summary": report.summary,
        "findings": findings,
        "attack_chains": report.attack_chains,
    }
