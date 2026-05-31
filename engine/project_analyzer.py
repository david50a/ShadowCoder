"""
ShadowCoder — Project-Wide Analyzer (Phase 6)

Analyzes an entire codebase, not just a single file.

Provides:
  - File dependency graph  (imports between modules)
  - Endpoint mapper        (FastAPI/Flask/Django routes)
  - Data flow tracker      (user input → API → DB → output)
  - Cross-file taint       (taint that crosses module boundaries)
  - Security surface map   (all entry points + their risk score)
"""

import ast
import os
import re
import uuid
import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger("shadowcoder.project_analyzer")

# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class Endpoint:
    path: str               # e.g. "/api/users/{id}"
    method: str             # GET | POST | PUT | DELETE | ANY
    handler: str            # function name
    file: str               # source file
    line: int
    params: list[str]       # path/query params
    risk_score: int         # 0-100
    risk_reasons: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)  # functions called in handler


@dataclass
class DataFlowPath:
    path_id: str
    description: str
    stages: list[dict]      # {stage, detail, file, line}
    risk: str               # LOW | MEDIUM | HIGH | CRITICAL
    involves_db: bool
    involves_network: bool
    involves_file_io: bool


@dataclass
class FileDependency:
    source_file: str
    imports: list[str]      # what this file imports
    imported_by: list[str]  # what files import this
    exports: list[str]      # public functions/classes


@dataclass
class ProjectReport:
    project_root: str
    files_analyzed: int
    total_lines: int
    endpoints: list[Endpoint]
    data_flows: list[DataFlowPath]
    dependencies: list[FileDependency]
    security_surface: dict  # summary stats
    cross_file_taints: list[dict]


# ── Endpoint detection patterns ───────────────────────────────────────────────

FRAMEWORK_PATTERNS = {
    "fastapi": [
        r'@\w+\.(get|post|put|delete|patch|options|head)\s*\(\s*["\']([^"\']+)["\']',
        r'@app\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        r'@router\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
    ],
    "flask": [
        r'@\w+\.route\s*\(\s*["\']([^"\']+)["\'](?:.*?methods\s*=\s*\[([^\]]+)\])?',
        r'@app\.route\s*\(\s*["\']([^"\']+)["\']',
    ],
    "django": [
        r'path\s*\(\s*["\']([^"\']+)["\']',
        r'url\s*\(\s*r?["\']([^"\']+)["\']',
        r're_path\s*\(\s*r?["\']([^"\']+)["\']',
    ],
}

SINK_CALLS = {
    # DB operations
    "execute", "executemany", "query", "find", "find_one", "filter", "get",
    # OS / command
    "system", "popen", "Popen", "run", "call", "spawn",
    # File I/O
    "open", "write", "read", "copyfile", "move",
    # Network
    "requests.get", "requests.post", "urlopen", "fetch",
    # Dangerous
    "eval", "exec", "loads", "load",
    # Rendering / response
    "render", "render_template", "jsonify", "Response",
}

USER_INPUT_PATTERNS = {
    # FastAPI / Starlette
    r"request\.query_params", r"request\.body", r"request\.json",
    r"request\.form", r"request\.path_params",
    # Flask
    r"request\.args", r"request\.form", r"request\.get_json",
    r"request\.data", r"request\.values",
    # Django
    r"request\.GET", r"request\.POST", r"request\.data",
    # General
    r"\binput\s*\(", r"sys\.stdin",
}


class ProjectAnalyzer:
    """
    Analyzes an entire Python project directory.
    """

    def __init__(self):
        self._file_asts: dict[str, ast.Module] = {}
        self._file_sources: dict[str, str] = {}

    def analyze(self, project_root: str, max_files: int = 100) -> ProjectReport:
        root = Path(project_root)
        if not root.exists():
            raise FileNotFoundError(f"Project root not found: {project_root}")

        py_files = self._discover_files(root, max_files)
        log.info(f"Project analyzer: {len(py_files)} Python files found")

        # Parse all files
        total_lines = 0
        for f in py_files:
            try:
                source = f.read_text(encoding="utf-8", errors="replace")
                self._file_sources[str(f)] = source
                total_lines += source.count("\n")
                tree = ast.parse(source, filename=str(f))
                self._file_asts[str(f)] = tree
            except Exception as e:
                log.debug(f"Could not parse {f}: {e}")

        # Run all analysis phases
        endpoints  = self._map_endpoints(py_files)
        deps       = self._build_dependency_graph(py_files)
        flows      = self._trace_data_flows(py_files, endpoints)
        cross_taint = self._detect_cross_file_taint(deps)
        surface    = self._compute_surface(endpoints, flows, cross_taint)

        return ProjectReport(
            project_root=str(root),
            files_analyzed=len(py_files),
            total_lines=total_lines,
            endpoints=endpoints,
            data_flows=flows,
            dependencies=deps,
            security_surface=surface,
            cross_file_taints=cross_taint,
        )

    # ── File discovery ─────────────────────────────────────────────────────────

    def _discover_files(self, root: Path, max_files: int) -> list[Path]:
        skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                     "site-packages", "dist", "build", "restored_engine"}
        files = []
        for f in root.rglob("*.py"):
            if any(p in f.parts for p in skip_dirs):
                continue
            files.append(f)
            if len(files) >= max_files:
                break
        return files

    # ── Endpoint mapping ───────────────────────────────────────────────────────

    def _map_endpoints(self, py_files: list[Path]) -> list[Endpoint]:
        endpoints = []
        for f in py_files:
            source = self._file_sources.get(str(f), "")
            tree = self._file_asts.get(str(f))
            if not tree:
                continue
            endpoints.extend(self._extract_endpoints_from_file(source, tree, str(f)))
        return sorted(endpoints, key=lambda e: -e.risk_score)

    def _extract_endpoints_from_file(self, source: str, tree: ast.Module, filepath: str) -> list[Endpoint]:
        endpoints = []
        lines = source.splitlines()

        # FastAPI / Flask decorator detection
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for decorator in node.decorator_list:
                route_info = self._parse_route_decorator(decorator, source)
                if route_info:
                    path, method = route_info
                    params = self._extract_path_params(path)
                    calls = self._extract_calls_in_func(node)
                    risk_score, risk_reasons = self._score_endpoint_risk(node, calls, params)
                    endpoints.append(Endpoint(
                        path=path, method=method.upper(),
                        handler=node.name, file=filepath,
                        line=node.lineno, params=params,
                        risk_score=risk_score, risk_reasons=risk_reasons,
                        calls=calls[:10],
                    ))

        # Django urls.py pattern
        if "urls.py" in filepath or "url_patterns" in source:
            django_eps = self._extract_django_urls(source, filepath)
            endpoints.extend(django_eps)

        return endpoints

    def _parse_route_decorator(self, decorator: ast.AST, source: str) -> Optional[tuple[str, str]]:
        """Extract (path, method) from a route decorator."""
        # @app.get("/path") or @router.post("/path")
        if isinstance(decorator, ast.Call):
            func = decorator.func
            if isinstance(func, ast.Attribute):
                method = func.attr.lower()
                if method in ("get", "post", "put", "delete", "patch", "route", "options"):
                    args = decorator.args
                    if args and isinstance(args[0], ast.Constant):
                        route_method = method if method != "route" else "ANY"
                        return (str(args[0].value), route_method)
        return None

    def _extract_path_params(self, path: str) -> list[str]:
        """Extract {param} and <param> style path parameters."""
        params = re.findall(r'\{(\w+)\}|<(?:int:|str:|float:)?(\w+)>', path)
        return [p[0] or p[1] for p in params if p[0] or p[1]]

    def _extract_calls_in_func(self, func_node: ast.FunctionDef) -> list[str]:
        calls = []
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                name = ""
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                if name:
                    calls.append(name)
        return list(dict.fromkeys(calls))  # deduplicate, preserve order

    def _score_endpoint_risk(self, func_node: ast.FunctionDef, calls: list[str], params: list[str]) -> tuple[int, list[str]]:
        score = 0
        reasons = []

        # Has path parameters → user-controlled input
        if params:
            score += 20
            reasons.append(f"Accepts path params: {params}")

        # Calls dangerous sinks
        dangerous = [c for c in calls if c in SINK_CALLS]
        if dangerous:
            score += min(len(dangerous) * 15, 50)
            reasons.append(f"Calls: {', '.join(dangerous[:5])}")

        # Unauthenticated POST/DELETE
        func_src = ast.unparse(func_node)
        if "auth" not in func_src.lower() and "token" not in func_src.lower():
            score += 15
            reasons.append("No auth check detected")

        # Directly returns DB results
        if any(c in calls for c in ("fetchone", "fetchall", "find", "filter")):
            score += 10
            reasons.append("Directly exposes DB results")

        return min(score, 100), reasons

    def _extract_django_urls(self, source: str, filepath: str) -> list[Endpoint]:
        endpoints = []
        for pattern in FRAMEWORK_PATTERNS["django"]:
            for m in re.finditer(pattern, source):
                lineno = source[:m.start()].count("\n") + 1
                endpoints.append(Endpoint(
                    path="/" + m.group(1).lstrip("/"),
                    method="ANY", handler="unknown",
                    file=filepath, line=lineno,
                    params=[], risk_score=30,
                    risk_reasons=["Django URL pattern — manual review needed"],
                ))
        return endpoints

    # ── Dependency graph ───────────────────────────────────────────────────────

    def _build_dependency_graph(self, py_files: list[Path]) -> list[FileDependency]:
        file_names = {f.stem: str(f) for f in py_files}
        deps = []

        for f in py_files:
            tree = self._file_asts.get(str(f))
            if not tree:
                continue

            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append(node.module)

            # Collect exports (top-level public functions/classes)
            exports = []
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if not node.name.startswith("_"):
                        exports.append(node.name)

            deps.append(FileDependency(
                source_file=str(f),
                imports=list(dict.fromkeys(imports)),
                imported_by=[],  # filled below
                exports=exports,
            ))

        # Fill imported_by
        for dep in deps:
            for other in deps:
                if dep.source_file == other.source_file:
                    continue
                short = Path(dep.source_file).stem
                if any(short in imp or imp.endswith(short) for imp in other.imports):
                    dep.imported_by.append(other.source_file)

        return deps

    # ── Data flow tracing ──────────────────────────────────────────────────────

    def _trace_data_flows(self, py_files: list[Path], endpoints: list[Endpoint]) -> list[DataFlowPath]:
        flows = []
        for ep in endpoints[:20]:  # limit to avoid explosion
            flow = self._trace_endpoint_flow(ep, py_files)
            if flow:
                flows.append(flow)
        return flows

    def _trace_endpoint_flow(self, endpoint: Endpoint, py_files: list[Path]) -> Optional[DataFlowPath]:
        stages = []
        involves_db = any(c in endpoint.calls for c in ("execute", "query", "find", "filter", "fetchone", "fetchall", "get"))
        involves_network = any(c in endpoint.calls for c in ("get", "post", "urlopen", "fetch", "requests"))
        involves_file = any(c in endpoint.calls for c in ("open", "write", "read", "copyfile"))

        # Stage 1: User input entry point
        stages.append({
            "stage": "USER_INPUT",
            "detail": f"HTTP {endpoint.method} {endpoint.path}" + (f" with params: {endpoint.params}" if endpoint.params else ""),
            "file": endpoint.file,
            "line": endpoint.line,
        })

        # Stage 2: API handler
        stages.append({
            "stage": "API_HANDLER",
            "detail": f"Handler: {endpoint.handler}()",
            "file": endpoint.file,
            "line": endpoint.line,
        })

        # Stage 3: Business logic / sink calls
        for call in endpoint.calls[:5]:
            if call in SINK_CALLS:
                stage_type = "DB_QUERY" if call in ("execute", "query", "find", "filter") else \
                             "FILE_IO" if call in ("open", "write", "read") else \
                             "NETWORK" if call in ("get", "post", "urlopen") else \
                             "DANGEROUS_CALL"
                stages.append({
                    "stage": stage_type,
                    "detail": f"Calls: {call}()",
                    "file": endpoint.file,
                    "line": endpoint.line,
                })

        # Stage 4: Response
        stages.append({
            "stage": "RESPONSE",
            "detail": f"Returns response to client",
            "file": endpoint.file,
            "line": endpoint.line,
        })

        if len(stages) < 2:
            return None

        risk = "HIGH" if endpoint.risk_score >= 60 else "MEDIUM" if endpoint.risk_score >= 30 else "LOW"

        return DataFlowPath(
            path_id=f"FLOW-{hashlib.md5(endpoint.path.encode()).hexdigest()[:6].upper()}",
            description=f"{endpoint.method} {endpoint.path} → {endpoint.handler}()",
            stages=stages,
            risk=risk,
            involves_db=involves_db,
            involves_network=involves_network,
            involves_file_io=involves_file,
        )

    # ── Cross-file taint ───────────────────────────────────────────────────────

    def _detect_cross_file_taint(self, deps: list[FileDependency]) -> list[dict]:
        """Detect functions that accept tainted data and are imported elsewhere."""
        taints = []
        for dep in deps:
            source = self._file_sources.get(dep.source_file, "")
            has_user_input = any(re.search(p, source) for p in USER_INPUT_PATTERNS)
            if has_user_input and dep.imported_by:
                taints.append({
                    "taint_id": f"XT-{hashlib.md5(dep.source_file.encode()).hexdigest()[:6].upper()}",
                    "source_file": dep.source_file,
                    "imported_by": dep.imported_by,
                    "exports": dep.exports[:5],
                    "risk": "HIGH",
                    "description": f"{Path(dep.source_file).name} processes user input and is imported by {len(dep.imported_by)} module(s) — tainted data may flow cross-file",
                })
        return taints

    # ── Security surface summary ───────────────────────────────────────────────

    def _compute_surface(self, endpoints, flows, cross_taint) -> dict:
        critical_eps = [e for e in endpoints if e.risk_score >= 70]
        db_flows = [f for f in flows if f.involves_db]
        network_flows = [f for f in flows if f.involves_network]

        return {
            "total_endpoints": len(endpoints),
            "high_risk_endpoints": len(critical_eps),
            "data_flows": len(flows),
            "db_touching_flows": len(db_flows),
            "network_touching_flows": len(network_flows),
            "cross_file_taints": len(cross_taint),
            "attack_surface_score": min(
                len(critical_eps) * 10 + len(cross_taint) * 15 + len(db_flows) * 5, 100
            ),
            "highest_risk_endpoint": endpoints[0].path if endpoints else None,
        }


# ── Serialization helpers ─────────────────────────────────────────────────────

def project_report_to_dict(report: ProjectReport) -> dict:
    from dataclasses import asdict
    return {
        "project_root": report.project_root,
        "files_analyzed": report.files_analyzed,
        "total_lines": report.total_lines,
        "security_surface": report.security_surface,
        "endpoints": [
            {
                "path": e.path, "method": e.method, "handler": e.handler,
                "file": e.file, "line": e.line, "params": e.params,
                "risk_score": e.risk_score, "risk_reasons": e.risk_reasons,
                "calls": e.calls,
            }
            for e in report.endpoints
        ],
        "data_flows": [
            {
                "path_id": f.path_id, "description": f.description,
                "stages": f.stages, "risk": f.risk,
                "involves_db": f.involves_db,
                "involves_network": f.involves_network,
                "involves_file_io": f.involves_file_io,
            }
            for f in report.data_flows
        ],
        "dependencies": [
            {
                "source_file": d.source_file,
                "imports": d.imports[:15],
                "imported_by": d.imported_by,
                "exports": d.exports[:10],
            }
            for d in report.dependencies
        ],
        "cross_file_taints": report.cross_file_taints,
    }
