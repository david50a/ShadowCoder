"""
Architecture Mapper — discovers entry points, trust boundaries, and data flows
from Python source code via AST analysis.

Outputs an ArchitectureMap used by the MultiVectorEngine to:
  - Identify all surfaces where user input can enter the system
  - Detect where data crosses security trust boundaries
  - Build the initial nodes for the Attack Graph
"""

import ast
import re
from dataclasses import dataclass, field
from typing import Optional


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class EntryPoint:
    ep_id: str
    kind: str          # "http_route" | "cli_arg" | "file_io" | "socket" | "env_var" | "stdin"
    label: str         # Human-readable description
    line: int
    method: str = ""   # GET, POST, etc. for HTTP routes
    path: str = ""     # URL path for HTTP routes
    params: list[str] = field(default_factory=list)
    risk_level: str = "MEDIUM"  # LOW | MEDIUM | HIGH


@dataclass
class TrustBoundary:
    boundary_id: str
    kind: str          # "user_to_app" | "app_to_db" | "app_to_os" | "app_to_network" | "app_to_fs"
    label: str
    source_line: int
    sink_line: int
    crossing_point: str  # The function/call that crosses the boundary


@dataclass
class DataFlow:
    flow_id: str
    source_label: str
    source_line: int
    intermediate_steps: list[str]
    sink_label: str
    sink_line: int
    tainted: bool
    flow_type: str     # "sql" | "command" | "network" | "file" | "template" | "deserialize"


@dataclass
class Component:
    name: str
    kind: str          # "route_handler" | "db_layer" | "auth_layer" | "utility" | "config"
    imports: list[str]
    risk_score: float  # 0.0 – 10.0
    lines: tuple[int, int]


@dataclass
class ArchitectureMap:
    entry_points: list[EntryPoint]
    trust_boundaries: list[TrustBoundary]
    data_flows: list[DataFlow]
    components: list[Component]
    risk_surface_score: float   # 0.0 – 10.0
    summary: str


# ── AST Visitor ───────────────────────────────────────────────────────────────

# Frameworks whose decorators signal HTTP route entry points
_ROUTE_DECORATORS = {
    "app.route", "router.get", "router.post", "router.put", "router.delete",
    "router.patch", "app.get", "app.post", "app.put", "app.delete", "app.patch",
    "bp.route", "blueprint.route",
}

# Libraries that introduce trust boundary crossings
_DB_CALLS    = {"execute", "executemany", "find", "find_one", "insert", "update", "delete", "raw"}
_OS_CALLS    = {"system", "popen", "execve", "execvp", "spawnl", "call", "Popen", "run", "check_output"}
_NET_CALLS   = {"get", "post", "put", "urlopen", "urlretrieve", "request"}
_FS_CALLS    = {"open", "read", "write", "copy", "move", "unlink", "remove"}
_DESER_CALLS = {"loads", "load", "load_string", "from_string"}

# User-input sources
_INPUT_SOURCES = {
    "input", "sys.argv", "request.args", "request.form", "request.json",
    "request.data", "request.values", "os.environ", "environ.get",
    "getenv", "argparse", "click",
}


class _ArchVisitor(ast.NodeVisitor):
    def __init__(self, source_lines: list[str], filename: str):
        self.source_lines = source_lines
        self.filename = filename
        self.entry_points: list[EntryPoint] = []
        self.trust_boundaries: list[TrustBoundary] = []
        self.data_flows: list[DataFlow] = []
        self.components: list[Component] = []
        self._imports: dict[str, str] = {}
        self._ep_counter = 0
        self._tb_counter = 0
        self._df_counter = 0

    def _next_ep_id(self):
        self._ep_counter += 1
        return f"EP-{self._ep_counter:03d}"

    def _next_tb_id(self):
        self._tb_counter += 1
        return f"TB-{self._tb_counter:03d}"

    def _next_df_id(self):
        self._df_counter += 1
        return f"DF-{self._df_counter:03d}"

    # ── Import tracking ───────────────────────────────────────────────────────

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self._imports[alias.asname or alias.name.split(".")[0]] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = node.module or ""
        for alias in node.names:
            key = alias.asname or alias.name
            self._imports[key] = f"{mod}.{alias.name}"
        self.generic_visit(node)

    # ── Function definitions (route handlers / components) ─────────────────────

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Check for HTTP route decorators
        for dec in node.decorator_list:
            dec_str = ast.unparse(dec)
            route_path = ""
            route_method = "GET"

            if any(dec_str.startswith(d) for d in _ROUTE_DECORATORS):
                # Extract path from decorator args
                if isinstance(dec, ast.Call) and dec.args:
                    if isinstance(dec.args[0], ast.Constant):
                        route_path = str(dec.args[0].value)
                # Extract method from keywords
                for kw in (dec.keywords if isinstance(dec, ast.Call) else []):
                    if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                        methods = [
                            elt.value for elt in kw.value.elts
                            if isinstance(elt, ast.Constant)
                        ]
                        route_method = "/".join(methods) if methods else "GET"

                params = [a.arg for a in node.args.args if a.arg != "self"]
                risk = "HIGH" if any(m in route_method for m in ["POST", "PUT", "DELETE", "PATCH"]) else "MEDIUM"
                self.entry_points.append(EntryPoint(
                    ep_id=self._next_ep_id(),
                    kind="http_route",
                    label=f"{route_method} {route_path or '/' + node.name}",
                    line=node.lineno,
                    method=route_method,
                    path=route_path or f"/{node.name}",
                    params=params,
                    risk_level=risk,
                ))

        # Classify function as a component
        body_lines = (node.lineno, node.end_lineno or node.lineno)
        imports_used = [
            imp for imp in self._imports
            if imp in ast.unparse(node)
        ]
        risk = self._component_risk(node, imports_used)
        kind = self._component_kind(node, dec_str if node.decorator_list else "")
        self.components.append(Component(
            name=node.name,
            kind=kind,
            imports=imports_used,
            risk_score=risk,
            lines=body_lines,
        ))

        self.generic_visit(node)

    def _component_risk(self, node: ast.FunctionDef, imports: list[str]) -> float:
        score = 0.0
        src = ast.unparse(node)
        if any(d in src for d in ["execute", "executemany", "cursor"]):
            score += 3.0
        if any(d in src for d in ["system", "popen", "subprocess", "eval", "exec"]):
            score += 4.0
        if any(d in src for d in ["loads", "pickle", "yaml.load"]):
            score += 3.5
        if any(d in src for d in ["password", "secret", "token", "key"]):
            score += 1.5
        if "request" in src or "input(" in src:
            score += 1.0
        return min(score, 10.0)

    def _component_kind(self, node: ast.FunctionDef, dec_str: str) -> str:
        name = node.name.lower()
        src = ast.unparse(node).lower()
        if any(d in dec_str for d in _ROUTE_DECORATORS):
            return "route_handler"
        if any(kw in name for kw in ["auth", "login", "logout", "verify", "token", "session"]):
            return "auth_layer"
        if any(kw in name for kw in ["db", "query", "fetch", "insert", "update", "delete", "crud"]):
            return "db_layer"
        if any(kw in src for kw in ["db_password", "api_key", "secret_key", "environ"]):
            return "config"
        return "utility"

    # ── Call analysis (trust boundary + data flow tracking) ────────────────────

    def visit_Call(self, node: ast.Call):
        func_name = ""
        module_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        line = node.lineno
        args_src = " ".join(ast.unparse(a) for a in node.args)
        has_user_input = any(
            src in args_src for src in ["request", "input(", "sys.argv", "environ", "args", "form", "json"]
        )

        # ── Trust boundaries ──────────────────────────────────────────────────

        if func_name in _DB_CALLS:
            self.trust_boundaries.append(TrustBoundary(
                boundary_id=self._next_tb_id(),
                kind="app_to_db",
                label=f"App → Database via {func_name}()",
                source_line=line,
                sink_line=line,
                crossing_point=f"{module_name}.{func_name}" if module_name else func_name,
            ))
            if has_user_input:
                self.data_flows.append(DataFlow(
                    flow_id=self._next_df_id(),
                    source_label="User input",
                    source_line=line,
                    intermediate_steps=["String interpolation / concatenation"],
                    sink_label=f"Database query ({func_name})",
                    sink_line=line,
                    tainted=True,
                    flow_type="sql",
                ))

        elif func_name in _OS_CALLS:
            self.trust_boundaries.append(TrustBoundary(
                boundary_id=self._next_tb_id(),
                kind="app_to_os",
                label=f"App → OS via {func_name}()",
                source_line=line,
                sink_line=line,
                crossing_point=f"{module_name}.{func_name}" if module_name else func_name,
            ))
            if has_user_input:
                self.data_flows.append(DataFlow(
                    flow_id=self._next_df_id(),
                    source_label="User input",
                    source_line=line,
                    intermediate_steps=["f-string / concatenation"],
                    sink_label=f"OS shell command ({func_name})",
                    sink_line=line,
                    tainted=True,
                    flow_type="command",
                ))

        elif func_name in _NET_CALLS and module_name in ("requests", "urllib", "httpx", "urllib3"):
            self.trust_boundaries.append(TrustBoundary(
                boundary_id=self._next_tb_id(),
                kind="app_to_network",
                label=f"App → External Network via {module_name}.{func_name}()",
                source_line=line,
                sink_line=line,
                crossing_point=f"{module_name}.{func_name}",
            ))
            if has_user_input:
                self.data_flows.append(DataFlow(
                    flow_id=self._next_df_id(),
                    source_label="User-controlled URL",
                    source_line=line,
                    intermediate_steps=["URL passed directly"],
                    sink_label=f"External HTTP request ({module_name}.{func_name})",
                    sink_line=line,
                    tainted=True,
                    flow_type="network",
                ))

        elif func_name in _DESER_CALLS and module_name in ("pickle", "yaml", "marshal", "dill", "joblib"):
            self.trust_boundaries.append(TrustBoundary(
                boundary_id=self._next_tb_id(),
                kind="user_to_app",
                label=f"Untrusted Deserialization via {module_name}.{func_name}()",
                source_line=line,
                sink_line=line,
                crossing_point=f"{module_name}.{func_name}",
            ))

        elif func_name == "open" and has_user_input:
            self.trust_boundaries.append(TrustBoundary(
                boundary_id=self._next_tb_id(),
                kind="app_to_fs",
                label="App → Filesystem via open() with user path",
                source_line=line,
                sink_line=line,
                crossing_point="open()",
            ))
            self.data_flows.append(DataFlow(
                flow_id=self._next_df_id(),
                source_label="User-controlled filename",
                source_line=line,
                intermediate_steps=["Path passed directly"],
                sink_label="File system open()",
                sink_line=line,
                tainted=True,
                flow_type="file",
            ))

        # ── CLI / stdin entry points ───────────────────────────────────────────

        if func_name == "input" and not any(ep.kind == "stdin" for ep in self.entry_points):
            self.entry_points.append(EntryPoint(
                ep_id=self._next_ep_id(),
                kind="stdin",
                label="stdin via input()",
                line=line,
                risk_level="MEDIUM",
            ))

        if module_name == "sys" and func_name == "argv":
            if not any(ep.kind == "cli_arg" for ep in self.entry_points):
                self.entry_points.append(EntryPoint(
                    ep_id=self._next_ep_id(),
                    kind="cli_arg",
                    label="CLI arguments via sys.argv",
                    line=line,
                    risk_level="MEDIUM",
                ))

        self.generic_visit(node)

    # ── Env var entry points via regex scan ────────────────────────────────────

    def visit_Attribute(self, node: ast.Attribute):
        if (isinstance(node.value, ast.Name) and node.value.id == "environ"
                and node.attr == "get"):
            if not any(ep.kind == "env_var" for ep in self.entry_points):
                self.entry_points.append(EntryPoint(
                    ep_id=self._next_ep_id(),
                    kind="env_var",
                    label="Environment variables via os.environ",
                    line=node.col_offset,
                    risk_level="MEDIUM",
                ))
        self.generic_visit(node)


# ── Public API ─────────────────────────────────────────────────────────────────

class ArchitectureMapper:
    """Maps Python source code architecture: entry points, trust boundaries, data flows."""

    def map(self, source_code: str, filename: str = "<stdin>") -> ArchitectureMap:
        source_lines = source_code.splitlines()

        # Parse AST
        try:
            tree = ast.parse(source_code, filename=filename)
        except SyntaxError:
            return ArchitectureMap(
                entry_points=[], trust_boundaries=[], data_flows=[],
                components=[], risk_surface_score=0.0,
                summary="Source code could not be parsed.",
            )

        visitor = _ArchVisitor(source_lines, filename)
        visitor.visit(tree)

        # Also detect env-var reads via regex
        for m in re.finditer(r'os\.environ\.get\(|os\.getenv\(', source_code):
            lineno = source_code[: m.start()].count("\n") + 1
            if not any(ep.kind == "env_var" for ep in visitor.entry_points):
                visitor.entry_points.append(EntryPoint(
                    ep_id=visitor._next_ep_id(),
                    kind="env_var",
                    label="Environment variables via os.environ / os.getenv",
                    line=lineno,
                    risk_level="LOW",
                ))

        # Compute risk surface score
        score = _compute_risk_surface(visitor)

        # Build summary
        summary = _build_summary(visitor, score)

        return ArchitectureMap(
            entry_points=visitor.entry_points,
            trust_boundaries=visitor.trust_boundaries,
            data_flows=visitor.data_flows,
            components=sorted(visitor.components, key=lambda c: -c.risk_score),
            risk_surface_score=round(score, 2),
            summary=summary,
        )


def _compute_risk_surface(visitor: _ArchVisitor) -> float:
    """Aggregate risk score: more entry points + tainted flows = higher surface."""
    score = 0.0
    score += len(visitor.entry_points) * 0.5
    score += len([tb for tb in visitor.trust_boundaries if tb.kind == "app_to_os"]) * 2.0
    score += len([tb for tb in visitor.trust_boundaries if tb.kind == "app_to_db"]) * 1.5
    score += len([df for df in visitor.data_flows if df.tainted]) * 1.5
    high_risk_comps = sum(1 for c in visitor.components if c.risk_score >= 5.0)
    score += high_risk_comps * 1.0
    return min(score, 10.0)


def _build_summary(visitor: _ArchVisitor, score: float) -> str:
    parts = []
    n_ep = len(visitor.entry_points)
    n_tb = len(visitor.trust_boundaries)
    n_df = len([df for df in visitor.data_flows if df.tainted])

    ep_kinds = list({ep.kind for ep in visitor.entry_points})
    parts.append(f"{n_ep} entry point(s) detected ({', '.join(ep_kinds) or 'none'}).")
    parts.append(f"{n_tb} trust boundary crossing(s) found.")
    parts.append(f"{n_df} tainted data flow(s) identified.")
    parts.append(f"Attack surface score: {score:.1f}/10.")

    if score >= 7.0:
        parts.append("⚠ HIGH attack surface — multiple tainted flows reaching dangerous sinks.")
    elif score >= 4.0:
        parts.append("⚠ MEDIUM attack surface — some user-controlled paths to sensitive operations.")
    else:
        parts.append("✓ LOW attack surface in this file.")

    return " ".join(parts)


def arch_map_to_dict(arch: ArchitectureMap) -> dict:
    """Serialize ArchitectureMap to JSON-compatible dict."""
    return {
        "entry_points": [
            {
                "ep_id": ep.ep_id, "kind": ep.kind, "label": ep.label,
                "line": ep.line, "method": ep.method, "path": ep.path,
                "params": ep.params, "risk_level": ep.risk_level,
            }
            for ep in arch.entry_points
        ],
        "trust_boundaries": [
            {
                "boundary_id": tb.boundary_id, "kind": tb.kind,
                "label": tb.label, "source_line": tb.source_line,
                "sink_line": tb.sink_line, "crossing_point": tb.crossing_point,
            }
            for tb in arch.trust_boundaries
        ],
        "data_flows": [
            {
                "flow_id": df.flow_id, "source_label": df.source_label,
                "source_line": df.source_line,
                "intermediate_steps": df.intermediate_steps,
                "sink_label": df.sink_label, "sink_line": df.sink_line,
                "tainted": df.tainted, "flow_type": df.flow_type,
            }
            for df in arch.data_flows
        ],
        "components": [
            {
                "name": c.name, "kind": c.kind, "imports": c.imports,
                "risk_score": c.risk_score, "lines": list(c.lines),
            }
            for c in arch.components
        ],
        "risk_surface_score": arch.risk_surface_score,
        "summary": arch.summary,
    }
