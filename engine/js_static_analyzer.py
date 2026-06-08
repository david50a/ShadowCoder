import uuid
from typing import List

from tree_sitter import Language, Parser
import tree_sitter_javascript as tsjs

from .static_analyzer import Vulnerability

JS_LANGUAGE = Language(tsjs.language())

class JsStaticAnalyzer:
    """
    Static Code Analyzer — AST-based vulnerability detection for JavaScript/Node.js.
    """
    def __init__(self):
        self.parser = Parser(JS_LANGUAGE)
        
    def analyze(self, source_code: str) -> List[Vulnerability]:
        try:
            tree = self.parser.parse(bytes(source_code, "utf8"))
        except Exception:
            # Fallback if parsing fails entirely
            return []
            
        vulns = []
        lines = source_code.splitlines()
        
        def get_snippet(node):
            if node.start_point[0] < len(lines):
                return lines[node.start_point[0]].strip()
            return ""

        def traverse(node):
            # Check function calls
            if node.type == "call_expression":
                func_node = node.child_by_field_name("function")
                if func_node:
                    # eval()
                    if func_node.type == "identifier" and func_node.text.decode('utf8') == "eval":
                        vulns.append(Vulnerability(
                            vuln_id=f"VULN-{uuid.uuid4().hex[:8]}",
                            vuln_type="Code Injection (eval)",
                            severity="CRITICAL",
                            line=node.start_point[0] + 1,
                            col=node.start_point[1] + 1,
                            description="eval() executes arbitrary JavaScript code from user input — full RCE risk",
                            code_snippet=get_snippet(node),
                            cwe="CWE-94",
                            owasp="A03"
                        ))
                    
                    # child_process.exec() or spawn()
                    if func_node.type == "member_expression":
                        prop_node = func_node.child_by_field_name("property")
                        if prop_node:
                            prop_text = prop_node.text.decode('utf8')
                            if prop_text in ("exec", "spawn"):
                                vulns.append(Vulnerability(
                                    vuln_id=f"VULN-{uuid.uuid4().hex[:8]}",
                                    vuln_type="Command Injection (child_process)",
                                    severity="CRITICAL",
                                    line=node.start_point[0] + 1,
                                    col=node.start_point[1] + 1,
                                    description="child_process methods pass unsanitized commands to the shell — full RCE",
                                    code_snippet=get_snippet(node),
                                    cwe="CWE-78",
                                    owasp="A03"
                                ))
            
            # Check for SQL injection (Template string with vars, or string concat)
            if node.type in ("template_string", "binary_expression"):
                try:
                    text = node.text.decode('utf8').lower()
                    # VERY rudimentary check for SQLi
                    is_sql = False
                    for kw in ("select ", "update ", "delete ", "insert "):
                        if kw in text:
                            is_sql = True
                            break
                    
                    if is_sql:
                        if (node.type == "template_string" and "${" in node.text.decode('utf8')) or \
                           (node.type == "binary_expression" and node.child_by_field_name("operator") and node.child_by_field_name("operator").text.decode('utf8') == "+"):
                            vulns.append(Vulnerability(
                                vuln_id=f"VULN-{uuid.uuid4().hex[:8]}",
                                vuln_type="SQL Injection",
                                severity="CRITICAL",
                                line=node.start_point[0] + 1,
                                col=node.start_point[1] + 1,
                                description="SQL query built with string concatenation or template literals — SQLi risk",
                                code_snippet=get_snippet(node),
                                cwe="CWE-89",
                                owasp="A03"
                            ))
                except Exception:
                    pass

            for child in node.children:
                traverse(child)
                
        traverse(tree.root_node)
        
        # Simple deduplication by line/vuln_type
        seen = set()
        deduped = []
        for v in vulns:
            key = (v.line, v.vuln_type)
            if key not in seen:
                seen.add(key)
                deduped.append(v)
                
        return deduped
