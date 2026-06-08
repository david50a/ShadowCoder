import re
import urllib.parse
import requests
from html.parser import HTMLParser
from typing import Set, Dict, List, Tuple

class LinkAndFormParser(HTMLParser):
    """
    Parses HTML to extract links, forms, query params, and upload fields.
    """
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: Set[str] = set()
        self.forms: List[Dict] = []
        self.current_form: Dict = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str]]):
        attrs_dict = dict(attrs)
        
        # Extract links
        if tag == "a":
            href = attrs_dict.get("href")
            if href:
                # Remove fragment
                href = href.split("#")[0].strip()
                if href:
                    absolute_url = urllib.parse.urljoin(self.base_url, href)
                    self.links.add(absolute_url)

        # Extract forms
        elif tag == "form":
            action = attrs_dict.get("action", "")
            method = attrs_dict.get("method", "get").lower()
            enctype = attrs_dict.get("enctype", "")
            absolute_action = urllib.parse.urljoin(self.base_url, action)
            self.current_form = {
                "action": absolute_action,
                "method": method,
                "enctype": enctype,
                "fields": [],
                "has_file_upload": "multipart/form-data" in enctype
            }

        # Extract form fields
        elif tag == "input" and self.current_form is not None:
            name = attrs_dict.get("name")
            field_type = attrs_dict.get("type", "text").lower()
            if name:
                self.current_form["fields"].append({
                    "name": name,
                    "type": field_type
                })
                if field_type == "file":
                    self.current_form["has_file_upload"] = True

        elif tag in ("textarea", "select") and self.current_form is not None:
            name = attrs_dict.get("name")
            if name:
                self.current_form["fields"].append({
                    "name": name,
                    "type": tag
                })

    def handle_endtag(self, tag: str):
        if tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None


class LocalhostDiscoveryEngine:
    """
    Target Discovery Module.
    Fetches the homepage and recursively crawls pages within the target domain.
    """
    def __init__(self, max_depth: int = 3, max_pages: int = 50):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited_urls: Set[str] = set()

    def discover(self, start_url: str) -> Dict[str, List[str]]:
        """
        Crawls the target site and builds a basic site map.
        Output format matching requirements:
        {
          "pages": ["/", "/login", "/dashboard"],
          "forms": ["/login"]
        }
        """
        self.visited_urls.clear()
        parsed_start = urllib.parse.urlparse(start_url)
        target_netloc = parsed_start.netloc

        pages: Set[str] = set()
        forms: Set[str] = set()
        queue: List[Tuple[str, int]] = [(start_url, 0)]

        session = requests.Session()
        session.headers.update({"User-Agent": "ShadowCoder-DiscoveryEngine/2.0"})

        while queue and len(self.visited_urls) < self.max_pages:
            url, depth = queue.pop(0)

            # Normalize URL to avoid duplicates (e.g. trailing slash / vs no trailing slash)
            parsed_url = urllib.parse.urlparse(url)
            normalized_url = urllib.parse.urlunparse(
                (parsed_url.scheme, parsed_url.netloc, parsed_url.path, '', parsed_url.query, '')
            )

            if normalized_url in self.visited_urls:
                continue

            self.visited_urls.add(normalized_url)

            # Record page path relative to root
            path = parsed_url.path if parsed_url.path else "/"
            pages.add(path)

            if depth >= self.max_depth:
                continue

            try:
                # Use a timeout to prevent hanging on slow pages
                response = session.get(url, timeout=5.0, allow_redirects=True)
                
                # Check redirects
                if response.history:
                    for redirect_resp in response.history:
                        redir_parsed = urllib.parse.urlparse(redirect_resp.url)
                        if redir_parsed.netloc == target_netloc:
                            pages.add(redir_parsed.path if redir_parsed.path else "/")

                final_parsed = urllib.parse.urlparse(response.url)
                if final_parsed.netloc != target_netloc:
                    # Redirected out of target domain, don't crawl
                    continue

                if "text/html" not in response.headers.get("Content-Type", "").lower():
                    continue

                # Parse the HTML content
                parser = LinkAndFormParser(response.url)
                parser.feed(response.text)

                # Record any forms found
                for form in parser.forms:
                    form_url = urllib.parse.urlparse(form["action"])
                    if form_url.netloc == target_netloc or not form_url.netloc:
                        forms.add(form_url.path if form_url.path else "/")

                # Add new links to queue
                for link in parser.links:
                    link_parsed = urllib.parse.urlparse(link)
                    if link_parsed.netloc == target_netloc:
                        # Strip query and fragment for crawling queue, keeping it for exploration
                        clean_link = urllib.parse.urlunparse(
                            (link_parsed.scheme, link_parsed.netloc, link_parsed.path, '', '', '')
                        )
                        if clean_link not in self.visited_urls:
                            queue.append((link, depth + 1))

            except Exception as e:
                # Silently ignore connection errors during crawl
                pass

        # Sort lists for stable outputs
        return {
            "pages": sorted(list(pages)),
            "forms": sorted(list(forms))
        }


class AttackSurfaceMapper:
    """
    Attack Surface Mapper.
    Tracks forms, query parameters, cookies, authentication pages, upload endpoints.
    Creates an internal navigation graph.
    """
    def __init__(self):
        pass

    def map_surface(self, start_url: str, discovery_results: Dict[str, List[str]]) -> Dict:
        """
        Gathers details on forms, query parameters, cookies, authentication pages, upload endpoints.
        Constructs an internal graph representation:
        {
          "forms": [{"action": "/login", "method": "post", "fields": [...], "has_file_upload": false}],
          "query_parameters": {"/search": ["q", "limit"]},
          "cookies": [{"name": "session", "http_only": true, "secure": false}],
          "authentication_pages": ["/login"],
          "upload_endpoints": ["/upload"],
          "graph": {
             "nodes": [{"id": "/", "label": "Homepage"}, ...],
             "edges": [{"from": "/", "to": "/login"}, ...]
          }
        }
        """
        parsed_start = urllib.parse.urlparse(start_url)
        target_netloc = parsed_start.netloc
        target_scheme = parsed_start.scheme

        forms_detail = []
        query_params = {}
        cookies_found = []
        auth_pages = []
        upload_endpoints = []
        edges = set()
        nodes = {}

        session = requests.Session()
        session.headers.update({"User-Agent": "ShadowCoder-AttackSurfaceMapper/2.0"})

        # Crawl again specifically to capture all request/response details
        # and build mapping metadata. We can limit this to the pages list from discovery.
        for path in discovery_results.get("pages", ["/"]):
            url = f"{target_scheme}://{target_netloc}{path}"
            
            # Map node
            label = "Homepage" if path == "/" else path.lstrip("/").capitalize()
            nodes[path] = {"id": path, "label": label}

            try:
                response = session.get(url, timeout=3.0)
                
                # Check for cookies in response
                for cookie in response.cookies:
                    # Note: Requests CookieJar doesn't expose httpOnly flag directly in standard api
                    # but we can look at the raw Set-Cookie headers
                    cookie_meta = {
                        "name": cookie.name,
                        "value": cookie.value,
                        "domain": cookie.domain,
                        "path": cookie.path,
                        "http_only": False,
                        "secure": cookie.secure
                    }
                    # Parse raw headers for HttpOnly
                    for header, val in response.raw.headers.items():
                        if header.lower() == 'set-cookie' and cookie.name in val:
                            if 'httponly' in val.lower():
                                cookie_meta["http_only"] = True
                            if 'secure' in val.lower():
                                cookie_meta["secure"] = True
                    
                    if cookie_meta not in cookies_found:
                        cookies_found.append(cookie_meta)

                # Check if this is an authentication page
                # Path matching or page containing login/register form
                path_lower = path.lower()
                is_auth = False
                if any(x in path_lower for x in ("login", "signin", "register", "signup", "auth")):
                    is_auth = True
                    if path not in auth_pages:
                        auth_pages.append(path)

                if "text/html" in response.headers.get("Content-Type", "").lower():
                    parser = LinkAndFormParser(response.url)
                    parser.feed(response.text)

                    # Extract form details
                    for form in parser.forms:
                        form_url = urllib.parse.urlparse(form["action"])
                        # Get action relative path
                        form_path = form_url.path if form_url.path else "/"
                        
                        detail = {
                            "action": form_path,
                            "method": form["method"],
                            "fields": form["fields"],
                            "has_file_upload": form["has_file_upload"]
                        }
                        if detail not in forms_detail:
                            forms_detail.append(detail)
                        
                        # If form contains password field, mark it as auth page
                        if any(f["type"] == "password" for f in form["fields"]):
                            is_auth = True
                            if path not in auth_pages:
                                auth_pages.append(path)

                        # Check if this form is an upload endpoint
                        if form["has_file_upload"] or "upload" in form_path.lower():
                            if form_path not in upload_endpoints:
                                upload_endpoints.append(form_path)

                        # Add form submission edge to graph
                        edges.add((path, form_path))

                    # Parse links and add edges
                    for link in parser.links:
                        link_url = urllib.parse.urlparse(link)
                        if link_url.netloc == target_netloc:
                            link_path = link_url.path if link_url.path else "/"
                            edges.add((path, link_path))

                            # Extract query parameters
                            if link_url.query:
                                params = urllib.parse.parse_qs(link_url.query)
                                if link_path not in query_params:
                                    query_params[link_path] = []
                                for p in params.keys():
                                    if p not in query_params[link_path]:
                                        query_params[link_path].append(p)

                # Also double check upload paths
                if "upload" in path_lower:
                    if path not in upload_endpoints:
                        upload_endpoints.append(path)

            except Exception:
                pass

        # Format graph nodes and edges
        graph_nodes = []
        for path, node in nodes.items():
            # Add roles/tags to nodes
            group = "page"
            if path == "/":
                group = "entry"
            elif path in auth_pages:
                group = "auth"
            elif path in upload_endpoints:
                group = "upload"
            
            node["group"] = group
            graph_nodes.append(node)

        graph_edges = [{"from": f, "to": t} for f, t in edges if f in nodes and t in nodes]

        return {
            "forms": forms_detail,
            "query_parameters": query_params,
            "cookies": cookies_found,
            "authentication_pages": auth_pages,
            "upload_endpoints": upload_endpoints,
            "graph": {
                "nodes": graph_nodes,
                "edges": graph_edges
            }
        }
