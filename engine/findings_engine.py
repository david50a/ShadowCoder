import uuid
from typing import Dict, List

class FindingsEngine:
    """
    Findings Engine.
    Standardizes security testing results into a uniform schema.
    """
    def __init__(self):
        pass

    def standardize(self, raw_findings: List[Dict]) -> List[Dict]:
        """
        Structures and deduplicates findings conforming to:
        {
          "id": "UUID",
          "title": "Vulnerability Title",
          "severity": "Critical" | "High" | "Medium" | "Low",
          "endpoint": "/endpoint-path",
          "description": "Details...",
          "recommendation": "Fix steps..."
        }
        """
        standardized = []
        seen = set()

        for raw in raw_findings:
            title = raw.get("title", "Potential Vulnerability")
            endpoint = raw.get("endpoint", "/")
            severity = raw.get("severity", "Medium")
            description = raw.get("description", "")
            recommendation = raw.get("recommendation", "")
            
            # Deduplicate by title + endpoint
            dup_key = (title, endpoint)
            if dup_key in seen:
                continue
            seen.add(dup_key)

            finding_id = f"FND-{uuid.uuid4().hex[:8].upper()}"

            standardized.append({
                "id": finding_id,
                "title": title,
                "severity": severity,
                "endpoint": endpoint,
                "description": description,
                "recommendation": recommendation
            })

        # Sort findings: Critical -> High -> Medium -> Low
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        return sorted(standardized, key=lambda x: severity_order.get(x["severity"], 4))
