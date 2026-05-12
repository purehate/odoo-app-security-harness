"""Tests for module risk scoring algorithm."""

from __future__ import annotations

SHARP_EDGE_PATTERNS = {
    "sudo": r"\.sudo\(",
    "with_user": r"\.with_user\(",
    "with_context": r"\.with_context\(",
    "raw_sql": r"\.cr\.execute\(|\bcr\.execute\(",
    "request_params": r"request\.params|request\.jsonrequest",
    "safe_eval": r"\bsafe_eval\(",
    "t_raw": r"t-raw\s*=",
    "markup": r"\bMarkup\(",
    "attachments": r"ir\.attachment|public\s*=\s*True",
}

SHARP_EDGE_WEIGHTS = {
    "sudo": 3,
    "with_user": 2,
    "with_context": 1,
    "raw_sql": 4,
    "request_params": 2,
    "safe_eval": 5,
    "t_raw": 4,
    "markup": 2,
    "attachments": 1,
}


def compute_module_risk(
    manifests: list[dict],
    routes: list[dict],
    acl_rows: list[dict],
    pattern_summary: dict,
) -> list[dict]:
    """Compute risk score per module."""
    routes_by_module: dict[str, int] = {}
    public_by_module: dict[str, int] = {}
    for r in routes:
        routes_by_module[r["module"]] = routes_by_module.get(r["module"], 0) + 1
        auth = (r.get("auth") or "").lower()
        if "public" in auth or "none" in auth:
            public_by_module[r["module"]] = public_by_module.get(r["module"], 0) + 1

    acl_by_module: dict[str, int] = {}
    acl_global_by_module: dict[str, int] = {}
    for row in acl_rows:
        mod = row.get("_module") or ""
        if not mod:
            continue
        acl_by_module[mod] = acl_by_module.get(mod, 0) + 1
        if not (row.get("group_id:id") or row.get("group_id") or "").strip():
            acl_global_by_module[mod] = acl_global_by_module.get(mod, 0) + 1

    per_module = pattern_summary.get("per_module", {})

    rows: list[dict] = []
    for item in manifests:
        module = item["module"]
        route_count = routes_by_module.get(module, 0)
        public_count = public_by_module.get(module, 0)
        acl_count = acl_by_module.get(module, 0)
        acl_global = acl_global_by_module.get(module, 0)
        sharp = per_module.get(module, {})
        sharp_score = sum(sharp.get(k, 0) * SHARP_EDGE_WEIGHTS.get(k, 1) for k in SHARP_EDGE_PATTERNS)
        score = route_count * 1 + public_count * 5 + acl_global * 3 + sharp_score
        band = "low"
        if score >= 50:
            band = "critical"
        elif score >= 25:
            band = "high"
        elif score >= 10:
            band = "medium"

        rows.append(
            {
                "module": module,
                "score": score,
                "band": band,
                "routes": route_count,
                "public_routes": public_count,
                "acl_rows": acl_count,
                "acl_global_rows": acl_global,
                "sharp_edge_score": sharp_score,
                "sharp_edges": sharp,
            }
        )

    rows.sort(key=lambda r: (-r["score"], r["module"]))
    return rows


class TestComputeModuleRisk:
    """Test module risk scoring."""

    def test_low_risk_module(self) -> None:
        """Test module with no risky patterns."""
        manifests = [{"module": "safe_module"}]
        routes = []
        acl_rows = []
        pattern_summary = {"per_module": {"safe_module": {}}}

        result = compute_module_risk(manifests, routes, acl_rows, pattern_summary)

        assert len(result) == 1
        assert result[0]["module"] == "safe_module"
        assert result[0]["score"] == 0
        assert result[0]["band"] == "low"

    def test_high_risk_public_routes(self) -> None:
        """Test module with public routes."""
        manifests = [{"module": "portal_module"}]
        routes = [
            {"module": "portal_module", "auth": "'public'"},
            {"module": "portal_module", "auth": "'public'"},
        ]
        acl_rows = []
        pattern_summary = {"per_module": {"portal_module": {}}}

        result = compute_module_risk(manifests, routes, acl_rows, pattern_summary)

        # 2 public routes * 5 + 2 regular routes * 1 = 12
        assert result[0]["score"] == 12
        assert result[0]["band"] == "medium"
        assert result[0]["public_routes"] == 2

    def test_critical_risk_module(self) -> None:
        """Test module with multiple risk factors."""
        manifests = [{"module": "risky_module"}]
        routes = [
            {"module": "risky_module", "auth": "'public'"},
            {"module": "risky_module", "auth": "'public'"},
        ]
        acl_rows = [
            {"_module": "risky_module", "group_id:id": ""},
            {"_module": "risky_module", "group_id:id": ""},
        ]
        pattern_summary = {
            "per_module": {
                "risky_module": {
                    "sudo": 3,
                    "raw_sql": 2,
                    "safe_eval": 1,
                }
            }
        }

        result = compute_module_risk(manifests, routes, acl_rows, pattern_summary)

        # 2 public routes * 5 = 10
        # 2 regular routes * 1 = 2
        # 2 global ACL rows * 3 = 6
        # sharp edges: 3*3 + 2*4 + 1*5 = 9 + 8 + 5 = 22
        # total = 40
        assert result[0]["score"] == 40
        assert result[0]["band"] == "high"

    def test_risk_sorting(self) -> None:
        """Test modules are sorted by risk descending."""
        manifests = [
            {"module": "low_risk"},
            {"module": "high_risk"},
            {"module": "medium_risk"},
        ]
        routes = [
            {"module": "high_risk", "auth": "'public'"},
            {"module": "high_risk", "auth": "'public'"},
            {"module": "high_risk", "auth": "'public'"},
            {"module": "high_risk", "auth": "'public'"},
            {"module": "high_risk", "auth": "'public'"},
            {"module": "medium_risk", "auth": "'public'"},
            {"module": "medium_risk", "auth": "'public'"},
        ]
        acl_rows = []
        pattern_summary = {"per_module": {}}

        result = compute_module_risk(manifests, routes, acl_rows, pattern_summary)

        assert len(result) == 3
        assert result[0]["module"] == "high_risk"
        assert result[0]["score"] == 30  # 5 public * 5 + 5 regular * 1
        assert result[1]["module"] == "medium_risk"
        assert result[1]["score"] == 12  # 2 public * 5 + 2 regular * 1
        assert result[2]["module"] == "low_risk"
        assert result[2]["score"] == 0

    def test_acl_global_rows(self) -> None:
        """Test global ACL rows increase risk."""
        manifests = [{"module": "acl_module"}]
        routes = []
        acl_rows = [
            {"_module": "acl_module", "group_id:id": ""},
            {"_module": "acl_module", "group_id:id": ""},
            {"_module": "acl_module", "group_id:id": "base.group_user"},
        ]
        pattern_summary = {"per_module": {"acl_module": {}}}

        result = compute_module_risk(manifests, routes, acl_rows, pattern_summary)

        assert result[0]["acl_rows"] == 3
        assert result[0]["acl_global_rows"] == 2
        assert result[0]["score"] == 6  # 2 global * 3

    def test_sharp_edge_scoring(self) -> None:
        """Test sharp edge patterns are weighted correctly."""
        manifests = [{"module": "sharp_module"}]
        routes = []
        acl_rows = []
        pattern_summary = {
            "per_module": {
                "sharp_module": {
                    "sudo": 1,  # weight 3
                    "raw_sql": 1,  # weight 4
                    "safe_eval": 1,  # weight 5
                    "t_raw": 1,  # weight 4
                    "request_params": 1,  # weight 2
                }
            }
        }

        result = compute_module_risk(manifests, routes, acl_rows, pattern_summary)

        expected_score = 3 + 4 + 5 + 4 + 2  # 18
        assert result[0]["sharp_edge_score"] == expected_score
        assert result[0]["score"] == expected_score
        assert result[0]["band"] == "medium"

    def test_empty_manifests(self) -> None:
        """Test with empty manifests list."""
        result = compute_module_risk([], [], [], {"per_module": {}})
        assert result == []

    def test_missing_per_module_data(self) -> None:
        """Test when module has no per_module data."""
        manifests = [{"module": "unknown"}]
        routes = []
        acl_rows = []
        pattern_summary = {"per_module": {}}  # Missing module entry

        result = compute_module_risk(manifests, routes, acl_rows, pattern_summary)

        assert result[0]["score"] == 0
        assert result[0]["sharp_edge_score"] == 0
