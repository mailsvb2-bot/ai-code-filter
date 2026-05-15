from ai_code_filter.capabilities.registry import Capability, capability_registry, capability_registry_summary, validate_capability_registry


def test_capability_registry_has_unique_ids_and_validates_cleanly():
    caps = capability_registry()
    assert len(caps) >= 60
    assert len({cap.capability_id for cap in caps}) == len(caps)
    report = validate_capability_registry(caps)
    assert report.summary()["TOTAL"] == 0


def test_capability_registry_rejects_duplicate_ids():
    cap = Capability("DUP001", "A", "code_static", "detector", "LOW", "active", "0.38.0", ("tests/test_x.py",))
    report = validate_capability_registry([cap, cap])
    assert any("Duplicate capability id" in issue.description for issue in report.issues)


def test_capability_registry_summary_is_machine_readable():
    data = capability_registry_summary()
    assert data["schema_version"] == "1.0"
    assert data["capability_count"] == len(data["capabilities"])
    assert "architecture" in data["by_domain"]
