from types import SimpleNamespace

from app.services import campus_validation_service


class _FakeScalarDB:
    def __init__(self, values: list[int | list[object]]):
        self.values = list(values)

    def scalar(self, stmt):  # noqa: ARG002
        value = self.values.pop(0)
        return value if not isinstance(value, list) else None

    def scalars(self, stmt):  # noqa: ARG002
        value = self.values.pop(0)

        class _Result:
            def __init__(self, items):
                self._items = list(items)

            def all(self):
                return list(self._items)

        return _Result(value if isinstance(value, list) else [])


def test_build_campus_preprod_validation_report_shapes_summary() -> None:
    db = _FakeScalarDB(
        [
            12,  # zones
            6,  # runners
            3,  # data sources
            100,  # assets
            20,  # executions
            5,  # online runners
            0,  # source errors
            0,  # unresolved executions
            [SimpleNamespace(id="asset-1", ports=[])],  # assets for stale port scan
            [SimpleNamespace(id="job-1", cidr="10.10.0.0/24", status=SimpleNamespace(value="completed"), scanner_zone_id="zone-a", started_at=None, finished_at=None)],
        ]
    )

    report = campus_validation_service.build_campus_preprod_validation_report(db)

    assert report["summary"]["zone_count"] == 12
    assert report["checks"]["zone_count_gte_10"] is True
    assert report["checks"]["runner_count_gte_5"] is True
    assert report["checks"]["data_source_count_gte_2"] is True
