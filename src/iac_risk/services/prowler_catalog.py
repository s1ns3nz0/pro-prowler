"""Load and query Prowler check definitions from YAML data files."""

from pathlib import Path

import yaml

from iac_risk.core.schemas import ProwlerCheckDef

_DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "prowler_checks"


class ProwlerCatalog:
    """In-memory catalog of Prowler-derived check definitions."""

    def __init__(self, data_dir: Path | None = None) -> None:
        self._data_dir = data_dir or _DEFAULT_DATA_DIR
        self._checks: dict[str, ProwlerCheckDef] = {}
        self._by_resource_type: dict[str, list[ProwlerCheckDef]] = {}
        self._load()

    def _load(self) -> None:
        if not self._data_dir.exists():
            return
        for yaml_file in sorted(self._data_dir.glob("*.yaml")):
            if yaml_file.name.startswith("_"):
                continue
            with open(yaml_file) as f:
                data = yaml.safe_load(f)
            if not isinstance(data, list):
                continue
            for entry in data:
                check = ProwlerCheckDef.model_validate(entry)
                self._checks[check.check_id] = check
                for rt in check.resource_types:
                    self._by_resource_type.setdefault(rt, []).append(check)

    def get_check_by_id(self, check_id: str) -> ProwlerCheckDef | None:
        return self._checks.get(check_id)

    def get_checks_for_resource_type(self, resource_type: str) -> list[ProwlerCheckDef]:
        return self._by_resource_type.get(resource_type, [])

    def get_all_checks(self) -> list[ProwlerCheckDef]:
        return list(self._checks.values())

    def get_compliance_mappings(self, check_id: str, framework: str) -> list[str]:
        check = self._checks.get(check_id)
        if not check:
            return []
        return check.compliance_mappings.get(framework, [])

    @property
    def check_count(self) -> int:
        return len(self._checks)
