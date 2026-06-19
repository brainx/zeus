from __future__ import annotations

import tomllib
from importlib.resources import files
from pathlib import Path
from typing import Any

from zeus.models import HermesTemplate

TemplateData = list[tuple[str, dict[str, Any]]]
TemplatePaths = list[Path]


class TemplateStore:
    def __init__(self, root: Path | str | None = "templates") -> None:
        self.root = Path(root) if root is not None else None

    def list(self) -> list[HermesTemplate]:
        templates: list[HermesTemplate] = []
        seen: set[str] = set()
        for _source, data in self._load_template_data():
            template = HermesTemplate.from_dict(data)
            if template.id in seen:
                raise ValueError(f"duplicate template id: {template.id}")
            seen.add(template.id)
            templates.append(template)
        return templates

    def get(self, template_id: str) -> HermesTemplate:
        for template in self.list():
            if template.id == template_id:
                return template
        raise KeyError(f"unknown template: {template_id}")

    def _load_template_data(self) -> TemplateData:
        local_paths = self._local_template_paths()
        if local_paths:
            return [(str(path), self._load_path(path)) for path in local_paths]
        return self._load_bundled_templates()

    def _local_template_paths(self) -> TemplatePaths:
        if self.root is None or not self.root.exists():
            return []
        return sorted(self.root.glob("*.toml"))

    def _load_path(self, path: Path) -> dict[str, Any]:
        with path.open("rb") as handle:
            return tomllib.load(handle)

    def _load_bundled_templates(self) -> TemplateData:
        result: TemplateData = []
        bundle = files("zeus.bundled_templates")
        for entry in sorted(bundle.iterdir(), key=lambda item: item.name):
            if not entry.name.endswith(".toml"):
                continue
            with entry.open("rb") as handle:
                result.append((entry.name, tomllib.load(handle)))
        return result
