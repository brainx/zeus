from __future__ import annotations

import tomllib
from pathlib import Path

from zeus.models import HermesTemplate


class TemplateStore:
    def __init__(self, root: Path | str = "templates") -> None:
        self.root = Path(root)

    def list(self) -> list[HermesTemplate]:
        templates: list[HermesTemplate] = []
        seen: set[str] = set()
        for path in sorted(self.root.glob("*.toml")):
            with path.open("rb") as handle:
                data = tomllib.load(handle)
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
