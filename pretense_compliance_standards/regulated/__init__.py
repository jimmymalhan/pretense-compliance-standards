"""
pretense_compliance_standards.regulated — registry + auto-discovery for regulated-data modules.

This package holds *additional* synthetic DLP benchmark data modules that extend
the base corpus into broader sensitive-data categories (health records,
personal-data records, controlled/technical program data, credentials/secrets).
Each sibling module in this package MAY define a module-level
``build_cases() -> list[dict]`` returning cases in the same schema the base
``corpus_builder.build_cases()`` uses.

``collect_regulated_cases()`` discovers every sibling module deterministically
(sorted by name), imports it, and — if it exposes a ``build_cases`` callable —
aggregates its cases. It is a safe no-op returning ``[]`` when no data modules
are present, so the base benchmark behaves identically until such modules arrive.

Everything here is SYNTHETIC. Every value is fake by construction; see the
package banner ``pretense_compliance_standards.BANNER``.
"""

from __future__ import annotations

import importlib
import pkgutil


def collect_regulated_cases() -> list[dict]:
    """Aggregate ``build_cases()`` output from every sibling data module.

    Discovery is deterministic (modules sorted by name). The package's own
    ``__init__`` is skipped, as is any module that does not expose a callable
    ``build_cases`` attribute. Returns ``[]`` when no data modules are present.
    """
    cases: list[dict] = []
    module_names = sorted(
        name
        for _finder, name, _ispkg in pkgutil.iter_modules(__path__)
        if name != "__init__"
    )
    for name in module_names:
        module = importlib.import_module(f"{__name__}.{name}")
        build = getattr(module, "build_cases", None)
        if callable(build):
            cases.extend(build())
    return cases


__all__ = ["collect_regulated_cases"]
