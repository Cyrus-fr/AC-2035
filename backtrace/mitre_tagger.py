"""Maps reconstructed attacker behaviour onto MITRE ATT&CK techniques.

Technique IDs are validated against the real ATT&CK dataset via
mitreattack-python when its STIX bundle is available locally; when it
isn't (no network / no bundle), we fall back to the hardcoded metadata
below so tagging still works fully offline.
"""

from __future__ import annotations

import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loguru import logger

# Hardcoded fallback metadata for every technique this engine can emit.
_META = {
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
}

_BLAST_RADIUS_THRESHOLD = 2

_STIX_CANDIDATES = [
    Path(__file__).resolve().parent.parent / "data" / "enterprise-attack.json",
    Path(__file__).resolve().parent.parent / "enterprise-attack.json",
]

_mad = None
_mad_tried = False


@dataclass
class MitreTechnique:
    technique_id: str
    technique_name: str
    tactic: str
    hop_index: int

    def to_dict(self) -> dict:
        return asdict(self)


def _find_stix() -> Optional[str]:
    env = os.getenv("MITRE_STIX_PATH")
    if env and Path(env).is_file():
        return env
    for candidate in _STIX_CANDIDATES:
        if candidate.is_file():
            return str(candidate)
    return None


def _load_mad():
    """Lazily load MitreAttackData once. Returns None (→ hardcoded
    fallback) if the library or its STIX bundle isn't available."""
    global _mad, _mad_tried
    if _mad_tried:
        return _mad
    _mad_tried = True

    stix_path = _find_stix()
    if not stix_path:
        logger.info("MITRE ATT&CK STIX bundle not found — using hardcoded technique metadata")
        return None
    try:
        from mitreattack.stix20 import MitreAttackData

        _mad = MitreAttackData(stix_path)
        logger.info("Loaded MITRE ATT&CK dataset from {}", stix_path)
    except Exception as e:
        logger.warning("mitreattack-python unavailable ({}) — using hardcoded metadata", e)
        _mad = None
    return _mad


def _valid(technique_id: str) -> bool:
    mad = _load_mad()
    if mad is None:
        return technique_id in _META
    try:
        return mad.get_object_by_attack_id(technique_id, "attack-pattern") is not None
    except Exception:
        return technique_id in _META


def _technique(technique_id: str, hop_index: int) -> Optional[MitreTechnique]:
    if not _valid(technique_id):
        logger.warning("Technique {} did not validate against ATT&CK — skipping", technique_id)
        return None
    meta = _META[technique_id]
    return MitreTechnique(technique_id, meta["name"], meta["tactic"], hop_index)


def tag_path(scored_path, blast_radius: Optional[list[str]] = None) -> list[MitreTechnique]:
    """Tag a scored path with ATT&CK techniques. Per-hop rules:
      CONNECTED_TO into the entry (or any CF-Ray'd) hop → T1190
      MOVED_TO (pod → pod)                             → T1021
      ACCESSED (pod → honeytoken)                      → T1552
    Plus a path-level rule: blast_radius > 2           → T1083
    """
    hops = scored_path.hops if scored_path else []
    techniques: list[MitreTechnique] = []

    for i, hop in enumerate(hops):
        technique_id = None
        if hop.edge_type == "ACCESSED":
            technique_id = "T1552"
        elif hop.edge_type == "MOVED_TO":
            technique_id = "T1021"
        elif hop.edge_type == "CONNECTED_TO" and (hop.cf_ray or i == 0):
            technique_id = "T1190"
        if technique_id:
            tech = _technique(technique_id, i)
            if tech:
                techniques.append(tech)

    if blast_radius and len(blast_radius) > _BLAST_RADIUS_THRESHOLD:
        tech = _technique("T1083", len(hops) - 1 if hops else -1)
        if tech:
            techniques.append(tech)

    # One entry per technique_id (keep the first / earliest hop it fired on).
    seen: set[str] = set()
    deduped = []
    for t in techniques:
        if t.technique_id in seen:
            continue
        seen.add(t.technique_id)
        deduped.append(t)

    logger.info("Tagged {} MITRE technique(s): {}", len(deduped), [t.technique_id for t in deduped])
    return deduped
