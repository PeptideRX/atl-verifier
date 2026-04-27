"""Generate the three PDA cross-language test-vector JSON fixtures.

Run from the repo root:

    python sdk/packages/atl-verifier/tests/pda-vectors/generate.py

This re-runs the Python reference implementation over the three frozen
vectors committed in `tests/test_peptide_design_attestation.py` and
writes the published ``PDAOutput`` shape to
``vector-{a,b,c}.json`` in this directory. The TypeScript tests consume
those files to confirm cross-language parity. Candidate metadata and
salts for the commit-reveal tests are written alongside as
``vector-{a,b,c}.reveal.json``.

Scope: research use only, nonclinical.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

# Ensure repo root is on sys.path when the script is launched directly.
HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[4]
sys.path.insert(0, str(REPO_ROOT))

from schemas.python.peptide_candidate import PeptideCandidate  # noqa: E402
from src.peptide_design.pda import (  # noqa: E402
    BiosecurityPolicy,
    ModelPin,
    PDAProducer,
    PipelineManifest,
    PocketCoordinate,
    TargetSpec,
    TEEAttesterSimulator,
    candidate_commit_bytes,
    candidate_metadata_hash,
    generate_inclusion_proof,
)

FIX_TS = datetime(2026, 4, 22, 12, 0, 0, tzinfo=UTC)


def _vector_a_inputs():
    ts = TargetSpec(
        target_pdb_hash="00" * 32,
        pocket_coordinates=(PocketCoordinate(x_nm=0, y_nm=0, z_nm=0),),
        length_min=8,
        length_max=20,
        modifications_whitelist=(),
    )
    pm = PipelineManifest(
        backbone_model=ModelPin(name="rfdiffusion", version="v1.0.0", weights_sha256="11" * 32),
        sequence_model=ModelPin(name="proteinmpnn", version="v1.0.1", weights_sha256="22" * 32),
        structure_model=ModelPin(name="boltz2", version="v2.0.0", weights_sha256="33" * 32),
        sequence_filter=ModelPin(
            name="identity_filter", version="v0.1.0", weights_sha256="44" * 32
        ),
    )
    bp = BiosecurityPolicy(
        pathogen_db_version="2026-01",
        pathogen_db_hash="55" * 32,
        toxin_db_version="2026-01",
        toxin_db_hash="66" * 32,
        t_pathogen=70,
        t_toxin=60,
        t_motif=80,
        blacklist_motif_patterns=(),
    )
    cand = PeptideCandidate(
        candidate_id="00000000-0000-4000-8000-000000000001",
        parent_thesis_id="ATL-001",
        sequence="GIGAVLKVLTT",
        length_residues=11,
        modifications=[],
        predicted_structure_pdb="HEADER test\nEND",
        predicted_affinity_kcal_mol=-7.5,
        structure_confidence=0.82,
        design_method="rfdiffusion_proteinmpnn_boltz2",
        generated_at=FIX_TS,
        pop_shield_tier="green",
        clinical_claims_pass=True,
    )
    salts = [bytes([0xAA] * 32)]
    nonce = bytes([0xBB] * 32)
    return ts, pm, bp, [cand], ["green"], salts, nonce


def _vector_b_inputs():
    ts = TargetSpec(
        target_pdb_hash="aa" * 32,
        pocket_coordinates=(
            PocketCoordinate(x_nm=100, y_nm=200, z_nm=300),
            PocketCoordinate(x_nm=110, y_nm=210, z_nm=310),
        ),
        length_min=12,
        length_max=25,
        modifications_whitelist=("lipidated", "cyclic-head-to-tail"),
    )
    pm = PipelineManifest(
        backbone_model=ModelPin(name="rfdiffusion", version="v1.2.0", weights_sha256="aa" * 32),
        sequence_model=ModelPin(name="proteinmpnn", version="v1.2.3", weights_sha256="bb" * 32),
        structure_model=ModelPin(name="boltz2", version="v2.1.0", weights_sha256="cc" * 32),
        sequence_filter=ModelPin(
            name="solubility_filter", version="v0.2.0", weights_sha256="dd" * 32
        ),
    )
    bp = BiosecurityPolicy(
        pathogen_db_version="2026-03",
        pathogen_db_hash="ee" * 32,
        toxin_db_version="2026-03",
        toxin_db_hash="ff" * 32,
        t_pathogen=75,
        t_toxin=65,
        t_motif=85,
        blacklist_motif_patterns=("RGD", "LDV"),
    )
    c1 = PeptideCandidate(
        candidate_id="00000000-0000-4000-8000-000000000002",
        parent_thesis_id="ATL-002",
        sequence="KLAKLAKKLAKLAK",
        length_residues=14,
        modifications=["cyclic-head-to-tail"],
        predicted_structure_pdb="HEADER b1\nEND",
        predicted_affinity_kcal_mol=-9.0,
        structure_confidence=0.91,
        design_method="rfdiffusion_proteinmpnn_boltz2",
        generated_at=FIX_TS,
        pop_shield_tier="green",
        clinical_claims_pass=True,
    )
    c2 = PeptideCandidate(
        candidate_id="00000000-0000-4000-8000-000000000003",
        parent_thesis_id="ATL-002",
        sequence="RGRGRGRGKLAK",
        length_residues=12,
        modifications=[],
        predicted_structure_pdb="HEADER b2\nEND",
        predicted_affinity_kcal_mol=-7.1,
        structure_confidence=0.76,
        design_method="rfdiffusion_proteinmpnn_boltz2",
        generated_at=FIX_TS,
        pop_shield_tier="green",
        clinical_claims_pass=True,
    )
    salts = [bytes([0x01] * 32), bytes([0x02] * 32)]
    nonce = bytes([0x03] * 32)
    return ts, pm, bp, [c1, c2], ["green", "green"], salts, nonce


def _vector_c_inputs():
    ts = TargetSpec(
        target_pdb_hash="12" * 32,
        pocket_coordinates=(
            PocketCoordinate(x_nm=1, y_nm=2, z_nm=3),
            PocketCoordinate(x_nm=4, y_nm=5, z_nm=6),
            PocketCoordinate(x_nm=7, y_nm=8, z_nm=9),
        ),
        length_min=10,
        length_max=30,
        modifications_whitelist=("lipidated",),
    )
    pm = PipelineManifest(
        backbone_model=ModelPin(name="rfdiffusion", version="v1.3.0", weights_sha256="13" * 32),
        sequence_model=ModelPin(name="proteinmpnn", version="v1.3.0", weights_sha256="14" * 32),
        structure_model=ModelPin(name="boltz2", version="v2.2.0", weights_sha256="15" * 32),
        sequence_filter=ModelPin(name="plm_filter", version="v0.3.0", weights_sha256="16" * 32),
    )
    bp = BiosecurityPolicy(
        pathogen_db_version="2026-04",
        pathogen_db_hash="17" * 32,
        toxin_db_version="2026-04",
        toxin_db_hash="18" * 32,
        t_pathogen=80,
        t_toxin=70,
        t_motif=90,
        blacklist_motif_patterns=("KKKKK",),
    )
    cands = []
    salts = []
    for i in range(3):
        cid = f"00000000-0000-4000-8000-00000000000{4 + i:x}"
        cands.append(
            PeptideCandidate(
                candidate_id=cid,
                parent_thesis_id="ATL-003",
                sequence="ACDEFGHIKLMN"[: 10 + i],
                length_residues=10 + i,
                modifications=[],
                predicted_structure_pdb=f"HEADER c{i}\nEND",
                predicted_affinity_kcal_mol=-6.0 - i * 0.5,
                structure_confidence=0.6 + i * 0.05,
                design_method="rfdiffusion_proteinmpnn_boltz2",
                generated_at=FIX_TS,
                pop_shield_tier="green",
                clinical_claims_pass=True,
            )
        )
        salts.append(bytes([0x20 + i] * 32))
    nonce = bytes([0x30] * 32)
    return ts, pm, bp, cands, ["green"] * 3, salts, nonce


def _dump_vector(label: str, inputs_fn) -> None:
    ts, pm, bp, cands, tiers, salts, nonce = inputs_fn()
    producer = PDAProducer()
    outcome = producer.produce(
        target_spec=ts,
        pipeline_manifest=pm,
        biosecurity_policy=bp,
        candidates=cands,
        tier_assignments=tiers,
        tee=TEEAttesterSimulator(),
        salts=salts,
        nonce=nonce,
    )
    out_path = HERE / f"vector-{label.lower()}.json"
    out_path.write_text(
        json.dumps(outcome.pda_output.model_dump(mode="json"), indent=2) + "\n",
        encoding="utf-8",
    )

    # Reveal-path fixture: per-candidate commit handle + full revealed
    # metadata + inclusion proof. Allows the TypeScript verifier to
    # exercise verifyCandidateReveal byte-for-byte against the Python
    # reference.
    leaves = [bytes.fromhex(h) for h in outcome.pda_output.merkle_leaves_hex]
    reveal_blobs = []
    for i, (cand, salt) in enumerate(zip(cands, salts, strict=True)):
        metadata = {k: v for k, v in cand.model_dump(mode="json").items() if k != "sequence"}
        proof_path = generate_inclusion_proof(leaves, i)
        reveal_blobs.append(
            {
                "candidate_id": cand.candidate_id,
                "salt_hex": salt.hex(),
                "sequence": cand.sequence,
                "metadata": metadata,
                "leaf_hex": leaves[i].hex(),
                "leaf_index": i,
                "inclusion_path": [
                    {"sibling_hex": sibling.hex(), "side": side} for sibling, side in proof_path
                ],
                "canonical_sequence_hash": cand.sequence_hash(),
                "metadata_hash": candidate_metadata_hash(cand).hex(),
                "candidate_commit_bytes_hex": candidate_commit_bytes(cand, salt).hex(),
            }
        )
    reveal_path = HERE / f"vector-{label.lower()}.reveal.json"
    reveal_path.write_text(
        json.dumps({"candidates": reveal_blobs}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {out_path.name} + {reveal_path.name}")


if __name__ == "__main__":
    _dump_vector("A", _vector_a_inputs)
    _dump_vector("B", _vector_b_inputs)
    _dump_vector("C", _vector_c_inputs)
