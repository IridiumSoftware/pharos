-- TriadBackboneMirror.lean — PH-014 no-oracle-triad-backbone,
-- formal track via cross-repo Lean composition.
--
-- PH-014 (PHAROS_SPEC.md) is PharOS's leg in the cross-Triad
-- No-Oracle Backbone joint claim that the TCE Discovery.Triadic
-- cross-Triad pass surfaced at v0.2.12 (commit `a9ddfea`):
--
--   `[LL-002, LZ-012, PH-004]` at score 26.00 — three
--   deployments, three layers, one structural claim: the
--   Triad does not leak distance information at any of its
--   three layers.
--
-- Lazarus is the home of the cross-repo Lean proof — at
-- v0.1.26, Lazarus's `src/lean4/TriadBackbone.lean` composes
-- all three concrete leg types (PharOS.Membrane.MembraneOutput
-- via cross-repo Lake git dep on pharos-lean@e3eaee1,
-- LavaLamp.LL002Visual.VisualOutput via dep on
-- lavalamp-hermetic@1a2534f, and Lazarus.CompanionDiscipline.LlmOutput
-- as a sibling module) and proves `no_oracle_triad_backbone`
-- (every joint Triad output is in a 12-element finite type).
--
-- This file is PharOS's mirror — it cites the Lazarus theorem
-- from PharOS's perspective. The `pharos-lean` lakefile gains
-- a Lake git dep on `lazarus-lean` at Lazarus commit `062dcb3`
-- so the proof is genuinely available in PharOS's build, not
-- just referenced in prose. The transitive dep tree brings in
-- lavalamp-hermetic@1a2534f + pharos-lean@e3eaee1 (the latter
-- diamonds with PharOS's local package; Lake prefers the local
-- HEAD which contains this mirror file).
--
-- The cited theorem `Lazarus.TriadBackbone.no_oracle_triad_backbone`
-- is exposed in this PharOS namespace via Lean's `export`
-- mechanism so PH-014's `Source:` field can cite a
-- PharOS-namespaced symbol.
--
-- Promotes PH-014 from `:argued` to `:proved` via this
-- cross-repo Lean citation.
--
-- Honest framing. PH-014's evidence is the SAME theorem
-- backing Lazarus's LZ-028 and (mirror) LavaLamp's LL-046.
-- The joint claim is one structural fact about the Triad's
-- observer surface; each deployment cites it from its own
-- perspective. This is structurally what "mirror entries"
-- means — three rows of evidence in three specs all pointing
-- at one proof artifact.

import TriadBackbone

namespace PharOS.TriadBackboneMirror

open Lazarus.TriadBackbone

/-- PH-014's evidence for the cross-Triad No-Oracle Backbone:
    the joint Triad output (visual × llm × membrane) is a
    12-element finite type. Re-exports
    `Lazarus.TriadBackbone.no_oracle_triad_backbone` under
    PharOS's namespace for spec-citation symmetry. -/
theorem ph014_no_oracle_triad_backbone (out : TriadOutput) :
    out ∈ triadOutputs :=
  no_oracle_triad_backbone out

/-- Cardinality witness re-exported under PharOS's namespace. -/
theorem ph014_triad_output_cardinality :
    triadOutputs.length = 12 :=
  triad_output_cardinality

end PharOS.TriadBackboneMirror
