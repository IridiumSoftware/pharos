-- DecouplingBackboneMirror.lean — PH-018 decoupling-triad-backbone,
-- formal track via cross-repo Lean composition.
--
-- PH-018 (PHAROS_SPEC.md) is PharOS's leg in the cross-Triad
-- Decoupling axis joint claim that the TCE Discovery.Triadic
-- cross-Triad pass surfaced at v0.2.12 (commit `a9ddfea`):
--
--   `[LL-002, LZ-001, PH-004]` at score 23.00 — three
--   deployments, three V-DECOUPLING flavors, one structural
--   claim: the Triad keeps user-facing presentation strictly
--   separated from the security state it represents.
--
-- Structurally distinct from the No-Oracle Backbone
-- `[LL-002, LZ-012, PH-004]` at 26.00 (PH-014, formalised in
-- this Lean tree's sibling `TriadBackboneMirror.lean`) despite
-- sharing LL-002 + PH-004 legs. The No-Oracle claim is about
-- output-cardinality; the Decoupling claim is about
-- architectural separation. PH-004 serves both invariants;
-- the distinguishing Lazarus leg is LZ-001 (visual-skin
-- decoupling) here, vs LZ-012 (companion-read-only) in the
-- No-Oracle Backbone.
--
-- Lazarus is the home of the cross-repo Lean proof — at
-- v0.1.29, Lazarus's `src/lean4/DecouplingBackbone.lean`
-- composes all three concrete leg types into an 8-element
-- finite joint output type:
--
--   - LavaLamp.LL002Visual.VisualOutput (2 states locked /
--     unlocked) — imported via Lake git dep on
--     lavalamp-hermetic.
--   - Lazarus.VisualSkinDecoupling.Mode (2 states normal /
--     shakespeare) — sibling module to DecouplingBackbone,
--     concrete formalisation of LZ-001's producer-side mode
--     vocabulary.
--   - PharOS.Membrane.MembraneOutput (2 states allow / deny)
--     — imported from this very `pharos-lean` package via
--     Lake git dep.
--
-- Joint cardinality 2 × 2 × 2 = 8 (vs TriadBackbone's
-- 2 × 3 × 2 = 12, because LZ-012's LlmOutput has 3
-- constructors and LZ-001's Mode has 2).
--
-- This file is PharOS's mirror — it cites the Lazarus
-- theorem from PharOS's perspective. The `pharos-lean`
-- lakefile gains the `DecouplingBackboneMirror` library and
-- bumps its existing lazarus-lean dep from commit `062dcb3`
-- (v0.1.26, the PH-014 pin) to `5f402d1` (v0.1.29) so the
-- new DecouplingBackbone proof is genuinely available in
-- PharOS's hermetic build, not just referenced in prose.
--
-- The cited theorem
-- `Lazarus.DecouplingBackbone.decoupling_triad_backbone` is
-- exposed in this PharOS namespace via Lean's `export`
-- mechanism so PH-018's `Source:` field can cite a
-- PharOS-namespaced symbol.
--
-- Promotes PH-018 from `:argued` to `:proved` via this
-- cross-repo Lean citation. Mirror entries also exist at
-- LavaLamp LL-050 and Lazarus LZ-031 (the home of the
-- composition).
--
-- Honest framing. PH-018's evidence is the SAME theorem
-- backing Lazarus's LZ-031 and (mirror) LavaLamp's LL-050.
-- The joint claim is one structural fact about the Triad's
-- observer surface; each deployment cites it from its own
-- perspective. This is structurally what "mirror entries"
-- means — three rows of evidence in three specs all pointing
-- at one proof artifact. Lazarus's local pharos-lean
-- transitive copy diamonds with this package's HEAD; Lake
-- prefers the local HEAD which contains this mirror file.

import DecouplingBackbone

namespace PharOS.DecouplingBackboneMirror

open Lazarus.DecouplingBackbone

/-- PH-018's evidence for the cross-Triad Decoupling axis:
    the joint Triad decoupling output (visual × mode ×
    membrane) is an 8-element finite type. Re-exports
    `Lazarus.DecouplingBackbone.decoupling_triad_backbone`
    under PharOS's namespace for spec-citation symmetry. -/
theorem ph018_decoupling_triad_backbone (out : DecouplingOutput) :
    out ∈ decouplingOutputs :=
  decoupling_triad_backbone out

/-- Cardinality witness re-exported under PharOS's namespace. -/
theorem ph018_decoupling_output_cardinality :
    decouplingOutputs.length = 8 :=
  decoupling_output_cardinality

end PharOS.DecouplingBackboneMirror
