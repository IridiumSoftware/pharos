-- lakefile.lean — hermetic Lean4 build for the PharOS formal track.
--
-- Mirrors the Lazarus + Triadic-Coordination-Engine pattern:
-- no external dependencies on the default build path. `lake build`
-- runs against `Init`/`Std` only, exits non-zero on any proof
-- failure, and completes in under a second after the first compile.
--
-- The first (and currently only) target is `Membrane.lean`, the
-- Lean-proved abstract version of the LL-017 no-oracle preservation
-- claim that PharOS instantiates as PH-004. See PHAROS_SPEC.md
-- PH-004 — LL-017-membrane-preservation.

import Lake
open Lake DSL

package «pharos-lean» where
  leanOptions := #[
    ⟨`pp.unicode.fun, true⟩,
    ⟨`autoImplicit, false⟩,
    ⟨`relaxedAutoImplicit, false⟩
  ]

-- Cross-repo dependency on Lazarus's hermetic Lean tree.
-- Required by:
--   - TriadBackboneMirror (PH-014 no-oracle-triad-backbone) —
--     imports Lazarus.TriadBackbone for the
--     `no_oracle_triad_backbone` 12-element joint composition
--     (LL-002 + LZ-012 + PH-004).
--   - DecouplingBackboneMirror (PH-018 decoupling-triad-
--     backbone) — imports Lazarus.DecouplingBackbone for the
--     `decoupling_triad_backbone` 8-element joint composition
--     (LL-002 + LZ-001 + PH-004; structurally distinct from
--     the No-Oracle Backbone despite sharing LL-002 + PH-004,
--     because Lazarus's leg shifts from LZ-012 LlmOutput to
--     LZ-001 Mode).
-- Pin bumped from v0.1.26 commit `062dcb3` to v0.1.29 commit
-- `5f402d1` at PH-018 promotion (2026-05-12) to bring in
-- Lazarus's new DecouplingBackbone module + sibling
-- VisualSkinDecoupling module. The bump is backward-compatible:
-- TriadBackboneMirror's cited theorem
-- `no_oracle_triad_backbone` exists unchanged in v0.1.29
-- (only new files were added).
-- Lazarus's lake-manifest pins pharos-lean@e3eaee1
-- transitively — Lake prefers the local pharos-lean (this
-- package, HEAD) over that transitive copy.
require «lazarus-lean» from git
  "https://github.com/IridiumSoftware/lazarus.git" @ "5f402d1" / "src/lean4"

@[default_target]
lean_lib «Membrane» where
  srcDir := "."

-- PH-014 cross-Triad No-Oracle Backbone mirror — re-exports
-- Lazarus's `no_oracle_triad_backbone` theorem under PharOS's
-- namespace. The Lake git dep above brings the proof artifact
-- into PharOS's build; this lean_lib stanza makes the mirror
-- module a default build target so `lake build` validates it.
@[default_target]
lean_lib «TriadBackboneMirror» where
  srcDir := "."

-- PH-018 cross-Triad Decoupling axis mirror — re-exports
-- Lazarus's `decoupling_triad_backbone` theorem under PharOS's
-- namespace. Lazarus's DecouplingBackbone composes
-- LavaLamp.LL002Visual.VisualOutput + Lazarus.VisualSkinDecoupling.Mode
-- + PharOS.Membrane.MembraneOutput into an 8-element finite
-- joint output type. The Lake git dep above (bumped to v0.1.29
-- commit `5f402d1` for this mirror) brings the proof artifact
-- into PharOS's build; this lean_lib stanza makes the mirror
-- module a default build target so `lake build` validates it.
@[default_target]
lean_lib «DecouplingBackboneMirror» where
  srcDir := "."
