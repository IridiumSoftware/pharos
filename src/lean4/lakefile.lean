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
-- Required by TriadBackboneMirror (PH-014 no-oracle-triad-
-- backbone), which imports Lazarus.TriadBackbone to re-export
-- the `no_oracle_triad_backbone` composition theorem (proved
-- at Lazarus v0.1.26 using PharOS Membrane + LavaLamp
-- LL002Visual + Lazarus CompanionDiscipline as the three
-- concrete legs). PH-014 cites the Lazarus theorem from
-- PharOS's perspective; mirror entries also exist at LavaLamp
-- LL-046 and Lazarus LZ-028. Lazarus's lake-manifest pins
-- pharos-lean@e3eaee1 transitively — Lake prefers the local
-- pharos-lean (this package, HEAD) over that transitive copy.
require «lazarus-lean» from git
  "https://github.com/IridiumSoftware/lazarus.git" @ "062dcb3" / "src/lean4"

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
