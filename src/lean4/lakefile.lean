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

@[default_target]
lean_lib «Membrane» where
  srcDir := "."
