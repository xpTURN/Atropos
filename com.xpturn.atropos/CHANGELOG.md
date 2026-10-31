# Changelog

## [0.1.2] — 2026-10-31

No code or API changes — the package contents are the same as 0.1.1.

### Added
- Changelog entry for 0.1.1.

### Tested
- AtroposTests (Unity EditMode) on Unity 6000.3.27f2 — all pass.

## [0.1.1] — 2026-07-05

No code or API changes — the package contents are the same as 0.1.0.

### Fixed
- Release workflow: runs on `atropos-v*` tags, the prefix the version is derived from (`MinVerTagPrefix`).
  It listened for `v*`, so the 0.1.0 tag never started the NuGet publish job — 0.1.1 is the first
  `xpTURN.Atropos` version on NuGet.

## [0.1.0] — 2026-07-05

### Added
- `com.xpturn.atropos`: dependency-free pure C# **Ed25519** (RFC 8032, plain PureEdDSA) primitive; IL2CPP/AOT-safe.
- Public API `xpTURN.Atropos.Ed25519` — `Sign` / `Verify` / `DerivePublicKey` (Span signatures):
  - **Zero heap allocation** per call (thread-safe; `[ThreadStatic]` scratch + `stackalloc`).
  - **Non-malleable** — `Verify` rejects non-canonical `S` (`S ≥ L`).
  - RFC 8032 deterministic → signatures byte-identical to any conformant implementation.
- Even/odd (radix-2⁵¹) **Karatsuba** field multiply/square with the hot field ops inlined.
- Vendored ref10 + SHA-512 from Chaos.NaCl (public domain) under `Runtime/ThirdParty/Ed25519/` — see PROVENANCE.md.
- `Server~` net8 mirror csproj + micro-benchmark for headless tests / CI.

### Tested
- RFC 8032 §7.1 KAT (1024 vectors) · BouncyCastle differential · boundary / malleability · Zero-GC ·
  thread-safety · field-arithmetic differential vs reference — all pass.
