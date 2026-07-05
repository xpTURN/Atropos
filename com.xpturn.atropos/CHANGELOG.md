# Changelog

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
