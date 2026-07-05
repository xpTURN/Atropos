# Vendored source provenance — `Runtime/ThirdParty/Ed25519/`

## Upstream
- **Project:** Chaos.NaCl — C# port of djb's ref10 Ed25519 (SUPERCOP) + SHA-512.
- **Repo:** https://github.com/CodesInChaos/Chaos.NaCl
- **Pinned commit:** `2c861348dc45369508e718aa08611c53b53553db`
- **License:** Public domain (see `Runtime/ThirdParty/Ed25519/LICENSE.txt`).

## Vendored subset (Ed25519 + SHA-512 only)
`CryptoBytes.cs`, `Sha512.cs`, `Internal/{ByteIntegerConverter,Array16,Array8,InternalAssert,Sha512Internal}.cs`,
and `Internal/Ed25519Ref10/*.cs`.

**Excluded** (not needed by Ed25519): the public `Ed25519.cs` wrapper (pulls in X25519 `MontgomeryCurve25519`),
Poly1305, Salsa/XSalsa20, `MontgomeryCurve25519.cs`, `OneTimeAuth.cs`. The Atropos facade
(`Runtime/Ed25519.cs`, namespace `xpTURN.Atropos`) calls the internal `Ed25519Operations` directly instead.

## Local modification log
**47 of 57 vendored files are byte-identical to upstream.** The other 10 carry Zero-GC / malleability /
Karatsuba / inlining changes, each marked in-file with an `Atropos …` comment:

| # | File | Change | Reason |
|---|------|--------|--------|
| 1 | `Sha512.cs` | **add** `Update(ReadOnlySpan<byte>)` (new overload; existing methods untouched) | hash the caller's message span without a byte[] copy (Zero-GC) |
| 2 | `Internal/Ed25519Ref10/ge_scalarmult_base.cs` | `sbyte[] e = new sbyte[64]` → `Span<sbyte> = stackalloc` | remove per-call heap temp (Zero-GC); logic unchanged |
| 3 | `Internal/Ed25519Ref10/ge_double_scalarmult.cs` | `aslide`/`bslide` (`sbyte[256]`) + `Ai` (`GroupElementCached[8]`) `new[]` → `stackalloc`; `slide(sbyte[])` → `slide(Span<sbyte>)` | remove per-call heap temps (Zero-GC); logic unchanged |
| 4 | `Internal/Ed25519Ref10/fe_mul.cs` | schoolbook renamed `fe_mul_schoolbook` (retained oracle); new even/odd radix-2⁵¹ Karatsuba `fe_mul` (75 muls vs 100) | perf (~1.2× field-mul); **bit-identical** (same pre-carry h0..h9 + unchanged carry chain), proven symbolically + differential-tested |
| 5 | `Internal/Ed25519Ref10/fe_sq.cs` | schoolbook renamed `fe_sq_schoolbook` (retained oracle); new square-symmetric Karatsuba `fe_sq` (45 muls) | as #4 |
| 6–10 | `Internal/Ed25519Ref10/{fe_add,fe_sub,fe_neg,fe_cmov,fe_mul121666}.cs` | added `[MethodImpl(AggressiveInlining)]` on the hot small field ops | perf (call/enregister overhead); **codegen hint only — output byte-identical**, no logic change |

`fe_sq2.cs` and all other files remain byte-identical to upstream (**47 of 57** verbatim). The Karatsuba edits are
proven bit-identical to the retained `*_schoolbook` oracles: (a) offline symbolic identity `expand(kara−school)==0`
for every limb + worst-case int64 accumulator = 2⁶¹·⁵² < 2⁶³ (both fe_mul/fe_sq), and (b) the differential test
`Tests/Ed25519FieldKaratsubaTests.cs` (random + max-magnitude + boundary + aliasing + non-reduced + `fe_sq==fe_mul(a,a)`).

The **canonical `S < L` malleability check** was added **without touching vendored files** — it lives in the
Atropos facade (`Runtime/Ed25519.cs`, `ScalarIsCanonical`) and is implemented by zero-extending S to 64 B and
running the verbatim `sc_reduce`, comparing reduced==original (no hardcoded group-order constant).

**Verification (all green):** RFC 8032 §7.1 KAT (1024 vectors: sign byte-identical, verify, derive-pubkey,
tamper-reject) + S<L malleability ((R, S+L) rejected) + Zero-GC (0 B/call over 6000 calls after warm-up) +
thread-safety (8 threads concurrent, 0 errors). BouncyCastle differential regression is added in the test suite.
