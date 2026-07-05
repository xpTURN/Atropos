# xpTURN.Atropos

Dependency-free, Zero-GC-oriented pure C# **Ed25519** (RFC 8032, plain PureEdDSA) sign/verify primitive for
Unity (IL2CPP/AOT-safe) and Godot. No native libs, no DLLs, no Klotho dependency — designed to be split out
as a standalone project.

## Public API

`Ed25519` is the only public type — plain Ed25519 (no context, no prehash), RFC 8032 deterministic (signatures
byte-identical across any conformant implementation). Every operation allocates zero heap after a one-time
per-thread warm-up, is thread-safe, and `Verify` rejects non-canonical signatures (non-malleable). All I/O is
`Span<byte>`; sizes: `SeedSize` 32, `PublicKeySize` 32, `SignatureSize` 64.

**Derive a public key** from a 32-byte private seed:

```csharp
using xpTURN.Atropos;

Span<byte> publicKey = stackalloc byte[Ed25519.PublicKeySize];   // 32
Ed25519.DerivePublicKey(seed /* 32 B */, publicKey);
```

**Sign** a message with the seed (writes a 64-byte signature):

```csharp
Span<byte> signature = stackalloc byte[Ed25519.SignatureSize];   // 64
Ed25519.Sign(seed /* 32 B */, message, signature);
```

**Verify** a signature against the public key:

```csharp
bool ok = Ed25519.Verify(publicKey, message, signature);
```

## Installation

### Unity (UPM)

1. Open **Window > Package Manager**
2. Click **+** > **Add package from git URL...**
3. Enter:

```text
https://github.com/xpTURN/Atropos.git?path=com.xpturn.atropos
```

#### Assembly Definition usage

If your project uses **Assembly Definition** (.asmdef), add a reference to this package's runtime assembly in
any asmdef that calls the API.

1. Select your **Assembly Definition** (.asmdef) file and open it in the Inspector.
2. Under **References**, click **+** and add **xpTURN.Atropos**.

### NuGet (.NET / Godot)

```text
dotnet add package xpTURN.Atropos
```

Ships `netstandard2.1` + `net8.0`.

### From source

`ProjectReference` the `com.xpturn.atropos/Server~/xpTURN.Atropos/xpTURN.Atropos.csproj` mirror, or
`<Compile Include>` `com.xpturn.atropos/Runtime/**/*.cs`.

## Third-party

Ed25519 ref10 math + SHA-512 are vendored from **Chaos.NaCl** (public domain). See
[com.xpturn.atropos/Runtime/ThirdParty/Ed25519/LICENSE.txt](com.xpturn.atropos/Runtime/ThirdParty/Ed25519/LICENSE.txt) and
[PROVENANCE.md](com.xpturn.atropos/PROVENANCE.md) for the pinned source commit and the local-modification log.

## Performance

Zero allocation on every operation, with latency competitive with BouncyCastle. Measured (net8 Release,
Apple-silicon desktop; a comparison against BouncyCastle 2.5.1 as a reference — machine-dependent, **relative**):

| op | Atropos µs/op | Atropos B/op | BouncyCastle µs/op | BouncyCastle B/op | Latency ×vs BC |
|---|--:|--:|--:|--:|--:|
| DerivePublicKey    | 23.2 | **0** | 26.0 | 1,776 | **1.12×** |
| Sign (msg 160 B)   | 47.3 | **0** | 53.7 | 3,448 | **1.14×** |
| Verify (msg 160 B) | 62.5 | **0** | 55.0 | 6,176 | 0.88× |

- **Latency ×vs BC** = BouncyCastle µs ÷ Atropos µs; >1 means Atropos is faster. Derive/Sign run ~1.1× faster;
  Verify trails by ~12% on this host, offset by 0 allocation.
- **0 bytes/op** vs 1.8–6.2 KB/op, and a ~28× smaller code footprint with no dependency.
- Field arithmetic uses an even/odd (radix-2⁵¹) Karatsuba `fe_mul`/`fe_sq` with the hot small ops inlined.
- Numbers are machine-dependent (an x86 host enables BouncyCastle's SIMD paths); treat as relative.

Reproduce:

```
dotnet run -c Release --project com.xpturn.atropos/Server~/xpTURN.Atropos.Bench
```

## License

Apache-2.0 (see [LICENSE.md](com.xpturn.atropos/LICENSE.md)) for the Atropos wrapper/facade code. Vendored
`ThirdParty/` retains its upstream public-domain dedication.
