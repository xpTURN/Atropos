using System;
using Chaos.NaCl;
using Chaos.NaCl.Internal.Ed25519Ref10;

namespace xpTURN.Atropos
{
    /// <summary>
    /// Zero-GC Ed25519 (RFC 8032, plain PureEdDSA) sign/verify primitive — the public surface of Atropos.
    /// Vendored ref10 math + SHA-512 (Chaos.NaCl, public domain) live under <c>ThirdParty/Ed25519/</c> and are
    /// used verbatim; this facade adds only the Zero-GC glue and a canonical <c>S &lt; L</c> check.
    /// <para>
    /// Zero-GC: after a one-time per-thread warm-up, Sign/Verify/DerivePublicKey allocate nothing on the heap.
    /// The fixed scratch (≤64 B buffers + one SHA-512 instance) is kept in <c>[ThreadStatic]</c> state so it is
    /// reused across calls and is inherently thread-safe (each thread owns its own; the primitive never
    /// reenters). The variable-length message is hashed straight from the caller's span (no copy). Keeping the
    /// scratch as reused per-thread byte buffers (rather than stackalloc) lets the vendored ref10 scalar/group
    /// code stay byte-for-byte unmodified.
    /// </para>
    /// <para>
    /// Plain Ed25519 (no context, no prehash): RFC 8032 deterministic, so signatures are byte-identical across
    /// any conformant implementation. Verify rejects a non-canonical S, so signatures are non-malleable.
    /// </para>
    /// </summary>
    public static class Ed25519
    {
        public const int SeedSize = 32;
        public const int PublicKeySize = 32;
        public const int SignatureSize = 64;

        /// <summary>Derives the 32-byte public key from a 32-byte private seed.</summary>
        public static void DerivePublicKey(ReadOnlySpan<byte> seed, Span<byte> publicKey)
        {
            if (seed.Length != SeedSize) throw new ArgumentException("seed must be 32 bytes", nameof(seed));
            if (publicKey.Length != PublicKeySize) throw new ArgumentException("publicKey must be 32 bytes", nameof(publicKey));
            var sc = Scratch.Local;
            seed.CopyTo(sc.sk.AsSpan(0, 32));
            KeypairFromSeedInSk(sc);
            sc.pk.AsSpan(0, PublicKeySize).CopyTo(publicKey);
        }

        /// <summary>Signs <paramref name="message"/> with a 32-byte private seed; writes a 64-byte signature.</summary>
        public static void Sign(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> message, Span<byte> signature)
        {
            if (seed.Length != SeedSize) throw new ArgumentException("seed must be 32 bytes", nameof(seed));
            if (signature.Length != SignatureSize) throw new ArgumentException("signature must be 64 bytes", nameof(signature));
            var sc = Scratch.Local;
            seed.CopyTo(sc.sk.AsSpan(0, 32));

            var h = sc.hasher;
            // az = SHA512(seed) computed ONCE; a = clamp(az[0..32]); prefix = az[32..64].
            h.Init(); h.Update(sc.sk, 0, 32); h.Finish(new ArraySegment<byte>(sc.az, 0, 64));
            ScalarOperations.sc_clamp(sc.az, 0);
            // A = [a]B ; publicKey = A  (derived from the same az — no second seed hash)
            GroupOperations.ge_scalarmult_base(out GroupElementP3 A, sc.az, 0);
            GroupOperations.ge_p3_tobytes(sc.pk, 0, ref A);
            // r = SHA512(prefix || M) mod L ; R = [r]B
            h.Init(); h.Update(sc.az, 32, 32); h.Update(message); h.Finish(new ArraySegment<byte>(sc.r, 0, 64));
            ScalarOperations.sc_reduce(sc.r);
            GroupOperations.ge_scalarmult_base(out GroupElementP3 R, sc.r, 0);
            GroupOperations.ge_p3_tobytes(sc.sig, 0, ref R);
            // k = SHA512(R || A || M) mod L ; S = (r + k*a) mod L
            h.Init(); h.Update(sc.sig, 0, 32); h.Update(sc.pk, 0, 32); h.Update(message); h.Finish(new ArraySegment<byte>(sc.hram, 0, 64));
            ScalarOperations.sc_reduce(sc.hram);
            ScalarOperations.sc_muladd(sc.s, sc.hram, sc.az, sc.r);
            Array.Copy(sc.s, 0, sc.sig, 32, 32);

            sc.sig.AsSpan(0, SignatureSize).CopyTo(signature);
        }

        /// <summary>Verifies <paramref name="signature"/> over <paramref name="message"/> under the 32-byte public key.</summary>
        public static bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
        {
            if (publicKey.Length != PublicKeySize) return false;
            if (signature.Length != SignatureSize) return false;
            var sc = Scratch.Local;
            signature.CopyTo(sc.sig.AsSpan(0, 64));
            publicKey.CopyTo(sc.pk.AsSpan(0, 32));

            // Reject the top 3 bits of S being set (cheap pre-check) ...
            if ((sc.sig[63] & 224) != 0) return false;
            // ... and reject any non-canonical S (S >= L), so a malleated (R, S+L) signature is not accepted.
            if (!ScalarIsCanonical(sc)) return false;

            if (GroupOperations.ge_frombytes_negate_vartime(out GroupElementP3 A, sc.pk, 0) != 0)
                return false;

            var h = sc.hasher;
            h.Init(); h.Update(sc.sig, 0, 32); h.Update(sc.pk, 0, 32); h.Update(message); h.Finish(new ArraySegment<byte>(sc.h, 0, 64));
            ScalarOperations.sc_reduce(sc.h);

            Array.Copy(sc.sig, 32, sc.sm32, 0, 32);
            GroupOperations.ge_double_scalarmult_vartime(out GroupElementP2 R, sc.h, ref A, sc.sm32);
            GroupOperations.ge_tobytes(sc.checkr, 0, ref R);
            return CryptoBytes.ConstantTimeEquals(sc.checkr, 0, sc.sig, 0, 32);
        }

        // Runs the vendored crypto_sign_keypair logic on the reused scratch: sc.sk[0..32] holds the seed on
        // entry; on exit sc.pk = public key and sc.sk[32..64] = public key (expanded form crypto_sign2 needs).
        private static void KeypairFromSeedInSk(Scratch sc)
        {
            var h = sc.hasher;
            h.Init(); h.Update(sc.sk, 0, 32); h.Finish(new ArraySegment<byte>(sc.h, 0, 64));
            ScalarOperations.sc_clamp(sc.h, 0);
            GroupOperations.ge_scalarmult_base(out GroupElementP3 A, sc.h, 0);
            GroupOperations.ge_p3_tobytes(sc.pk, 0, ref A);
            Array.Copy(sc.pk, 0, sc.sk, 32, 32);
        }

        // Canonical S < L test WITHOUT hardcoding the group order: zero-extend S (sig[32..64]) to 64 bytes and
        // run sc_reduce (which computes value mod L into the low 32 bytes). S is canonical iff the reduction is
        // a no-op, i.e. reduced == original S. This reuses the existing reducer and needs no order constant.
        private static bool ScalarIsCanonical(Scratch sc)
        {
            Array.Copy(sc.sig, 32, sc.canon, 0, 32);
            Array.Clear(sc.canon, 32, 32);
            ScalarOperations.sc_reduce(sc.canon); // sc.canon[0..32] = S mod L
            return CryptoBytes.ConstantTimeEquals(sc.canon, 0, sc.sig, 32, 32);
        }

        // Per-thread reusable scratch — allocated once per thread, then zero heap per call. Thread-safe by
        // isolation (no cross-thread sharing; Ed25519 never reenters on one thread).
        private sealed class Scratch
        {
            [ThreadStatic] private static Scratch _local;
            public static Scratch Local => _local ?? (_local = new Scratch());

            public readonly Sha512 hasher = new Sha512();
            public readonly byte[] sk = new byte[64];
            public readonly byte[] pk = new byte[32];
            public readonly byte[] sig = new byte[64];
            public readonly byte[] az = new byte[64];
            public readonly byte[] r = new byte[64];
            public readonly byte[] hram = new byte[64];
            public readonly byte[] s = new byte[32];
            public readonly byte[] h = new byte[64];
            public readonly byte[] checkr = new byte[32];
            public readonly byte[] sm32 = new byte[32];
            public readonly byte[] canon = new byte[64];
        }
    }
}
