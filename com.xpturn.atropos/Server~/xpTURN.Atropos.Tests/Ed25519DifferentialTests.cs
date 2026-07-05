using System;
using System.Linq;
using NUnit.Framework;
using xpTURN.Atropos;
using BcEd25519 = Org.BouncyCastle.Math.EC.Rfc8032.Ed25519;

namespace xpTURN.Atropos.Tests
{
    // Differential against BouncyCastle, kept as a test-only oracle. Headless/CI only: this test references
    // the BouncyCastle NuGet, which the dependency-free Atropos package itself never does. Ed25519 is RFC 8032
    // deterministic, so Atropos and BouncyCastle must produce byte-identical signatures and cross-verify.
    [TestFixture]
    public class Ed25519DifferentialTests
    {
        [Test]
        public void Atropos_Vs_BouncyCastle_SignByteIdentical_AndCrossVerify()
        {
            var rng = new Random(0x5EED); // fixed seed for CI reproducibility (not a crypto RNG)
            int keypairs = 64;
            int[] msgLens = { 0, 1, 2, 31, 32, 33, 64, 127, 128, 129, 500 };

            for (int k = 0; k < keypairs; k++)
            {
                var seed = new byte[32];
                rng.NextBytes(seed);

                var pkBc = new byte[32];
                BcEd25519.GeneratePublicKey(seed, 0, pkBc, 0);
                var pkAt = new byte[32];
                Ed25519.DerivePublicKey(seed, pkAt);
                Assert.That(pkAt, Is.EqualTo(pkBc), $"pubkey mismatch, keypair {k}");

                // BC's Sign expects sk = seed(32) || publicKey(32).
                var skBc = new byte[64];
                Array.Copy(seed, 0, skBc, 0, 32);
                Array.Copy(pkBc, 0, skBc, 32, 32);

                foreach (var len in msgLens)
                {
                    var msg = new byte[len];
                    rng.NextBytes(msg);

                    var sigBc = new byte[64];
                    BcEd25519.Sign(skBc, 0, msg, 0, msg.Length, sigBc, 0);

                    var sigAt = new byte[64];
                    Ed25519.Sign(seed, msg, sigAt);

                    Assert.That(sigAt, Is.EqualTo(sigBc), $"signature mismatch, keypair {k}, len {len}");

                    // Cross-verify both directions.
                    Assert.IsTrue(Ed25519.Verify(pkBc, msg, sigBc), $"Atropos rejected BC sig, k{k} len{len}");
                    Assert.IsTrue(BcEd25519.Verify(sigAt, 0, pkAt, 0, msg, 0, msg.Length), $"BC rejected Atropos sig, k{k} len{len}");
                }
            }
        }
    }
}
