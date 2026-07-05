using NUnit.Framework;
using Chaos.NaCl.Tests;

namespace xpTURN.Atropos.Tests
{
    // RFC 8032 §7.1 known-answer vectors (1024 cases): deterministic signatures must be byte-identical,
    // verify must accept, and the derived public key must match the vector.
    [TestFixture]
    public class Ed25519KatTests
    {
        [Test]
        public void Rfc8032_KnownAnswerVectors_SignVerifyDerive()
        {
            var pk = new byte[Ed25519.PublicKeySize];
            var sig = new byte[Ed25519.SignatureSize];
            int n = 0;
            foreach (var tc in Ed25519TestVectors.TestCases)
            {
                Ed25519.DerivePublicKey(tc.Seed, pk);
                Assert.That(pk, Is.EqualTo(tc.PublicKey), $"derive pubkey #{n}");
                Ed25519.Sign(tc.Seed, tc.Message, sig);
                Assert.That(sig, Is.EqualTo(tc.Signature), $"sign #{n}");
                Assert.IsTrue(Ed25519.Verify(tc.PublicKey, tc.Message, tc.Signature), $"verify #{n}");
                n++;
            }
            Assert.That(n, Is.EqualTo(1024), "expected 1024 RFC 8032 vectors");
        }
    }
}
