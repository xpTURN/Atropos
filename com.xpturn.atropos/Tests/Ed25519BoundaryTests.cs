using System;
using System.Linq;
using System.Numerics;
using NUnit.Framework;
using Chaos.NaCl.Tests;

namespace xpTURN.Atropos.Tests
{
    // Negative / boundary cases. Judged against a fixed spec (RFC 8032 + rejection of malleated signatures),
    // not against another implementation's edge-case quirks.
    [TestFixture]
    public class Ed25519BoundaryTests
    {
        // Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493 (test-only constant).
        private static readonly BigInteger L =
            BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");

        private static Ed25519TestVectors.TestTuple Sample => Ed25519TestVectors.TestCases[3];

        [Test]
        public void Rejects_TamperedMessage()
        {
            var t = Sample;
            var msg = (byte[])t.Message.Clone();
            if (msg.Length == 0) msg = new byte[] { 0x01 }; else msg[0] ^= 0x01;
            Assert.IsFalse(Ed25519.Verify(t.PublicKey, msg, t.Signature));
        }

        [Test]
        public void Rejects_TamperedSignature()
        {
            var t = Sample;
            var sig = (byte[])t.Signature.Clone();
            sig[0] ^= 0x01;
            Assert.IsFalse(Ed25519.Verify(t.PublicKey, t.Message, sig));
        }

        [Test]
        public void Rejects_WrongKey()
        {
            var t = Sample;
            var other = Ed25519TestVectors.TestCases[4].PublicKey;
            Assert.IsFalse(Ed25519.Verify(other, t.Message, t.Signature));
        }

        [Test]
        public void Rejects_WrongLengths()
        {
            var t = Sample;
            Assert.IsFalse(Ed25519.Verify(t.PublicKey, t.Message, new byte[63]), "sig too short");
            Assert.IsFalse(Ed25519.Verify(new byte[31], t.Message, t.Signature), "pk too short");
        }

        [Test]
        public void Rejects_AllZeroSignature()
        {
            var t = Sample;
            Assert.IsFalse(Ed25519.Verify(t.PublicKey, t.Message, new byte[64]));
        }

        // Malleability: (R, S+L) satisfies the verify equation (since [L]B = identity) but S+L is non-canonical.
        // A verifier without the S<L check would accept it; Atropos must reject.
        [Test]
        public void Rejects_NonCanonicalS_Malleability()
        {
            var t = Sample;
            Assert.IsTrue(Ed25519.Verify(t.PublicKey, t.Message, t.Signature), "baseline valid");

            var s = new BigInteger(t.Signature.Skip(32).Take(32).Concat(new byte[] { 0 }).ToArray()); // force +
            var sp = s + L;
            var spBytes = sp.ToByteArray(); // little-endian
            var malleated = new byte[64];
            Array.Copy(t.Signature, 0, malleated, 0, 32); // same R
            for (int i = 0; i < 32; i++) malleated[32 + i] = i < spBytes.Length ? spBytes[i] : (byte)0;

            Assert.IsFalse(Ed25519.Verify(t.PublicKey, t.Message, malleated), "non-canonical S (S+L) must be rejected");
        }
    }
}
