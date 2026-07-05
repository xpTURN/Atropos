using System;
using NUnit.Framework;
using Chaos.NaCl.Tests;

namespace xpTURN.Atropos.Tests
{
    // Zero-GC: at steady state (after per-thread warm-up) Sign/Verify/DerivePublicKey must allocate 0 bytes.
    // Uses GC.GetAllocatedBytesForCurrentThread (portable). On Unity IL2CPP this may report 0 regardless; the
    // Unity Test Runner can additionally assert Is.Not.AllocatingGCMemory — kept API-portable here.
    [TestFixture]
    public class Ed25519ZeroGcTests
    {
        [Test]
        public void SignVerifyDerive_ZeroAllocationSteadyState()
        {
            var t = Ed25519TestVectors.TestCases[3];
            var seed = t.Seed;
            var msg = t.Message;
            var sig = new byte[Ed25519.SignatureSize];
            var pk = new byte[Ed25519.PublicKeySize];

            // Warm-up: JIT + one-time per-thread scratch allocation.
            for (int i = 0; i < 64; i++)
            {
                Ed25519.Sign(seed, msg, sig);
                Ed25519.Verify(t.PublicKey, msg, sig);
                Ed25519.DerivePublicKey(seed, pk);
            }

            const int iter = 2000;
            long before = GC.GetAllocatedBytesForCurrentThread();
            for (int i = 0; i < iter; i++)
            {
                Ed25519.Sign(seed, msg, sig);
                Ed25519.Verify(t.PublicKey, msg, sig);
                Ed25519.DerivePublicKey(seed, pk);
            }
            long delta = GC.GetAllocatedBytesForCurrentThread() - before;
            Assert.That(delta, Is.EqualTo(0), $"expected 0 alloc, got {delta}B over {iter * 3} calls");
        }
    }
}
