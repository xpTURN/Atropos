using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using Chaos.NaCl.Tests;

namespace xpTURN.Atropos.Tests
{
    // Thread-safety. The [ThreadStatic] per-thread scratch must isolate concurrent callers: N threads
    // signing/verifying/deriving simultaneously must all produce correct results with no cross-thread corruption.
    [TestFixture]
    public class Ed25519ThreadSafetyTests
    {
        [Test]
        public void Concurrent_SignVerifyDerive_NoCorruption()
        {
            var cases = Ed25519TestVectors.TestCases;
            const int threads = 8, repsPerThread = 200;
            int errors = 0;

            Parallel.For(0, threads, t =>
            {
                var sig = new byte[Ed25519.SignatureSize];
                var pk = new byte[Ed25519.PublicKeySize];
                for (int rep = 0; rep < repsPerThread; rep++)
                {
                    var tc = cases[(t * 37 + rep) % cases.Count];
                    Ed25519.DerivePublicKey(tc.Seed, pk);
                    if (!pk.SequenceEqual(tc.PublicKey)) Interlocked.Increment(ref errors);
                    Ed25519.Sign(tc.Seed, tc.Message, sig);
                    if (!sig.SequenceEqual(tc.Signature)) Interlocked.Increment(ref errors);
                    if (!Ed25519.Verify(tc.PublicKey, tc.Message, tc.Signature)) Interlocked.Increment(ref errors);
                }
            });

            Assert.That(errors, Is.EqualTo(0), "concurrent operations must not corrupt shared state");
        }
    }
}
