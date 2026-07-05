using System;
using System.Linq;
using NUnit.Framework;
using Chaos.NaCl.Internal.Ed25519Ref10;

namespace xpTURN.Atropos.Tests
{
    // Differential guard for the Karatsuba fe_mul/fe_sq (vs the retained schoolbook oracle). Step 0 proved the
    // formulas are algebraically identical for all inputs; this test's job is to confirm the C# transcription
    // faithfully realizes that proof and that int64 arithmetic holds at the worst-case input magnitudes.
    // Requires bit-identical (x0..x9) output, not just field-value equality.
    [TestFixture]
    public class Ed25519FieldKaratsubaTests
    {
        // ref10 fe_mul/fe_sq precondition: |even limb| <= 1.65*2^26, |odd limb| <= 1.65*2^25.
        private static readonly int[] MaxMag =
        {
            (int)(1.65 * (1 << 26)), (int)(1.65 * (1 << 25)),
            (int)(1.65 * (1 << 26)), (int)(1.65 * (1 << 25)),
            (int)(1.65 * (1 << 26)), (int)(1.65 * (1 << 25)),
            (int)(1.65 * (1 << 26)), (int)(1.65 * (1 << 25)),
            (int)(1.65 * (1 << 26)), (int)(1.65 * (1 << 25)),
        };

        private static FieldElement FE(int[] x)
        {
            var e = new FieldElement();
            e.x0 = x[0]; e.x1 = x[1]; e.x2 = x[2]; e.x3 = x[3]; e.x4 = x[4];
            e.x5 = x[5]; e.x6 = x[6]; e.x7 = x[7]; e.x8 = x[8]; e.x9 = x[9];
            return e;
        }

        private static int[] Limbs(in FieldElement e)
            => new[] { e.x0, e.x1, e.x2, e.x3, e.x4, e.x5, e.x6, e.x7, e.x8, e.x9 };

        private static void CheckMul(int[] fa, int[] ga)
        {
            var f = FE(fa); var g = FE(ga);
            FieldOperations.fe_mul(out var hk, ref f, ref g);
            var f2 = FE(fa); var g2 = FE(ga);
            FieldOperations.fe_mul_schoolbook(out var hs, ref f2, ref g2);
            if (!Limbs(hk).SequenceEqual(Limbs(hs)))
                Assert.Fail($"fe_mul != schoolbook\n f=[{string.Join(",", fa)}]\n g=[{string.Join(",", ga)}]\n kara  =[{string.Join(",", Limbs(hk))}]\n school=[{string.Join(",", Limbs(hs))}]");
        }

        private static void CheckSq(int[] fa)
        {
            var f = FE(fa);
            FieldOperations.fe_sq(out var hk, ref f);
            var f2 = FE(fa);
            FieldOperations.fe_sq_schoolbook(out var hs, ref f2);
            if (!Limbs(hk).SequenceEqual(Limbs(hs)))
                Assert.Fail($"fe_sq != schoolbook\n f=[{string.Join(",", fa)}]\n kara  =[{string.Join(",", Limbs(hk))}]\n school=[{string.Join(",", Limbs(hs))}]");
        }

        private static int[] RandLimbs(Random r)
        {
            var x = new int[10];
            for (int i = 0; i < 10; i++) x[i] = r.Next(-MaxMag[i], MaxMag[i] + 1);
            return x;
        }

        // Reduced-magnitude limbs (~fe_mul/fe_sq postcondition: even <= 2^25, odd <= 2^24). fe_add/fe_sub of two
        // such stays within the fe_mul precondition (<= ~2^26 / 2^25 < 1.65*2^26), matching what ge_* actually
        // feeds — feeding two precondition-MAX limbs into fe_add would instead be 2x out of spec.
        private static int[] RandReduced(Random r)
        {
            var x = new int[10];
            for (int i = 0; i < 10; i++)
            {
                int b = i % 2 == 0 ? (1 << 25) : (1 << 24);
                x[i] = r.Next(-b, b + 1);
            }
            return x;
        }

        // ── ① max-magnitude / boundary (the int64-overflow probes) ──
        [Test]
        public void FeMul_MaxMagnitude_AllSignCombos()
        {
            // all-+max, all--max, alternating, and per-limb single extreme; both operands at extreme.
            int[] pos = (int[])MaxMag.Clone();
            int[] neg = MaxMag.Select(v => -v).ToArray();
            int[] alt = MaxMag.Select((v, i) => i % 2 == 0 ? v : -v).ToArray();
            int[][] extremes = { pos, neg, alt };
            foreach (var a in extremes)
                foreach (var b in extremes)
                    CheckMul(a, b);

            var r = new Random(0x5EED);
            for (int it = 0; it < 20000; it++)
            {
                // each limb at +/- its max magnitude with random sign (worst-case magnitude, random signs)
                int[] a = new int[10], b = new int[10];
                for (int i = 0; i < 10; i++) { a[i] = (r.Next(2) == 0 ? 1 : -1) * MaxMag[i]; b[i] = (r.Next(2) == 0 ? 1 : -1) * MaxMag[i]; }
                CheckMul(a, b);
            }
        }

        [Test]
        public void FeMul_SmokeEdges()
        {
            int[] zero = new int[10];
            int[] one = new int[10]; one[0] = 1;
            CheckMul(zero, zero); CheckMul(one, one); CheckMul(zero, one);
            var r = new Random(1);
            CheckMul(RandLimbs(r), one); CheckMul(zero, RandLimbs(r));
        }

        // ── ⑤ random sweep (transcription-typo net) ──
        [Test]
        public void FeMul_RandomSweep()
        {
            var r = new Random(0x5EED);
            for (int i = 0; i < 300000; i++) CheckMul(RandLimbs(r), RandLimbs(r));
        }

        // ── ④ non-reduced inputs as ge_* feeds them (from fe_add/fe_sub outputs) ──
        [Test]
        public void FeMul_NonReducedInputs()
        {
            var r = new Random(0x5EED);
            for (int i = 0; i < 100000; i++)
            {
                var a = FE(RandReduced(r)); var b = FE(RandReduced(r));
                var c = FE(RandReduced(r)); var d = FE(RandReduced(r));
                FieldOperations.fe_add(out var ab, ref a, ref b);   // in-spec unreduced sum, as fed into ge_* multiplies
                FieldOperations.fe_sub(out var cd, ref c, ref d);
                CheckMul(Limbs(ab), Limbs(cd));
            }
        }

        // ── ② aliasing: h overlaps f/g (ref10 contract) ──
        [Test]
        public void FeMul_Aliasing_OutOverlapsInput()
        {
            var r = new Random(7);
            for (int i = 0; i < 5000; i++)
            {
                int[] fa = RandLimbs(r), ga = RandLimbs(r);
                // expected via distinct-out schoolbook
                var fs = FE(fa); var gs = FE(ga);
                FieldOperations.fe_mul_schoolbook(out var expected, ref fs, ref gs);

                // h aliases f
                var a = FE(fa); var b = FE(ga);
                FieldOperations.fe_mul(out a, ref a, ref b);
                Assert.That(Limbs(a), Is.EqualTo(Limbs(expected)), "h aliases f");

                // h aliases g
                var a2 = FE(fa); var b2 = FE(ga);
                FieldOperations.fe_mul(out b2, ref a2, ref b2);
                Assert.That(Limbs(b2), Is.EqualTo(Limbs(expected)), "h aliases g");
            }
        }

        // ── fe_sq: same battery ──
        [Test]
        public void FeSq_MaxMagnitude()
        {
            CheckSq((int[])MaxMag.Clone());
            CheckSq(MaxMag.Select(v => -v).ToArray());
            CheckSq(MaxMag.Select((v, i) => i % 2 == 0 ? v : -v).ToArray());
            var r = new Random(0x5EED);
            for (int it = 0; it < 20000; it++)
            {
                int[] a = new int[10];
                for (int i = 0; i < 10; i++) a[i] = (r.Next(2) == 0 ? 1 : -1) * MaxMag[i];
                CheckSq(a);
            }
        }

        [Test]
        public void FeSq_RandomSweep()
        {
            var r = new Random(0x5EED);
            for (int i = 0; i < 300000; i++) CheckSq(RandLimbs(r));
        }

        [Test]
        public void FeSq_NonReducedInputs()
        {
            var r = new Random(0x5EED);
            for (int i = 0; i < 100000; i++)
            {
                var a = FE(RandReduced(r)); var b = FE(RandReduced(r));
                FieldOperations.fe_add(out var ab, ref a, ref b);
                CheckSq(Limbs(ab));
            }
        }

        [Test]
        public void FeSq_Aliasing_OutOverlapsInput()
        {
            var r = new Random(11);
            for (int i = 0; i < 5000; i++)
            {
                int[] fa = RandLimbs(r);
                var fs = FE(fa);
                FieldOperations.fe_sq_schoolbook(out var expected, ref fs);
                var a = FE(fa);
                FieldOperations.fe_sq(out a, ref a);
                Assert.That(Limbs(a), Is.EqualTo(Limbs(expected)), "fe_sq h aliases f");
            }
        }

        // ── ③ cross-oracle: fe_sq(a) == fe_mul(a,a) ──
        [Test]
        public void FeSq_EqualsMulWithSelf()
        {
            var r = new Random(0x5EED);
            for (int i = 0; i < 100000; i++)
            {
                int[] fa = RandLimbs(r);
                var f1 = FE(fa);
                FieldOperations.fe_sq(out var sq, ref f1);
                var f2 = FE(fa); var f3 = FE(fa);
                FieldOperations.fe_mul(out var mul, ref f2, ref f3);
                Assert.That(Limbs(sq), Is.EqualTo(Limbs(mul)), "fe_sq(a) must equal fe_mul(a,a)");
            }
        }
    }
}
