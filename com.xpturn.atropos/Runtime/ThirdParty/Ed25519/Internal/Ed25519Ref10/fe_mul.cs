using System;

namespace Chaos.NaCl.Internal.Ed25519Ref10
{
	internal static partial class FieldOperations
	{
		// ===== Atropos change (vs upstream): even/odd (radix-2^51) Karatsuba fe_mul =====
		// Replaces the schoolbook 10x10 (100 int64 muls) with a 5+5 even/odd split (75 muls). Produces the
		// SAME pre-carry h0..h9 integers as fe_mul_schoolbook, then runs the identical carry chain, so the
		// output is byte-identical for every input. Correctness (h_i identity) and int64 safety (worst
		// |accumulator| = 2^61.52 < 2^63, under |even|<=1.65*2^26 / |odd|<=1.65*2^25) were proven symbolically
		// before coding. The retained fe_mul_schoolbook below is the differential-test oracle.
		internal static void fe_mul(out FieldElement h, ref FieldElement f, ref FieldElement g)
		{
			// Read all inputs into locals first — the ref10 contract allows h to overlap f or g.
			int f0 = f.x0, f1 = f.x1, f2 = f.x2, f3 = f.x3, f4 = f.x4, f5 = f.x5, f6 = f.x6, f7 = f.x7, f8 = f.x8, f9 = f.x9;
			int g0 = g.x0, g1 = g.x1, g2 = g.x2, g3 = g.x3, g4 = g.x4, g5 = g.x5, g6 = g.x6, g7 = g.x7, g8 = g.x8, g9 = g.x9;

			// Even/odd sum-limbs for the Karatsuba middle term (each fits int32: <= 1.65*2^26 + 1.65*2^25).
			int sf0 = f0 + f1, sf1 = f2 + f3, sf2 = f4 + f5, sf3 = f6 + f7, sf4 = f8 + f9;
			int sg0 = g0 + g1, sg1 = g2 + g3, sg2 = g4 + g5, sg3 = g6 + g7, sg4 = g8 + g9;

			// EE = conv(even f, even g)  [f0,f2,f4,f6,f8] x [g0,g2,g4,g6,g8]
			long ee0 = (long)f0 * g0;
			long ee1 = (long)f0 * g2 + (long)f2 * g0;
			long ee2 = (long)f0 * g4 + (long)f2 * g2 + (long)f4 * g0;
			long ee3 = (long)f0 * g6 + (long)f2 * g4 + (long)f4 * g2 + (long)f6 * g0;
			long ee4 = (long)f0 * g8 + (long)f2 * g6 + (long)f4 * g4 + (long)f6 * g2 + (long)f8 * g0;
			long ee5 = (long)f2 * g8 + (long)f4 * g6 + (long)f6 * g4 + (long)f8 * g2;
			long ee6 = (long)f4 * g8 + (long)f6 * g6 + (long)f8 * g4;
			long ee7 = (long)f6 * g8 + (long)f8 * g6;
			long ee8 = (long)f8 * g8;

			// OO = conv(odd f, odd g)  [f1,f3,f5,f7,f9] x [g1,g3,g5,g7,g9]
			long oo0 = (long)f1 * g1;
			long oo1 = (long)f1 * g3 + (long)f3 * g1;
			long oo2 = (long)f1 * g5 + (long)f3 * g3 + (long)f5 * g1;
			long oo3 = (long)f1 * g7 + (long)f3 * g5 + (long)f5 * g3 + (long)f7 * g1;
			long oo4 = (long)f1 * g9 + (long)f3 * g7 + (long)f5 * g5 + (long)f7 * g3 + (long)f9 * g1;
			long oo5 = (long)f3 * g9 + (long)f5 * g7 + (long)f7 * g5 + (long)f9 * g3;
			long oo6 = (long)f5 * g9 + (long)f7 * g7 + (long)f9 * g5;
			long oo7 = (long)f7 * g9 + (long)f9 * g7;
			long oo8 = (long)f9 * g9;

			// SS = conv(sum f, sum g)
			long ss0 = (long)sf0 * sg0;
			long ss1 = (long)sf0 * sg1 + (long)sf1 * sg0;
			long ss2 = (long)sf0 * sg2 + (long)sf1 * sg1 + (long)sf2 * sg0;
			long ss3 = (long)sf0 * sg3 + (long)sf1 * sg2 + (long)sf2 * sg1 + (long)sf3 * sg0;
			long ss4 = (long)sf0 * sg4 + (long)sf1 * sg3 + (long)sf2 * sg2 + (long)sf3 * sg1 + (long)sf4 * sg0;
			long ss5 = (long)sf1 * sg4 + (long)sf2 * sg3 + (long)sf3 * sg2 + (long)sf4 * sg1;
			long ss6 = (long)sf2 * sg4 + (long)sf3 * sg3 + (long)sf4 * sg2;
			long ss7 = (long)sf3 * sg4 + (long)sf4 * sg3;
			long ss8 = (long)sf4 * sg4;

			// MM = SS - EE - OO  (Karatsuba middle = fe*go + fo*ge)
			long mm0 = ss0 - ee0 - oo0, mm1 = ss1 - ee1 - oo1, mm2 = ss2 - ee2 - oo2, mm3 = ss3 - ee3 - oo3, mm4 = ss4 - ee4 - oo4;
			long mm5 = ss5 - ee5 - oo5, mm6 = ss6 - ee6 - oo6, mm7 = ss7 - ee7 - oo7, mm8 = ss8 - ee8 - oo8;

			// Pre-carry limbs (proven identical to schoolbook; 2^255 == 19 folded via the 19/38 factors).
			long h0 = ee0 + 19 * ee5 + 38 * oo4;
			long h1 = mm0 + 19 * mm5;
			long h2 = ee1 + 19 * ee6 + 2 * oo0 + 38 * oo5;
			long h3 = mm1 + 19 * mm6;
			long h4 = ee2 + 19 * ee7 + 2 * oo1 + 38 * oo6;
			long h5 = mm2 + 19 * mm7;
			long h6 = ee3 + 19 * ee8 + 2 * oo2 + 38 * oo7;
			long h7 = mm3 + 19 * mm8;
			long h8 = ee4 + 2 * oo3 + 38 * oo8;
			long h9 = mm4;

			// ----- carry chain: identical to fe_mul_schoolbook (unchanged) -----
			long carry0, carry1, carry2, carry3, carry4, carry5, carry6, carry7, carry8, carry9;
			carry0 = (h0 + (long)(1 << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
			carry4 = (h4 + (long)(1 << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
			carry1 = (h1 + (long)(1 << 24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
			carry5 = (h5 + (long)(1 << 24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
			carry2 = (h2 + (long)(1 << 25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
			carry6 = (h6 + (long)(1 << 25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
			carry3 = (h3 + (long)(1 << 24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
			carry7 = (h7 + (long)(1 << 24)) >> 25; h8 += carry7; h7 -= carry7 << 25;
			carry4 = (h4 + (long)(1 << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
			carry8 = (h8 + (long)(1 << 25)) >> 26; h9 += carry8; h8 -= carry8 << 26;
			carry9 = (h9 + (long)(1 << 24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
			carry0 = (h0 + (long)(1 << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;

			h.x0 = (int)h0; h.x1 = (int)h1; h.x2 = (int)h2; h.x3 = (int)h3; h.x4 = (int)h4;
			h.x5 = (int)h5; h.x6 = (int)h6; h.x7 = (int)h7; h.x8 = (int)h8; h.x9 = (int)h9;
		}

		/*
		h = f * g
		Can overlap h with f or g.

		Preconditions:
		   |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.
		   |g| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.

		Postconditions:
		   |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
		*/

		/*
		Notes on implementation strategy:

		Using schoolbook multiplication.
		Karatsuba would save a little in some cost models.

		Most multiplications by 2 and 19 are 32-bit precomputations;
		cheaper than 64-bit postcomputations.

		There is one remaining multiplication by 19 in the carry chain;
		one *19 precomputation can be merged into this,
		but the resulting data flow is considerably less clean.

		There are 12 carries below.
		10 of them are 2-way parallelizable and vectorizable.
		Can get away with 11 carries, but then data flow is much deeper.

		With tighter constraints on inputs can squeeze carries into int32.
		*/

		// Retained verbatim ref10 schoolbook (renamed) — the differential-test oracle for the Karatsuba fe_mul above.
		internal static void fe_mul_schoolbook(out FieldElement h, ref FieldElement f, ref FieldElement g)
		{
			Int32 f0 = f.x0;
			Int32 f1 = f.x1;
			Int32 f2 = f.x2;
			Int32 f3 = f.x3;
			Int32 f4 = f.x4;
			Int32 f5 = f.x5;
			Int32 f6 = f.x6;
			Int32 f7 = f.x7;
			Int32 f8 = f.x8;
			Int32 f9 = f.x9;
			Int32 g0 = g.x0;
			Int32 g1 = g.x1;
			Int32 g2 = g.x2;
			Int32 g3 = g.x3;
			Int32 g4 = g.x4;
			Int32 g5 = g.x5;
			Int32 g6 = g.x6;
			Int32 g7 = g.x7;
			Int32 g8 = g.x8;
			Int32 g9 = g.x9;
			Int32 g1_19 = 19 * g1; /* 1.959375*2^29 */
			Int32 g2_19 = 19 * g2; /* 1.959375*2^30; still ok */
			Int32 g3_19 = 19 * g3;
			Int32 g4_19 = 19 * g4;
			Int32 g5_19 = 19 * g5;
			Int32 g6_19 = 19 * g6;
			Int32 g7_19 = 19 * g7;
			Int32 g8_19 = 19 * g8;
			Int32 g9_19 = 19 * g9;
			Int32 f1_2 = 2 * f1;
			Int32 f3_2 = 2 * f3;
			Int32 f5_2 = 2 * f5;
			Int32 f7_2 = 2 * f7;
			Int32 f9_2 = 2 * f9;
			Int64 f0g0 = f0 * (Int64)g0;
			Int64 f0g1 = f0 * (Int64)g1;
			Int64 f0g2 = f0 * (Int64)g2;
			Int64 f0g3 = f0 * (Int64)g3;
			Int64 f0g4 = f0 * (Int64)g4;
			Int64 f0g5 = f0 * (Int64)g5;
			Int64 f0g6 = f0 * (Int64)g6;
			Int64 f0g7 = f0 * (Int64)g7;
			Int64 f0g8 = f0 * (Int64)g8;
			Int64 f0g9 = f0 * (Int64)g9;
			Int64 f1g0 = f1 * (Int64)g0;
			Int64 f1g1_2 = f1_2 * (Int64)g1;
			Int64 f1g2 = f1 * (Int64)g2;
			Int64 f1g3_2 = f1_2 * (Int64)g3;
			Int64 f1g4 = f1 * (Int64)g4;
			Int64 f1g5_2 = f1_2 * (Int64)g5;
			Int64 f1g6 = f1 * (Int64)g6;
			Int64 f1g7_2 = f1_2 * (Int64)g7;
			Int64 f1g8 = f1 * (Int64)g8;
			Int64 f1g9_38 = f1_2 * (Int64)g9_19;
			Int64 f2g0 = f2 * (Int64)g0;
			Int64 f2g1 = f2 * (Int64)g1;
			Int64 f2g2 = f2 * (Int64)g2;
			Int64 f2g3 = f2 * (Int64)g3;
			Int64 f2g4 = f2 * (Int64)g4;
			Int64 f2g5 = f2 * (Int64)g5;
			Int64 f2g6 = f2 * (Int64)g6;
			Int64 f2g7 = f2 * (Int64)g7;
			Int64 f2g8_19 = f2 * (Int64)g8_19;
			Int64 f2g9_19 = f2 * (Int64)g9_19;
			Int64 f3g0 = f3 * (Int64)g0;
			Int64 f3g1_2 = f3_2 * (Int64)g1;
			Int64 f3g2 = f3 * (Int64)g2;
			Int64 f3g3_2 = f3_2 * (Int64)g3;
			Int64 f3g4 = f3 * (Int64)g4;
			Int64 f3g5_2 = f3_2 * (Int64)g5;
			Int64 f3g6 = f3 * (Int64)g6;
			Int64 f3g7_38 = f3_2 * (Int64)g7_19;
			Int64 f3g8_19 = f3 * (Int64)g8_19;
			Int64 f3g9_38 = f3_2 * (Int64)g9_19;
			Int64 f4g0 = f4 * (Int64)g0;
			Int64 f4g1 = f4 * (Int64)g1;
			Int64 f4g2 = f4 * (Int64)g2;
			Int64 f4g3 = f4 * (Int64)g3;
			Int64 f4g4 = f4 * (Int64)g4;
			Int64 f4g5 = f4 * (Int64)g5;
			Int64 f4g6_19 = f4 * (Int64)g6_19;
			Int64 f4g7_19 = f4 * (Int64)g7_19;
			Int64 f4g8_19 = f4 * (Int64)g8_19;
			Int64 f4g9_19 = f4 * (Int64)g9_19;
			Int64 f5g0 = f5 * (Int64)g0;
			Int64 f5g1_2 = f5_2 * (Int64)g1;
			Int64 f5g2 = f5 * (Int64)g2;
			Int64 f5g3_2 = f5_2 * (Int64)g3;
			Int64 f5g4 = f5 * (Int64)g4;
			Int64 f5g5_38 = f5_2 * (Int64)g5_19;
			Int64 f5g6_19 = f5 * (Int64)g6_19;
			Int64 f5g7_38 = f5_2 * (Int64)g7_19;
			Int64 f5g8_19 = f5 * (Int64)g8_19;
			Int64 f5g9_38 = f5_2 * (Int64)g9_19;
			Int64 f6g0 = f6 * (Int64)g0;
			Int64 f6g1 = f6 * (Int64)g1;
			Int64 f6g2 = f6 * (Int64)g2;
			Int64 f6g3 = f6 * (Int64)g3;
			Int64 f6g4_19 = f6 * (Int64)g4_19;
			Int64 f6g5_19 = f6 * (Int64)g5_19;
			Int64 f6g6_19 = f6 * (Int64)g6_19;
			Int64 f6g7_19 = f6 * (Int64)g7_19;
			Int64 f6g8_19 = f6 * (Int64)g8_19;
			Int64 f6g9_19 = f6 * (Int64)g9_19;
			Int64 f7g0 = f7 * (Int64)g0;
			Int64 f7g1_2 = f7_2 * (Int64)g1;
			Int64 f7g2 = f7 * (Int64)g2;
			Int64 f7g3_38 = f7_2 * (Int64)g3_19;
			Int64 f7g4_19 = f7 * (Int64)g4_19;
			Int64 f7g5_38 = f7_2 * (Int64)g5_19;
			Int64 f7g6_19 = f7 * (Int64)g6_19;
			Int64 f7g7_38 = f7_2 * (Int64)g7_19;
			Int64 f7g8_19 = f7 * (Int64)g8_19;
			Int64 f7g9_38 = f7_2 * (Int64)g9_19;
			Int64 f8g0 = f8 * (Int64)g0;
			Int64 f8g1 = f8 * (Int64)g1;
			Int64 f8g2_19 = f8 * (Int64)g2_19;
			Int64 f8g3_19 = f8 * (Int64)g3_19;
			Int64 f8g4_19 = f8 * (Int64)g4_19;
			Int64 f8g5_19 = f8 * (Int64)g5_19;
			Int64 f8g6_19 = f8 * (Int64)g6_19;
			Int64 f8g7_19 = f8 * (Int64)g7_19;
			Int64 f8g8_19 = f8 * (Int64)g8_19;
			Int64 f8g9_19 = f8 * (Int64)g9_19;
			Int64 f9g0 = f9 * (Int64)g0;
			Int64 f9g1_38 = f9_2 * (Int64)g1_19;
			Int64 f9g2_19 = f9 * (Int64)g2_19;
			Int64 f9g3_38 = f9_2 * (Int64)g3_19;
			Int64 f9g4_19 = f9 * (Int64)g4_19;
			Int64 f9g5_38 = f9_2 * (Int64)g5_19;
			Int64 f9g6_19 = f9 * (Int64)g6_19;
			Int64 f9g7_38 = f9_2 * (Int64)g7_19;
			Int64 f9g8_19 = f9 * (Int64)g8_19;
			Int64 f9g9_38 = f9_2 * (Int64)g9_19;
			Int64 h0 = f0g0 + f1g9_38 + f2g8_19 + f3g7_38 + f4g6_19 + f5g5_38 + f6g4_19 + f7g3_38 + f8g2_19 + f9g1_38;
			Int64 h1 = f0g1 + f1g0 + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 + f7g4_19 + f8g3_19 + f9g2_19;
			Int64 h2 = f0g2 + f1g1_2 + f2g0 + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 + f7g5_38 + f8g4_19 + f9g3_38;
			Int64 h3 = f0g3 + f1g2 + f2g1 + f3g0 + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19;
			Int64 h4 = f0g4 + f1g3_2 + f2g2 + f3g1_2 + f4g0 + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38;
			Int64 h5 = f0g5 + f1g4 + f2g3 + f3g2 + f4g1 + f5g0 + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19;
			Int64 h6 = f0g6 + f1g5_2 + f2g4 + f3g3_2 + f4g2 + f5g1_2 + f6g0 + f7g9_38 + f8g8_19 + f9g7_38;
			Int64 h7 = f0g7 + f1g6 + f2g5 + f3g4 + f4g3 + f5g2 + f6g1 + f7g0 + f8g9_19 + f9g8_19;
			Int64 h8 = f0g8 + f1g7_2 + f2g6 + f3g5_2 + f4g4 + f5g3_2 + f6g2 + f7g1_2 + f8g0 + f9g9_38;
			Int64 h9 = f0g9 + f1g8 + f2g7 + f3g6 + f4g5 + f5g4 + f6g3 + f7g2 + f8g1 + f9g0;
			Int64 carry0;
			Int64 carry1;
			Int64 carry2;
			Int64 carry3;
			Int64 carry4;
			Int64 carry5;
			Int64 carry6;
			Int64 carry7;
			Int64 carry8;
			Int64 carry9;

			/*
			|h0| <= (1.65*1.65*2^52*(1+19+19+19+19)+1.65*1.65*2^50*(38+38+38+38+38))
			  i.e. |h0| <= 1.4*2^60; narrower ranges for h2, h4, h6, h8
			|h1| <= (1.65*1.65*2^51*(1+1+19+19+19+19+19+19+19+19))
			  i.e. |h1| <= 1.7*2^59; narrower ranges for h3, h5, h7, h9
			*/

			carry0 = (h0 + (Int64)(1 << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
			carry4 = (h4 + (Int64)(1 << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
			/* |h0| <= 2^25 */
			/* |h4| <= 2^25 */
			/* |h1| <= 1.71*2^59 */
			/* |h5| <= 1.71*2^59 */

			carry1 = (h1 + (Int64)(1 << 24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
			carry5 = (h5 + (Int64)(1 << 24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
			/* |h1| <= 2^24; from now on fits into int32 */
			/* |h5| <= 2^24; from now on fits into int32 */
			/* |h2| <= 1.41*2^60 */
			/* |h6| <= 1.41*2^60 */

			carry2 = (h2 + (Int64)(1 << 25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
			carry6 = (h6 + (Int64)(1 << 25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
			/* |h2| <= 2^25; from now on fits into int32 unchanged */
			/* |h6| <= 2^25; from now on fits into int32 unchanged */
			/* |h3| <= 1.71*2^59 */
			/* |h7| <= 1.71*2^59 */

			carry3 = (h3 + (Int64)(1 << 24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
			carry7 = (h7 + (Int64)(1 << 24)) >> 25; h8 += carry7; h7 -= carry7 << 25;
			/* |h3| <= 2^24; from now on fits into int32 unchanged */
			/* |h7| <= 2^24; from now on fits into int32 unchanged */
			/* |h4| <= 1.72*2^34 */
			/* |h8| <= 1.41*2^60 */

			carry4 = (h4 + (Int64)(1 << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
			carry8 = (h8 + (Int64)(1 << 25)) >> 26; h9 += carry8; h8 -= carry8 << 26;
			/* |h4| <= 2^25; from now on fits into int32 unchanged */
			/* |h8| <= 2^25; from now on fits into int32 unchanged */
			/* |h5| <= 1.01*2^24 */
			/* |h9| <= 1.71*2^59 */

			carry9 = (h9 + (Int64)(1 << 24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
			/* |h9| <= 2^24; from now on fits into int32 unchanged */
			/* |h0| <= 1.1*2^39 */

			carry0 = (h0 + (Int64)(1 << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
			/* |h0| <= 2^25; from now on fits into int32 unchanged */
			/* |h1| <= 1.01*2^24 */

			h.x0 = (Int32)h0;
			h.x1 = (Int32)h1;
			h.x2 = (Int32)h2;
			h.x3 = (Int32)h3;
			h.x4 = (Int32)h4;
			h.x5 = (Int32)h5;
			h.x6 = (Int32)h6;
			h.x7 = (Int32)h7;
			h.x8 = (Int32)h8;
			h.x9 = (Int32)h9;
		}
	}
}