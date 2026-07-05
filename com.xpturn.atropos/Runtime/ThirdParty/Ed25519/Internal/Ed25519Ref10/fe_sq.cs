using System;

namespace Chaos.NaCl.Internal.Ed25519Ref10
{
	internal static partial class FieldOperations
	{
		// ===== Atropos change (vs upstream): even/odd (radix-2^51) Karatsuba fe_sq =====
		// Square-symmetric Karatsuba: EE = Fe^2, OO = Fo^2, SS = (Fe+Fo)^2 (15 muls each = 45), then the same
		// EE/OO/MM -> h_i mapping and carry chain as fe_mul. Produces the SAME pre-carry h0..h9 integers as
		// fe_sq_schoolbook -> byte-identical output for every input. Proven symbolically before coding; int64
		// worst |accumulator| = 2^61.52 < 2^63. fe_sq_schoolbook below is the differential-test oracle.
		internal static void fe_sq(out FieldElement h, ref FieldElement f)
		{
			// Read all inputs first — the ref10 contract allows h to overlap f.
			int f0 = f.x0, f1 = f.x1, f2 = f.x2, f3 = f.x3, f4 = f.x4, f5 = f.x5, f6 = f.x6, f7 = f.x7, f8 = f.x8, f9 = f.x9;
			int s0 = f0 + f1, s1 = f2 + f3, s2 = f4 + f5, s3 = f6 + f7, s4 = f8 + f9;

			// EE = (even)^2  [f0,f2,f4,f6,f8]
			long ee0 = (long)f0 * f0;
			long ee1 = 2 * (long)f0 * f2;
			long ee2 = 2 * (long)f0 * f4 + (long)f2 * f2;
			long ee3 = 2 * (long)f0 * f6 + 2 * (long)f2 * f4;
			long ee4 = 2 * (long)f0 * f8 + 2 * (long)f2 * f6 + (long)f4 * f4;
			long ee5 = 2 * (long)f2 * f8 + 2 * (long)f4 * f6;
			long ee6 = 2 * (long)f4 * f8 + (long)f6 * f6;
			long ee7 = 2 * (long)f6 * f8;
			long ee8 = (long)f8 * f8;

			// OO = (odd)^2  [f1,f3,f5,f7,f9]
			long oo0 = (long)f1 * f1;
			long oo1 = 2 * (long)f1 * f3;
			long oo2 = 2 * (long)f1 * f5 + (long)f3 * f3;
			long oo3 = 2 * (long)f1 * f7 + 2 * (long)f3 * f5;
			long oo4 = 2 * (long)f1 * f9 + 2 * (long)f3 * f7 + (long)f5 * f5;
			long oo5 = 2 * (long)f3 * f9 + 2 * (long)f5 * f7;
			long oo6 = 2 * (long)f5 * f9 + (long)f7 * f7;
			long oo7 = 2 * (long)f7 * f9;
			long oo8 = (long)f9 * f9;

			// SS = (even+odd)^2
			long ss0 = (long)s0 * s0;
			long ss1 = 2 * (long)s0 * s1;
			long ss2 = 2 * (long)s0 * s2 + (long)s1 * s1;
			long ss3 = 2 * (long)s0 * s3 + 2 * (long)s1 * s2;
			long ss4 = 2 * (long)s0 * s4 + 2 * (long)s1 * s3 + (long)s2 * s2;
			long ss5 = 2 * (long)s1 * s4 + 2 * (long)s2 * s3;
			long ss6 = 2 * (long)s2 * s4 + (long)s3 * s3;
			long ss7 = 2 * (long)s3 * s4;
			long ss8 = (long)s4 * s4;

			// MM = SS - EE - OO
			long mm0 = ss0 - ee0 - oo0, mm1 = ss1 - ee1 - oo1, mm2 = ss2 - ee2 - oo2, mm3 = ss3 - ee3 - oo3, mm4 = ss4 - ee4 - oo4;
			long mm5 = ss5 - ee5 - oo5, mm6 = ss6 - ee6 - oo6, mm7 = ss7 - ee7 - oo7, mm8 = ss8 - ee8 - oo8;

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

			// ----- carry chain: identical to fe_sq_schoolbook (unchanged) -----
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
		h = f * f
		Can overlap h with f.

		Preconditions:
		   |f| bounded by 1.65*2^26,1.65*2^25,1.65*2^26,1.65*2^25,etc.

		Postconditions:
		   |h| bounded by 1.01*2^25,1.01*2^24,1.01*2^25,1.01*2^24,etc.
		*/

		/*
		See fe_mul.c for discussion of implementation strategy.
		*/
		// Retained verbatim ref10 schoolbook (renamed) — the differential-test oracle for the Karatsuba fe_sq above.
		internal static void fe_sq_schoolbook(out FieldElement h, ref FieldElement f)
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
			Int32 f0_2 = 2 * f0;
			Int32 f1_2 = 2 * f1;
			Int32 f2_2 = 2 * f2;
			Int32 f3_2 = 2 * f3;
			Int32 f4_2 = 2 * f4;
			Int32 f5_2 = 2 * f5;
			Int32 f6_2 = 2 * f6;
			Int32 f7_2 = 2 * f7;
			Int32 f5_38 = 38 * f5; /* 1.959375*2^30 */
			Int32 f6_19 = 19 * f6; /* 1.959375*2^30 */
			Int32 f7_38 = 38 * f7; /* 1.959375*2^30 */
			Int32 f8_19 = 19 * f8; /* 1.959375*2^30 */
			Int32 f9_38 = 38 * f9; /* 1.959375*2^30 */
			Int64 f0f0 = f0 * (Int64)f0;
			Int64 f0f1_2 = f0_2 * (Int64)f1;
			Int64 f0f2_2 = f0_2 * (Int64)f2;
			Int64 f0f3_2 = f0_2 * (Int64)f3;
			Int64 f0f4_2 = f0_2 * (Int64)f4;
			Int64 f0f5_2 = f0_2 * (Int64)f5;
			Int64 f0f6_2 = f0_2 * (Int64)f6;
			Int64 f0f7_2 = f0_2 * (Int64)f7;
			Int64 f0f8_2 = f0_2 * (Int64)f8;
			Int64 f0f9_2 = f0_2 * (Int64)f9;
			Int64 f1f1_2 = f1_2 * (Int64)f1;
			Int64 f1f2_2 = f1_2 * (Int64)f2;
			Int64 f1f3_4 = f1_2 * (Int64)f3_2;
			Int64 f1f4_2 = f1_2 * (Int64)f4;
			Int64 f1f5_4 = f1_2 * (Int64)f5_2;
			Int64 f1f6_2 = f1_2 * (Int64)f6;
			Int64 f1f7_4 = f1_2 * (Int64)f7_2;
			Int64 f1f8_2 = f1_2 * (Int64)f8;
			Int64 f1f9_76 = f1_2 * (Int64)f9_38;
			Int64 f2f2 = f2 * (Int64)f2;
			Int64 f2f3_2 = f2_2 * (Int64)f3;
			Int64 f2f4_2 = f2_2 * (Int64)f4;
			Int64 f2f5_2 = f2_2 * (Int64)f5;
			Int64 f2f6_2 = f2_2 * (Int64)f6;
			Int64 f2f7_2 = f2_2 * (Int64)f7;
			Int64 f2f8_38 = f2_2 * (Int64)f8_19;
			Int64 f2f9_38 = f2 * (Int64)f9_38;
			Int64 f3f3_2 = f3_2 * (Int64)f3;
			Int64 f3f4_2 = f3_2 * (Int64)f4;
			Int64 f3f5_4 = f3_2 * (Int64)f5_2;
			Int64 f3f6_2 = f3_2 * (Int64)f6;
			Int64 f3f7_76 = f3_2 * (Int64)f7_38;
			Int64 f3f8_38 = f3_2 * (Int64)f8_19;
			Int64 f3f9_76 = f3_2 * (Int64)f9_38;
			Int64 f4f4 = f4 * (Int64)f4;
			Int64 f4f5_2 = f4_2 * (Int64)f5;
			Int64 f4f6_38 = f4_2 * (Int64)f6_19;
			Int64 f4f7_38 = f4 * (Int64)f7_38;
			Int64 f4f8_38 = f4_2 * (Int64)f8_19;
			Int64 f4f9_38 = f4 * (Int64)f9_38;
			Int64 f5f5_38 = f5 * (Int64)f5_38;
			Int64 f5f6_38 = f5_2 * (Int64)f6_19;
			Int64 f5f7_76 = f5_2 * (Int64)f7_38;
			Int64 f5f8_38 = f5_2 * (Int64)f8_19;
			Int64 f5f9_76 = f5_2 * (Int64)f9_38;
			Int64 f6f6_19 = f6 * (Int64)f6_19;
			Int64 f6f7_38 = f6 * (Int64)f7_38;
			Int64 f6f8_38 = f6_2 * (Int64)f8_19;
			Int64 f6f9_38 = f6 * (Int64)f9_38;
			Int64 f7f7_38 = f7 * (Int64)f7_38;
			Int64 f7f8_38 = f7_2 * (Int64)f8_19;
			Int64 f7f9_76 = f7_2 * (Int64)f9_38;
			Int64 f8f8_19 = f8 * (Int64)f8_19;
			Int64 f8f9_38 = f8 * (Int64)f9_38;
			Int64 f9f9_38 = f9 * (Int64)f9_38;
			Int64 h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
			Int64 h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
			Int64 h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
			Int64 h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
			Int64 h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
			Int64 h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
			Int64 h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
			Int64 h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
			Int64 h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
			Int64 h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;
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

			carry0 = (h0 + (Int64)(1 << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
			carry4 = (h4 + (Int64)(1 << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;

			carry1 = (h1 + (Int64)(1 << 24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
			carry5 = (h5 + (Int64)(1 << 24)) >> 25; h6 += carry5; h5 -= carry5 << 25;

			carry2 = (h2 + (Int64)(1 << 25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
			carry6 = (h6 + (Int64)(1 << 25)) >> 26; h7 += carry6; h6 -= carry6 << 26;

			carry3 = (h3 + (Int64)(1 << 24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
			carry7 = (h7 + (Int64)(1 << 24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

			carry4 = (h4 + (Int64)(1 << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
			carry8 = (h8 + (Int64)(1 << 25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

			carry9 = (h9 + (Int64)(1 << 24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;

			carry0 = (h0 + (Int64)(1 << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;

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