// Informational micro-benchmark: Atropos Ed25519 vs BouncyCastle (the implementation it replaces).
// Measures per-op latency (ns) and per-op heap allocation (bytes) for DerivePublicKey / Sign / Verify.
//
// Run:  dotnet run -c Release  (from this folder)
//
// Expected shape: Atropos allocates 0 B/op (Zero-GC) but is modestly slower per op than BouncyCastle's
// more optimized field arithmetic. For the low-frequency (join-time) use case the latency is negligible
// and the zero allocation is the win; this bench just makes the trade-off measurable.

using System;
using System.Diagnostics;
using xpTURN.Atropos;
using Bc = Org.BouncyCastle.Math.EC.Rfc8032.Ed25519;

static (double nsPerOp, long bytesPerOp) Bench(int iters, int warmup, Action op)
{
    for (int i = 0; i < warmup; i++) op();
    GC.Collect(); GC.WaitForPendingFinalizers(); GC.Collect();
    long b0 = GC.GetAllocatedBytesForCurrentThread();
    var sw = Stopwatch.StartNew();
    for (int i = 0; i < iters; i++) op();
    sw.Stop();
    long b1 = GC.GetAllocatedBytesForCurrentThread();
    return (sw.Elapsed.TotalMilliseconds * 1_000_000.0 / iters, (b1 - b0) / iters);
}

const int ITER = 30000, WARM = 3000;
int[] sizes = { 32, 160, 1024 };

var seed = new byte[32];
for (int i = 0; i < 32; i++) seed[i] = (byte)(i + 1);

var pkAt = new byte[32]; Ed25519.DerivePublicKey(seed, pkAt);
var pkBc = new byte[32]; Bc.GeneratePublicKey(seed, 0, pkBc, 0);
var skBc = new byte[64]; Array.Copy(seed, 0, skBc, 0, 32); Array.Copy(pkBc, 0, skBc, 32, 32);

Console.WriteLine($"{"op",-22}{"Atropos ns/op",16}{"B/op",8}{"BC ns/op",14}{"B/op",8}{"speedup",10}");
Console.WriteLine(new string('-', 78));

{
    var pk = new byte[32];
    var a = Bench(ITER, WARM, () => Ed25519.DerivePublicKey(seed, pk));
    var b = Bench(ITER, WARM, () => Bc.GeneratePublicKey(seed, 0, pk, 0));
    Console.WriteLine($"{"DerivePublicKey",-22}{a.nsPerOp,13:F0}{a.bytesPerOp,10}{b.nsPerOp,11:F0}{b.bytesPerOp,10}{b.nsPerOp / a.nsPerOp,9:F2}x");
}

foreach (var sz in sizes)
{
    var msg = new byte[sz];
    for (int i = 0; i < sz; i++) msg[i] = (byte)(i * 7 + 1);
    var sigAt = new byte[64]; Ed25519.Sign(seed, msg, sigAt);
    var sigBc = new byte[64]; Bc.Sign(skBc, 0, msg, 0, msg.Length, sigBc, 0);

    var sA = Bench(ITER, WARM, () => Ed25519.Sign(seed, msg, sigAt));
    var sB = Bench(ITER, WARM, () => Bc.Sign(skBc, 0, msg, 0, msg.Length, sigBc, 0));
    Console.WriteLine($"{$"Sign (msg={sz}B)",-22}{sA.nsPerOp,13:F0}{sA.bytesPerOp,10}{sB.nsPerOp,11:F0}{sB.bytesPerOp,10}{sB.nsPerOp / sA.nsPerOp,9:F2}x");

    var vA = Bench(ITER, WARM, () => Ed25519.Verify(pkAt, msg, sigAt));
    var vB = Bench(ITER, WARM, () => Bc.Verify(sigBc, 0, pkBc, 0, msg, 0, msg.Length));
    Console.WriteLine($"{$"Verify (msg={sz}B)",-22}{vA.nsPerOp,13:F0}{vA.bytesPerOp,10}{vB.nsPerOp,11:F0}{vB.bytesPerOp,10}{vB.nsPerOp / vA.nsPerOp,9:F2}x");
}

Console.WriteLine();
Console.WriteLine("Atropos = ThreadStatic Zero-GC facade · BC = BouncyCastle 2.5.1 Rfc8032 (byte[] API)");
Console.WriteLine("net8 Release · workstation GC · numbers are machine-dependent (relative comparison only)");
