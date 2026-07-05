using System.Runtime.CompilerServices;

// Exposes internal helpers to the Atropos test assembly (Zero-GC benchmarks / white-box KAT).
[assembly: InternalsVisibleTo("xpTURN.Atropos.Tests")]
