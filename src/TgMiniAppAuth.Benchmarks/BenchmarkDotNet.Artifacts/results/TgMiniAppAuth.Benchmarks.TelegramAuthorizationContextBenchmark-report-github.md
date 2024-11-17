```

BenchmarkDotNet v0.14.0, macOS Ventura 13.3.1 (a) (22E772610a) [Darwin 22.4.0]
Apple M1 2.40GHz, 1 CPU, 8 logical and 8 physical cores
.NET SDK 8.0.303
  [Host]     : .NET 8.0.7 (8.0.724.31311), X64 RyuJIT SSE4.2
  DefaultJob : .NET 8.0.7 (8.0.724.31311), X64 RyuJIT SSE4.2


```
| Method       | Mean     | Error     | StdDev    | Median   | Allocated |
|------------- |---------:|----------:|----------:|---------:|----------:|
| IsValid      | 8.169 μs | 0.3619 μs | 1.0615 μs | 8.040 μs |   7.55 KB |
| IsValidSpans | 7.286 μs | 0.1719 μs | 0.4904 μs | 7.054 μs |   2.79 KB |
