```

BenchmarkDotNet v0.14.0, macOS Ventura 13.3.1 (a) (22E772610a) [Darwin 22.4.0]
Apple M1 2.40GHz, 1 CPU, 8 logical and 8 physical cores
.NET SDK 8.0.303
  [Host]     : .NET 8.0.7 (8.0.724.31311), X64 RyuJIT SSE4.2
  DefaultJob : .NET 8.0.7 (8.0.724.31311), X64 RyuJIT SSE4.2


```
| Method       | Mean     | Error     | StdDev    | Allocated |
|------------- |---------:|----------:|----------:|----------:|
| IsValid      | 7.671 μs | 0.1227 μs | 0.1680 μs |   7.55 KB |
| IsValidSpans | 7.137 μs | 0.0933 μs | 0.0779 μs |   3.18 KB |
