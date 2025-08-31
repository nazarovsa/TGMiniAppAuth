```

BenchmarkDotNet v0.14.0, macOS Sequoia 15.6.1 (24G90) [Darwin 24.6.0]
Apple M1 2.40GHz, 1 CPU, 8 logical and 8 physical cores
.NET SDK 8.0.303
  [Host]     : .NET 8.0.7 (8.0.724.31311), X64 RyuJIT SSE4.2
  DefaultJob : .NET 8.0.7 (8.0.724.31311), X64 RyuJIT SSE4.2


```
| Method           | Mean     | Error     | StdDev    | Allocated |
|----------------- |---------:|----------:|----------:|----------:|
| IsValid          | 7.005 μs | 0.0927 μs | 0.0867 μs |    2856 B |
| IsValidOptimized | 7.659 μs | 0.0866 μs | 0.0810 μs |         - |
