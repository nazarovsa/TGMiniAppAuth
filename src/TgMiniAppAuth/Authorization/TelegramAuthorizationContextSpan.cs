using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization.Metadata;
using System.Web;

namespace TgMiniAppAuth.Authorization;

/// <summary>
/// Telgram mini app auth context
/// </summary>
internal static class TelegramAuthorizationContextSpan
{
  /// <summary>
  /// Static value used as a key for bot token sign
  /// </summary>
  private static readonly byte[] WebAppDataBytes = "WebAppData"u8.ToArray();

  internal static bool IsValidTelegramMiniAppContext(string urlEncodedString, string token, out DateTimeOffset issuedAt)
  {
    var decodedString = HttpUtility.UrlDecode(urlEncodedString);
    var blocksCount = decodedString.Count(x => x == '&') + 1;

    AuthDataPair hashPair = default;
    var array = new AuthDataPair[blocksCount - 1];
    var startPairIndex = 0;
    var endPairIndex = decodedString.IndexOf('&', 0);
    var length = endPairIndex;
    var index = 0;
    while (startPairIndex < decodedString.Length)
    {
      var rawPair = decodedString.AsMemory(startPairIndex, length);
      var authDataPair = new AuthDataPair(rawPair);
      if (authDataPair.Key is "hash")
      {
        hashPair = authDataPair;
      }
      else
        array[index++] = authDataPair;

      startPairIndex = endPairIndex + 1;
      if (startPairIndex > decodedString.Length - 1)
        break;

      endPairIndex = decodedString.IndexOf('&', startPairIndex);
      if (endPairIndex == -1)
      {
        endPairIndex = decodedString.Length;
      }

      length = endPairIndex - startPairIndex;
    }

    Array.Sort(array);

    if (hashPair == default)
    {
      throw new ArgumentException("Key 'hash' not found");
    }

    var authDatePair = array.FirstOrDefault(x => x.Key is "auth_date");
    if (authDatePair == default)
    {
      throw new ArgumentException("Key 'auth_date' not found");
    }

    if (!long.TryParse(authDatePair.Value, out var unixAuthDate))
    {
      throw new InvalidOperationException("Failed to parse 'auth_date'");
    }

    issuedAt = DateTimeOffset.FromUnixTimeSeconds(unixAuthDate);

    var spanSize = array.Sum(x => x.Raw.Length) + (array.Length - 1);
    Span<char> miniAppCheckDataSpan = stackalloc char[spanSize];
    var spanIndex = 0;
    for (var i = 0; i < array.Length; i++)
    {
      var item = array[i];

      foreach (var ch in item.Raw.Span)
      {
        miniAppCheckDataSpan[spanIndex++] = ch;
      }

      if (i != array.Length - 1)
        miniAppCheckDataSpan[spanIndex++] = '\n';
    }

    var hash = hashPair.Value;
    Span<byte> checkDataBytes = stackalloc byte[1024];
    var checkDataBytesSize = Encoding.UTF8.GetBytes(miniAppCheckDataSpan, checkDataBytes);
    var checkDataBytesActual = checkDataBytes[..checkDataBytesSize];

    Span<byte> tokenSignedBytesSpan = stackalloc byte[32];
    Span<byte> targetHashBytesSpan = stackalloc byte[32];
    
    var tokenBytes = Encoding.UTF8.GetBytes(token); // < 256
    // Хэш токена с ключом "WebAppData"
    HMACSHA256.HashData(WebAppDataBytes, tokenBytes, tokenSignedBytesSpan);
    HMACSHA256.HashData(tokenSignedBytesSpan, checkDataBytesActual, targetHashBytesSpan);

    var targetHex = Convert.ToHexString(targetHashBytesSpan);
    
    for (var i = 0; i < hash.Length; i++)
    {
      if (Char.ToLower(hash[i]) != Char.ToLower(targetHex[i]))
        return false;
    }

    return true;
  }

  /// <summary>
  /// Represents a key-value pair of auth data.
  /// </summary>
  private readonly record struct AuthDataPair : IComparable<AuthDataPair>
  {
    private readonly int _keyLength;

    /// <summary>
    /// Gets the key of the pair.
    /// </summary>
    public ReadOnlySpan<char> Key => Raw.Slice(0, _keyLength).Span;

    /// <summary>
    /// Gets the value of the pair.
    /// </summary>
    public ReadOnlySpan<char> Value => Raw.Slice(_keyLength + 1).Span;

    /// <summary>
    /// Gets the raw pair string.
    /// </summary>
    public ReadOnlyMemory<char> Raw { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthDataPair"/> struct.
    /// </summary>
    /// <param name="pair">The key-value pair string.</param>
    /// <exception cref="ArgumentException">Thrown when the pair string is not properly formatted.</exception>
    public AuthDataPair(ReadOnlyMemory<char> pair)
    {
      ReadOnlySpan<char> span = pair.Span;
      var indexOfEquals = span.IndexOf('=');
      _keyLength = indexOfEquals;
      Raw = pair;
    }

    public int CompareTo(AuthDataPair other)
    {
      return Raw.Span.SequenceCompareTo(other.Raw.Span);
    }
  }
}