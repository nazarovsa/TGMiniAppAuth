using System.Buffers;
using System.Security.Cryptography;
using System.Text;
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

  /// <summary>
  /// Check that hash value valid sign of all pairs except 'hash=*' of <see cref="WebAppDataBytes"/> with the token of the telegram bot. 
  /// </summary>
  /// <param name="urlEncodedString">Signed data from telegram mini app</param>
  /// <param name="token">Token of the telegram bot</param>
  /// <param name="issuedAt">Date of signed data issued</param>
  /// <returns>Returns true if sign is valid</returns>
  /// <exception cref="ArgumentException"></exception>
  /// <exception cref="InvalidOperationException"></exception>
  internal static bool IsValidTelegramMiniAppContext(string urlEncodedString, string token, out DateTimeOffset issuedAt)
  {
    AuthDataPair hashPair = default;
    // TODO : Think about UrlDecode to Span<char>
    var decodedString = HttpUtility.UrlDecode(urlEncodedString);
    var blocksCount = decodedString.Count(x => x == '&') + 1;

    var rented = ArrayPool<AuthDataPair>.Shared.Rent(blocksCount);
    var pairs = new Span<AuthDataPair>(rented)[..(blocksCount - 1)];

    var startPairIndex = 0;
    var endPairIndex = decodedString.IndexOf('&', 0);
    var length = endPairIndex;
    var index = 0;
    while (startPairIndex < decodedString.Length)
    {
      var rawPair = decodedString.AsMemory(startPairIndex, length);
      var authDataPair = new AuthDataPair(rawPair);
      if (authDataPair.Key is "hash")
        hashPair = authDataPair;
      else
        pairs[index++] = authDataPair;

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

    pairs.Sort();

    if (hashPair == default)
    {
      throw new ArgumentException("Key 'hash' not found");
    }

    AuthDataPair authDatePair = default;
    foreach (var pair in pairs)
    {
      if (pair.Key is "auth_date")
      {
        authDatePair = pair;
        break;
      }
    }
    
    if (authDatePair == default)
    {
      throw new ArgumentException("Key 'auth_date' not found");
    }

    if (!long.TryParse(authDatePair.Value, out var unixAuthDate))
    {
      throw new InvalidOperationException("Failed to parse 'auth_date'");
    }

    issuedAt = DateTimeOffset.FromUnixTimeSeconds(unixAuthDate);

    var sum = 0;
    foreach (var pair in pairs)
    {
      sum += pair.Raw.Length;
    }
    
    // Build check string: use alphabetically sorted pairs except 'hash=*' joined with '\n'
    // Sum of all pairs + pairs.Length - 1 for '\n'
    var spanSize = sum + pairs.Length - 1;
    Span<char> miniAppCheckDataSpan = stackalloc char[spanSize];
    var spanIndex = 0;
    for (var i = 0; i < pairs.Length; i++)
    {
      var item = pairs[i];

      foreach (var ch in item.Raw.Span)
      {
        miniAppCheckDataSpan[spanIndex++] = ch;
      }

      if (i != pairs.Length - 1)
        miniAppCheckDataSpan[spanIndex++] = '\n';
    }

    ArrayPool<AuthDataPair>.Shared.Return(rented, true);
    
    Span<byte> checkDataBytes = stackalloc byte[1024];
    var checkDataBytesSize = Encoding.UTF8.GetBytes(miniAppCheckDataSpan, checkDataBytes);
    var checkDataBytesActual = checkDataBytes[..checkDataBytesSize];

    Span<byte> tokenSignedBytes = stackalloc byte[32];
    Span<byte> targetHashBytes = stackalloc byte[32];
    Span<byte> tokenBytesContainer = stackalloc byte[128];

    var tokenBytesLength = Encoding.UTF8.GetBytes(token, tokenBytesContainer); // < 128 bytes hypothetically
    var tokenBytesActual = tokenBytesContainer[..tokenBytesLength];

    // Hash of the token with the key "WebAppData"
    HMACSHA256.HashData(WebAppDataBytes, tokenBytesActual, tokenSignedBytes);
    HMACSHA256.HashData(tokenSignedBytes, checkDataBytesActual, targetHashBytes);

    var hash = hashPair.Value;
    Span<byte> hashHexBytes = stackalloc byte[32];
    HexStringToByteSpan(hash, hashHexBytes);

    for (var i = 0; i < hashHexBytes.Length; i++)
    {
      if (hashHexBytes[i] != targetHashBytes[i])
        return false;
    }

    return true;
  }

  #region Hex

  /// <summary>
  /// https://gist.github.com/crozone/06c4aa41e13be89def1352ba0d378b0f
  /// </summary>
  /// <param name="inputChars"></param>
  /// <param name="decodedBytesBuffer"></param>
  /// <returns></returns>
  /// <exception cref="InvalidOperationException"></exception>
  public static Span<byte> HexStringToByteSpan(ReadOnlySpan<char> inputChars, Span<byte> decodedBytesBuffer)
  {
    if (inputChars.Length % 2 != 0)
    {
      throw new InvalidOperationException($"{nameof(inputChars)} length must be even");
    }

    int bufferLength = inputChars.Length / 2;
    if (decodedBytesBuffer.Length < bufferLength)
    {
      throw new InvalidOperationException(
        $"{nameof(decodedBytesBuffer)} must be at least half the length of {nameof(inputChars)}");
    }

    for (int bx = 0, sx = 0; bx < bufferLength; ++bx, ++sx)
    {
      // Convert first half of byte
      char c = inputChars[sx];
      decodedBytesBuffer[bx] = (byte)((c > '9' ? (c > 'Z' ? (c - 'a' + 10) : (c - 'A' + 10)) : (c - '0')) << 4);

      // Convert second half of byte
      c = inputChars[++sx];
      decodedBytesBuffer[bx] |= (byte)(c > '9' ? (c > 'Z' ? (c - 'a' + 10) : (c - 'A' + 10)) : (c - '0'));
    }

    return decodedBytesBuffer.Slice(0, bufferLength);
  }

  #endregion

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