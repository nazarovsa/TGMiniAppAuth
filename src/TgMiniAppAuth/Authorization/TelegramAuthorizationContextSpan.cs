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
    var items = decodedString.Split('&');
    var pairs = items
      .Select(x => new AuthDataPair(x))
      .OrderBy(x => x.Raw)
      .ToArray();

    var tokenBytes = Encoding.UTF8.GetBytes(token);
    var hashPair = pairs.FirstOrDefault(x => x.Key is "hash");
    if (hashPair == default)
    {
      throw new ArgumentException("Key 'hash' not found");
    }

    var authDatePair = pairs.FirstOrDefault(x => x.Key is "auth_date");
    if (authDatePair == default)
    {
      throw new ArgumentException("Key 'auth_date' not found");
    }

    if (!long.TryParse(authDatePair.Value, out var unixAuthDate))
    {
      throw new InvalidOperationException("Failed to parse 'auth_date'");
    }

    issuedAt = DateTimeOffset.FromUnixTimeSeconds(unixAuthDate);
    
    var hash = hashPair.Value;
    var miniAppCheckDataString = string.Join("\n", pairs.Where(x => x.Key is not "hash").Select(x => x.Raw));
    var miniAppCheckDataBytes = Encoding.UTF8.GetBytes(miniAppCheckDataString);

    // Хэш токена с ключом "WebAppData"
    var tokenSigned = HMACSHA256.HashData(WebAppDataBytes, tokenBytes);
    var targetHashBytes = HMACSHA256.HashData(tokenSigned, miniAppCheckDataBytes);
    var targetHashHex = Convert.ToHexString(targetHashBytes);

    for (var i = 0; i < hash.Length; i++)
    {
      if (Char.ToLower(hash[i]) == Char.ToLower(targetHashHex[i]))
        return false;
    }

    return true;
  }

  /// <summary>
  /// Represents a key-value pair of auth data.
  /// </summary>
  private readonly record struct AuthDataPair
  {
    private readonly int _keyLength;
    
    /// <summary>
    /// Gets the key of the pair.
    /// </summary>
    public ReadOnlySpan<char> Key => Raw.AsSpan(0, _keyLength);

    /// <summary>
    /// Gets the value of the pair.
    /// </summary>
    public ReadOnlySpan<char> Value => Raw.AsSpan(_keyLength + 1);

    /// <summary>
    /// Gets the raw pair string.
    /// </summary>
    public string Raw { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthDataPair"/> struct.
    /// </summary>
    /// <param name="pair">The key-value pair string.</param>
    /// <exception cref="ArgumentException">Thrown when the pair string is not properly formatted.</exception>
    public AuthDataPair(string pair)
    {
      var indexOfEquals = pair.IndexOf('=');
      _keyLength = indexOfEquals;
      Raw = pair;
    }
  }
}