using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace TgMiniAppAuth.Authorization;

/// <summary>
/// Telgram mini app auth context
/// </summary>
internal static class TelegramAuthorizationContext
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
    var hash = pairs.FirstOrDefault(x => x.Key.Equals("hash")).Value ??
               throw new ArgumentException("Auth pair 'hash' not found");

    issuedAt = DateTimeOffset.FromUnixTimeSeconds(
      long.Parse(pairs.FirstOrDefault(x => x.Key.Equals("auth_date", StringComparison.Ordinal)).Value ??
                 throw new ArgumentException("Auth pair 'auth_date' not found")));

    var miniAppCheckDataString = string.Join("\n", pairs.Where(x => !x.Key.Equals("hash")).Select(x => x.Raw));
    var miniAppCheckDataBytes = Encoding.UTF8.GetBytes(miniAppCheckDataString);

    // Хэш токена с ключом "WebAppData"
    var tokenSigned = HMACSHA256.HashData(WebAppDataBytes, tokenBytes);
    var targetHashBytes = HMACSHA256.HashData(tokenSigned, miniAppCheckDataBytes);
    var targetHashHex = Convert.ToHexString(targetHashBytes);

    return string.Equals(targetHashHex, hash, StringComparison.OrdinalIgnoreCase);
  }

  /// <summary>
  /// Represents a key-value pair of auth data.
  /// </summary>
  private readonly record struct AuthDataPair
  {
    /// <summary>
    /// Gets the key of the pair.
    /// </summary>
    public string Key { get; }

    /// <summary>
    /// Gets the value of the pair.
    /// </summary>
    public string Value { get; }

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
      var items = pair.Split('=');
      if (items.Length != 2)
      {
        throw new ArgumentException($"{nameof(pair)} should be '=' separated string with two operands");
      }

      Key = items[0];
      Value = items[1];
      Raw = pair;
    }
  }
}