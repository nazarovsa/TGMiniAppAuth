using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace TgMiniAppAuth.Authorization;

/// <summary>
/// Telgram mini app auth context
/// </summary>
internal sealed class TelegramAuthorizationContext
{
  /// <summary>
  /// Id of a query
  /// </summary>
  public string QueryId { get; }

  /// <summary>
  /// Hash of data signed with telegram bot token
  /// </summary>
  public string Hash { get; }

  /// <summary>
  /// Date of auth
  /// </summary>
  public DateTimeOffset AuthDate { get; }

  /// <summary>
  /// Check data's string
  /// </summary>
  private string CheckDataString { get; }

  /// <summary>
  /// Check data's bytes
  /// </summary>
  private byte[] CheckDataBytes { get; }

  /// <summary>
  /// Static value used as a key for bot token sign
  /// </summary>
  private static readonly byte[] WebAppDataBytes = "WebAppData"u8.ToArray();

  /// <summary>
  /// Initializes a new instance of the <see cref="TelegramAuthorizationContext"/> class.
  /// </summary>
  /// <param name="userRaw">Raw user data.</param>
  /// <param name="queryId">Query ID data.</param>
  /// <param name="authDate">Auth date data.</param>
  /// <param name="hash">Hash data.</param>
  private TelegramAuthorizationContext(AuthDataPair userRaw, AuthDataPair queryId, AuthDataPair authDate, AuthDataPair hash)
  {
    QueryId = queryId.Value;
    Hash = hash.Value;

    CheckDataString = authDate.Raw + "\n" + queryId.Raw + "\n" + userRaw.Raw;
    CheckDataBytes = Encoding.UTF8.GetBytes(CheckDataString);
    AuthDate = DateTimeOffset.FromUnixTimeSeconds(long.Parse(authDate.Value));
  }

  /// <summary>
  /// Validates the auth context using the provided token.
  /// </summary>
  /// <param name="token">The token to validate against.</param>
  /// <returns>True if valid, otherwise false.</returns>
  public bool IsValid(string token)
  {
    var tokenBytes = Encoding.UTF8.GetBytes(token);

    // Хэш токена с ключом "WebAppData"
    var tokenSigned = HMACSHA256.HashData(WebAppDataBytes, tokenBytes);
    var targetHashBytes = HMACSHA256.HashData(tokenSigned, CheckDataBytes);
    var targetHashHex = Convert.ToHexString(targetHashBytes);

    return string.Equals(targetHashHex, Hash, StringComparison.OrdinalIgnoreCase);
  }

  /// <summary>
  /// Creates an instance of <see cref="TelegramAuthorizationContext"/> from an HTML-encoded auth data string.
  /// </summary>
  /// <param name="urlEncodedString">HTML-encoded auth data string.</param>
  /// <returns>New instance of a <see cref="TelegramAuthorizationContext"/>.</returns>
  /// <exception cref="ArgumentException">Thrown when required keys are not found in the data string.</exception>
  public static TelegramAuthorizationContext FromUrlEncodedString(string urlEncodedString)
  {
    var decodedString = HttpUtility.UrlDecode(urlEncodedString);
    var items = decodedString.Split('&');
    var pairs = items
      .Select(x => new AuthDataPair(x))
      .ToArray();

    var queryIdPair = pairs.FirstOrDefault(x => string.Equals(x.Key, "query_id", StringComparison.Ordinal));
    if (queryIdPair == default)
    {
      throw new ArgumentException("Key query_id not found");
    }

    var userPair = pairs.FirstOrDefault(x => string.Equals(x.Key, "user", StringComparison.Ordinal));
    if (userPair == default)
    {
      throw new ArgumentException("Key user not found");
    }

    var authDate = pairs.FirstOrDefault(x => string.Equals(x.Key, "auth_date", StringComparison.Ordinal));
    if (authDate == default)
    {
      throw new ArgumentException("Key auth_date not found");
    }

    var hash = pairs.FirstOrDefault(x => string.Equals(x.Key, "hash", StringComparison.Ordinal));
    if (hash == default)
    {
      throw new ArgumentException("Key hash not found");
    }

    return new TelegramAuthorizationContext(userPair, queryIdPair, authDate, hash);
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