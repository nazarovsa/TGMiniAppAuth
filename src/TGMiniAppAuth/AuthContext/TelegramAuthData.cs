using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Web;
using TGMiniAppAuth.Contracts;

namespace TGMiniAppAuth.AuthContext;

/// <summary>
/// Telgram mini app auth context
/// </summary>
public sealed class TelegramAuthContext
{
    /// <summary>
    /// User's data
    /// </summary>
    public ITelegramUser User { get;  }

    /// <summary>
    /// Id of an query
    /// </summary>
    public string QueryId { get;  }

    /// <summary>
    /// Hash of data signed with telegram bot token
    /// </summary>
    public string Hash { get;  }

    /// <summary>
    /// Date of auth
    /// </summary>
    public DateTimeOffset AuthDate { get; }

    /// <summary>
    /// Check data's string
    /// </summary>
    private string CheckDataString { get; }

    /// <summary>
    /// Check data's butes
    /// </summary>
    private byte[] CheckDataBytes { get; }

    /// <summary>
    /// Static value used as a key for bot token sign
    /// </summary>
    private static readonly byte[] WebAppDataBytes = "WebAppData"u8.ToArray();

    private TelegramAuthContext(AuthDataPair userRaw, AuthDataPair queryId, AuthDataPair authDate, AuthDataPair hash)
    {
        QueryId = queryId.Value;
        Hash = hash.Value;

        CheckDataString = authDate.Raw + "\n" + queryId.Raw + "\n" + userRaw.Raw;
        CheckDataBytes = Encoding.UTF8.GetBytes(CheckDataString);
        AuthDate = DateTimeOffset.FromUnixTimeSeconds(long.Parse(authDate.Value));
        User = JsonSerializer.Deserialize<TelegramUser>(userRaw.Value);
    }

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
    /// Creates instance of <see cref="TelegramAuthContext"/> from html-encoded auth data string
    /// </summary>
    /// <param name="htmlEncodedString">Html-encoded auth data string</param>
    /// <returns>New instance of a <see cref="TelegramAuthContext"/></returns>
    /// <exception cref="ArgumentException"></exception>
    public static TelegramAuthContext FromHtmlEncodedString(string htmlEncodedString)
    {
        var decodedString = HttpUtility.UrlDecode(htmlEncodedString);
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

        return new TelegramAuthContext(userPair, queryIdPair, authDate, hash);
    }

    private readonly record struct AuthDataPair
    {
        public string Key { get; }

        public string Value { get; }

        public string Raw { get; }

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

    private readonly record struct TelegramUser : ITelegramUser
    {
        [JsonPropertyName("id")]
        public long Id { get; init; }

        [JsonPropertyName("first_name")] 
        public string FirstName { get; init; }

        [JsonPropertyName("last_name")] 
        public string LastName { get; init; }

        [JsonPropertyName("username")] 
        public string? Username { get; init; }

        [JsonPropertyName("language_code")]
        public string? LanguageCode { get; init; }

        [JsonPropertyName("is_premium")] 
        public bool IsPremium { get; init; }

        [JsonPropertyName("allows_write_to_pm")]
        public bool AllowWriteToPm { get; init; }
    }
}