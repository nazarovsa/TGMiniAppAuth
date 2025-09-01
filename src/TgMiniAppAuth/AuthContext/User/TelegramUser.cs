using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Web;

namespace TgMiniAppAuth.AuthContext.User;

/// <summary>
/// Represents a Telegram user.
/// </summary>
public sealed class TelegramUser
{
    /// <summary>
    /// Gets the user's ID.
    /// </summary>
    [JsonPropertyName("id")]
    public long Id { get; init; }

    /// <summary>
    /// Gets the user's first name.
    /// </summary>
    [JsonPropertyName("first_name")]
    public required string FirstName { get; init; }

    /// <summary>
    /// Gets the user's last name.
    /// </summary>
    [JsonPropertyName("last_name")]
    public string? LastName { get; init; }

    /// <summary>
    /// Gets the user's username.
    /// </summary>
    [JsonPropertyName("username")]
    public string? Username { get; init; }

    /// <summary>
    /// Gets the user's language code.
    /// </summary>
    [JsonPropertyName("language_code")]
    public string? LanguageCode { get; init; }

    /// <summary>
    /// Gets a value indicating whether the user is a premium user.
    /// </summary>
    [JsonPropertyName("is_premium")]
    public bool? IsPremium { get; init; }

    /// <summary>
    /// Gets a value indicating whether the user is a bot.
    /// </summary>
    [JsonPropertyName("is_bot")]
    public bool? IsBot { get; init; }

    /// <summary>
    /// Gets a value indicating whether the user allows writing to private messages.
    /// </summary>
    [JsonPropertyName("allows_write_to_pm")]
    public bool? AllowWriteToPm { get; init; }

    /// <summary>
    /// Gets a value with user photo url.
    /// </summary>
    [JsonPropertyName("photo_url")]
    public string? PhotoUrl { get; init; }

    /// <summary>
    /// Creates a <see cref="TelegramUser"/> instance from a <see cref="ClaimsPrincipal"/>.
    /// </summary>
    /// <param name="principal">The claims principal containing the user claims.</param>
    /// <returns>A <see cref="TelegramUser"/> instance.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the required ID claim is missing.</exception>
    internal static TelegramUser FromClaimsPrincipal(ClaimsPrincipal principal)
    {
        var idClaim = principal.FindFirst(TgMiniAppAuthConstants.Claims.Id);
        var firstNameClaim = principal.FindFirst(TgMiniAppAuthConstants.Claims.FirstName);
        var lastNameClaim = principal.FindFirst(TgMiniAppAuthConstants.Claims.LastName);
        var usernameClaim = principal.FindFirst(TgMiniAppAuthConstants.Claims.Username);
        var languageCodeClaim = principal.FindFirst(TgMiniAppAuthConstants.Claims.LanguageCode);
        var isPremiumClaim = principal.FindFirst(TgMiniAppAuthConstants.Claims.IsPremium);
        var isBotClaim = principal.FindFirst(TgMiniAppAuthConstants.Claims.IsBot);
        var allowWriteToPmClaim = principal.FindFirst(TgMiniAppAuthConstants.Claims.AllowWriteToPm);
        var photoUrlClaim = principal.FindFirst(TgMiniAppAuthConstants.Claims.PhotoUrl);

        if (idClaim == null)
        {
            throw new InvalidOperationException($"Required claim `{TgMiniAppAuthConstants.Claims.Id}` is missing");
        }

        if (firstNameClaim == null)
        {
            throw new InvalidOperationException(
                $"Required claim `{TgMiniAppAuthConstants.Claims.FirstName}` is missing");
        }

        return new TelegramUser
        {
            Id = long.Parse(idClaim.Value),
            FirstName = firstNameClaim.Value,
            LastName = lastNameClaim?.Value,
            Username = usernameClaim?.Value,
            LanguageCode = languageCodeClaim?.Value,
            IsBot = isBotClaim != null && bool.Parse(isBotClaim.Value),
            IsPremium = isPremiumClaim != null && bool.Parse(isPremiumClaim.Value),
            AllowWriteToPm = allowWriteToPmClaim != null && bool.Parse(allowWriteToPmClaim.Value),
            PhotoUrl = photoUrlClaim?.Value
        };
    }

    /// <summary>
    /// Creates a <see cref="TelegramUser"/> instance from a URL-encoded string.
    /// </summary>
    /// <param name="urlEncodedString">The URL-encoded string containing the user data.</param>
    /// <returns>A <see cref="TelegramUser"/> instance.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the user data cannot be extracted from the URL-encoded string.</exception>
    internal static TelegramUser FromUrlEncodedString(string urlEncodedString)
    {
        var serializedUser = HttpUtility
            .UrlDecode(urlEncodedString)
            .Split('&')
            .FirstOrDefault(x => x.StartsWith("user=", StringComparison.OrdinalIgnoreCase))?
            .Replace("user=", string.Empty);

        if (string.IsNullOrWhiteSpace(serializedUser))
            throw new InvalidOperationException("Failed to extract user data from url encoded string");

        return JsonSerializer.Deserialize<TelegramUser>(serializedUser) ??
               throw new ArgumentException($"Failed to extract {nameof(TelegramUser)} from serialized user data");
    }
}