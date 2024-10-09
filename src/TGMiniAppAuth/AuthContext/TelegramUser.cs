using System.Text.Json.Serialization;

namespace TGMiniAppAuth.AuthContext;

/// <summary>
/// Represents a Telegram user.
/// </summary>
public class TelegramUser
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
  public required string LastName { get; init; }

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
  public bool IsPremium { get; init; }

  /// <summary>
  /// Gets a value indicating whether the user allows writing to private messages.
  /// </summary>
  [JsonPropertyName("allows_write_to_pm")]
  public bool AllowWriteToPm { get; init; }
}