
using System.Text.Json.Serialization;

namespace TGMiniAppAuth.AuthContext;

public class TelegramUser
{
  [JsonPropertyName("id")]
  public long Id { get; init; }

  [JsonPropertyName("first_name")]
  public required string FirstName { get; init; }

  [JsonPropertyName("last_name")] 
  public required string LastName { get; init; }

  [JsonPropertyName("username")]
  public string? Username { get; init; }

  [JsonPropertyName("language_code")] 
  public string? LanguageCode { get; init; }

  [JsonPropertyName("is_premium")] 
  public bool IsPremium { get; init; }

  [JsonPropertyName("allows_write_to_pm")]
  public bool AllowWriteToPm { get; init; }
}