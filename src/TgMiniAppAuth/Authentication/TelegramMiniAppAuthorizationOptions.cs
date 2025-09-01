namespace TgMiniAppAuth.Authentication;

/// <summary>
/// Options for Telegram Mini App authentication.
/// </summary>
public sealed class TelegramMiniAppAuthorizationOptions
{
  /// <summary>
  /// Gets or sets the Telegram bot token.
  /// </summary>
  public required string Token { get; init; }

  /// <summary>
  /// Threshold to allocate on stack when processing auth data validation.
  /// </summary>
  public int StackAllocationThreshold = 1024;

  /// <summary>
  /// Gets or sets the validity interval for authentication data. Default value is 2 hours.
  /// </summary>
  public TimeSpan AuthDataValidInterval { get; init; } = TimeSpan.FromHours(2);
}