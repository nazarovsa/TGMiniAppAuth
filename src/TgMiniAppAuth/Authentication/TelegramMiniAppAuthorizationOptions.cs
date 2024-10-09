namespace TgMiniAppAuth.Authentication
{
  /// <summary>
  /// Options for Telegram Mini App authentication.
  /// </summary>
  public sealed class TelegramMiniAppAuthorizationOptions
  {
    /// <summary>
    /// Gets or sets the Telegram bot token.
    /// </summary>
    public string Token { get; set; }

    /// <summary>
    /// Gets or sets the validity interval for authentication data. Default value is 2 hours.
    /// </summary>
    public TimeSpan AuthDataValidInterval { get; set; } = TimeSpan.FromHours(2);
  }
}