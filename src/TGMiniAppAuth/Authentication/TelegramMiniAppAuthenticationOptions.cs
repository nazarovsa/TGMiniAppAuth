namespace TGMiniAppAuth.Authentication;

/// <summary>
/// Options for Telegram Mini App authentication.
/// </summary>
public sealed class TelegramMiniAppAuthenticationOptions
{
    /// <summary>
    /// Gets or sets the Telegram bot token.
    /// </summary>
    public string Token { get; set; }

    /// <summary>
    /// Gets or sets the validity interval for authentication data.
    /// </summary>
    public TimeSpan AuthDataValidInterval { get; set; } = TimeSpan.FromHours(2);
}