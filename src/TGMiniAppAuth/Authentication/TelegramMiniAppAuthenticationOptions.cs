namespace TGMiniAppAuth.Authentication;

public sealed class TelegramMiniAppAuthenticationOptions
{
    /// <summary>
    /// Telegram bot token
    /// </summary>
    public string Token { get; set; }

    /// <summary>
    /// How much auth data valid
    /// </summary>
    public TimeSpan AuthDataValidInterval { get; set; } = TimeSpan.FromHours(2);
}