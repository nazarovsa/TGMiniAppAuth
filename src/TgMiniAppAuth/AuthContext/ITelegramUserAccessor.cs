namespace TgMiniAppAuth.AuthContext;

/// <summary>
/// Provides access to the Telegram user.
/// </summary>
public interface ITelegramUserAccessor
{
    /// <summary>
    /// Gets the Telegram user.
    /// </summary>
    TelegramUser User { get; }
}