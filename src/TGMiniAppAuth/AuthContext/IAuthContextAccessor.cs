namespace TGMiniAppAuth.AuthContext;

/// <summary>
/// Provides access to the Telegram authentication context from the HTTP context.
/// </summary>
public interface IAuthContextAccessor
{
    /// <summary>
    /// Gets the Telegram authentication context.
    /// </summary>
    /// <returns>The <see cref="TelegramAuthContext"/>.</returns>
    TelegramAuthContext Context { get; }
}