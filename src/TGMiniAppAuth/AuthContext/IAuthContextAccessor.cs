namespace TGMiniAppAuth.AuthContext;

/// <summary>
/// Telegram mini app auth context accessor
/// </summary>
public interface IAuthContextAccessor
{
    /// <summary>
    /// Returns TelegramAuthContext from http-context
    /// </summary>
    /// <returns><see cref="TelegramAuthContext"/></returns>
    public TelegramAuthContext Context { get; }
}