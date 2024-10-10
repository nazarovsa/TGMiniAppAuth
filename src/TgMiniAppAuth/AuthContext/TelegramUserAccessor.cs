using Microsoft.AspNetCore.Http;

namespace TgMiniAppAuth.AuthContext
{
  /// <summary>
  /// Provides access to the Telegram authentication context from the HTTP context.
  /// </summary>
  internal sealed class TelegramUserAccessor : ITelegramUserAccessor
  {
    /// <summary>
    /// The HTTP context accessor.
    /// </summary>
    private readonly IHttpContextAccessor _httpContextAccessor;

    /// <summary>
    /// The cached Telegram authentication context.
    /// </summary>
    private TelegramUser? _telegramUser;

    /// <summary>
    /// Initializes a new instance of the <see cref="TelegramUserAccessor"/> class.
    /// </summary>
    /// <param name="httpContextAccessor">The HTTP context accessor.</param>
    public TelegramUserAccessor(IHttpContextAccessor httpContextAccessor)
    {
      _httpContextAccessor = httpContextAccessor;
    }

    /// <summary>
    /// Gets the Telegram authentication context.
    /// </summary>
    public TelegramUser User => _telegramUser ??= Get();

    /// <summary>
    /// Extracts the Telegram authentication context from the HTTP context.
    /// </summary>
    /// <returns>The Telegram authentication context.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the authentication context cannot be extracted from the HTTP context.</exception>
    private TelegramUser Get()
    {
      var rawAuthDataClaim = _httpContextAccessor.HttpContext?.User.Claims.FirstOrDefault(x =>
        string.Equals(x.Type, TgMiniAppAuthConstants.Claims.RawAuthData, StringComparison.Ordinal));
      if (rawAuthDataClaim == null)
        throw new InvalidOperationException("Failed to extract auth context from HTTP context");

      return TelegramUser.FromUrlEncodedString(rawAuthDataClaim.Value);
    }
  }
}