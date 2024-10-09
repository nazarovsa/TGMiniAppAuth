using Microsoft.AspNetCore.Http;

namespace TGMiniAppAuth.AuthContext;

/// <summary>
/// Provides access to the Telegram authentication context from the HTTP context.
/// </summary>
internal sealed class AuthContextAccessor : IAuthContextAccessor
{
  /// <summary>
  /// The HTTP context accessor.
  /// </summary>
  private readonly IHttpContextAccessor _httpContextAccessor;

  /// <summary>
  /// The cached Telegram authentication context.
  /// </summary>
  private TelegramAuthContext? _context;

  /// <summary>
  /// Initializes a new instance of the <see cref="AuthContextAccessor"/> class.
  /// </summary>
  /// <param name="httpContextAccessor">The HTTP context accessor.</param>
  public AuthContextAccessor(IHttpContextAccessor httpContextAccessor)
  {
    _httpContextAccessor = httpContextAccessor;
  }

  /// <summary>
  /// Gets the Telegram authentication context.
  /// </summary>
  public TelegramAuthContext Context => _context ??= Get();

  /// <summary>
  /// Extracts the Telegram authentication context from the HTTP context.
  /// </summary>
  /// <returns>The Telegram authentication context.</returns>
  /// <exception cref="InvalidOperationException">Thrown when the authentication context cannot be extracted from the HTTP context.</exception>
  private TelegramAuthContext Get()
  {
    var rawAuthContextClaim = _httpContextAccessor.HttpContext?.User.Claims.FirstOrDefault(x =>
      string.Equals(x.Type, TMiniApp.TelegramMiniAppAuthDataClaimName, StringComparison.Ordinal));
    if (rawAuthContextClaim == null)
      throw new InvalidOperationException("Failed to extract auth context from HTTP context");

    return TelegramAuthContext.FromUrlEncodedString(rawAuthContextClaim.Value);
  }
}