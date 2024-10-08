using Microsoft.AspNetCore.Http;

namespace TGMiniAppAuth.AuthContext;

internal sealed class AuthContextAccessor : IAuthContextAccessor
{
  private readonly IHttpContextAccessor _httpContextAccessor;

  private TelegramAuthContext? _context;

  public AuthContextAccessor(IHttpContextAccessor httpContextAccessor)
  {
    _httpContextAccessor = httpContextAccessor;
  }

  public TelegramAuthContext Context => _context ??= Get();

  private TelegramAuthContext Get()
  {
    var rawAuthContextClaim = _httpContextAccessor.HttpContext?.User.Claims.FirstOrDefault(x =>
      string.Equals(x.Type, TMiniApp.TelegramMiniAppAuthDataClaimName, StringComparison.Ordinal));
    if (rawAuthContextClaim == null)
      throw new InvalidOperationException("Failed to extract auth context from http-context");

    return TelegramAuthContext.FromHtmlEncodedString(rawAuthContextClaim.Value);
  }
}