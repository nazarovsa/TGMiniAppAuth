using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using TgMiniAppAuth.Authentication;

namespace TgMiniAppAuth.Authorization
{
  /// <summary>
  /// Handles authorization for Telegram Mini App.
  /// </summary>
  internal class TelegramMiniAppAuthorizationHandler : AuthorizationHandler<TelegramMiniAppAuthorizationRequirement>
  {
    /// <summary>
    /// The system clock.
    /// </summary>
    private readonly ISystemClock _systemClock;

    /// <summary>
    /// The Telegram Mini App authentication options.
    /// </summary>
    private readonly TelegramMiniAppAuthorizationOptions _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="TelegramMiniAppAuthorizationHandler"/> class.
    /// </summary>
    /// <param name="options">The options for Telegram Mini App authentication.</param>
    /// <param name="systemClock">The system clock.</param>
    /// <exception cref="ArgumentNullException">Thrown when options are null.</exception>
    public TelegramMiniAppAuthorizationHandler(IOptions<TelegramMiniAppAuthorizationOptions> options,
      ISystemClock systemClock)
    {
      _systemClock = systemClock;
      _options = options.Value ?? throw new ArgumentNullException(nameof(options));
    }
    
    /// <summary>
    /// Handles the authorization requirement.
    /// </summary>
    /// <param name="context">The authorization handler context.</param>
    /// <param name="requirement">The authorization requirement.</param>
    /// <returns>A task that represents the asynchronous operation.</returns>
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
      TelegramMiniAppAuthorizationRequirement requirement)
    {
      var dataClaim = context.User.Claims
        .FirstOrDefault(x => string.Equals(x.Type, TgMiniAppAuthConstants.Claims.RawAuthData));
      if (dataClaim == null)
      {
        context.Fail(new AuthorizationFailureReason(this,
          $"Claim '{TgMiniAppAuthConstants.Claims.RawAuthData} not found'"));
        return Task.CompletedTask;
      }

      if (TelegramAuthorizationContext.IsValidTelegramMiniAppContext(dataClaim.Value, _options.Token, out var issuedAt))
      {
        var utcNow = _systemClock.UtcNow;
        if (utcNow - issuedAt < _options.AuthDataValidInterval)
        {
          context.Succeed(requirement);
        }
        else
        {
          context.Fail(new AuthorizationFailureReason(this, "Auth data expired"));
        }
      }
      else
      {
        context.Fail(new AuthorizationFailureReason(this, "Auth data hash invalid"));
      }

      return Task.CompletedTask;
    }
  }
}