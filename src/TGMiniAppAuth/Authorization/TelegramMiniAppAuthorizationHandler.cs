using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using TGMiniAppAuth.AuthContext;
using TGMiniAppAuth.Authentication;

namespace TGMiniAppAuth.Authorization;

public class TelegramMiniAppAuthorizationHandler : AuthorizationHandler<TelegramMiniAppAuthorizationRequirement>
{
    private readonly ISystemClock _systemClock;
    private readonly TelegramMiniAppAuthenticationOptions _options;

    public TelegramMiniAppAuthorizationHandler(IOptions<TelegramMiniAppAuthenticationOptions> options,
        ISystemClock systemClock)
    {
        _systemClock = systemClock;
        _options = options.Value ?? throw new ArgumentNullException(nameof(options));
    }

    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
        TelegramMiniAppAuthorizationRequirement requirement)
    {
        var dataClaim = context.User.Claims.FirstOrDefault(x => string.Equals(x.Type, TMiniApp.TelegramMiniAppAuthDataClaimName));
        if (dataClaim == null)
        {
            context.Fail(new AuthorizationFailureReason(this,
                $"Claim '{TMiniApp.TelegramMiniAppAuthDataClaimName} not found'"));
            return Task.CompletedTask;
        }

        var data = TelegramAuthContext.FromHtmlEncodedString(dataClaim.Value);
        if (data.IsValid(_options.Token))
        {
            var utcNow = _systemClock.UtcNow;
            if (utcNow - data.AuthDate < _options.AuthDataValidInterval)
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