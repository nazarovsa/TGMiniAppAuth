using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace TGMiniAppAuth.Authentication;

public class TelegramMiniAppAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public TelegramMiniAppAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var headers = Request.Headers;

        if (!headers.TryGetValue("Authorization", out var authorizationHeader) ||
            string.IsNullOrWhiteSpace(authorizationHeader.ToString()))
        {
            return Task.FromResult(AuthenticateResult.Fail("Authorization header does not presented"));
        }

        var authorizationHeaderValue = authorizationHeader.ToString();
        var rawData = authorizationHeaderValue.Replace($"{TMiniApp.AuthenticationScheme} ", string.Empty);
        var claims = new[]
        {
            new Claim(TMiniApp.TelegramMiniAppAuthDataClaimName, rawData)
        };

        var identity = new ClaimsIdentity(claims);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}