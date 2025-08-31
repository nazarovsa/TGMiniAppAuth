using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TgMiniAppAuth.AuthContext;

namespace TgMiniAppAuth.Authentication
{
    /// <summary>
    /// Handles authentication for Telegram Mini App.
    /// </summary>
    public class TelegramMiniAppAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TelegramMiniAppAuthenticationHandler"/> class.
        /// </summary>
        /// <param name="options">The options monitor.</param>
        /// <param name="logger">The logger factory.</param>
        /// <param name="encoder">The URL encoder.</param>
        /// <param name="clock">The system clock.</param>
        public TelegramMiniAppAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {
        }

        /// <summary>
        /// Handles the authentication process.
        /// </summary>
        /// <returns>The authentication result.</returns>
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var headers = Request.Headers;

            if (!headers.TryGetValue("Authorization", out var authorizationHeader) ||
                string.IsNullOrWhiteSpace(authorizationHeader.ToString()))
            {
                return Task.FromResult(AuthenticateResult.Fail("Authorization header does not presented"));
            }

            var authorizationHeaderValue = authorizationHeader.ToString();
            var rawData =
                authorizationHeaderValue.Replace($"{TgMiniAppAuthConstants.AuthenticationScheme} ", string.Empty);
            var telegramUser = TelegramUser.FromUrlEncodedString(rawData);

            var claims = new List<Claim>()
            {
                new(TgMiniAppAuthConstants.Claims.RawAuthData, rawData),
                new(TgMiniAppAuthConstants.Claims.Id, telegramUser.Id.ToString()),
                new(TgMiniAppAuthConstants.Claims.FirstName, telegramUser.FirstName)
            };

            FillNonRequiredClaims(claims, telegramUser);

            var identity = new ClaimsIdentity(claims, TgMiniAppAuthConstants.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return Task.FromResult(AuthenticateResult.Success(ticket));
        }

        private void FillNonRequiredClaims(List<Claim> claims, TelegramUser telegramUser)
        {
            if (!string.IsNullOrEmpty(telegramUser.LastName))
                claims.Add(new Claim(TgMiniAppAuthConstants.Claims.LastName, telegramUser.LastName));

            if (!string.IsNullOrEmpty(telegramUser.Username))
                claims.Add(new Claim(TgMiniAppAuthConstants.Claims.Username, telegramUser.Username));

            if (!string.IsNullOrEmpty(telegramUser.LanguageCode))
                claims.Add(new Claim(TgMiniAppAuthConstants.Claims.LanguageCode, telegramUser.LanguageCode));

            if (telegramUser.IsPremium.HasValue)
                claims.Add(new Claim(TgMiniAppAuthConstants.Claims.IsPremium, telegramUser.IsPremium.Value.ToString()));

            if (telegramUser.IsBot.HasValue)
                claims.Add(new Claim(TgMiniAppAuthConstants.Claims.IsBot, telegramUser.IsBot.Value.ToString()));

            if (telegramUser.AllowWriteToPm.HasValue)
                claims.Add(new Claim(TgMiniAppAuthConstants.Claims.AllowWriteToPm,
                    telegramUser.AllowWriteToPm.Value.ToString()));

            if (!string.IsNullOrEmpty(telegramUser.PhotoUrl))
                claims.Add(new Claim(TgMiniAppAuthConstants.Claims.PhotoUrl, telegramUser.PhotoUrl));
        }
    }
}