using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using NSubstitute;
using TgMiniAppAuth;
using TgMiniAppAuth.AuthContext;
using TgMiniAppAuth.Authorization;

namespace TgMIniAppAuth.UnitTests
{
    public class TelegramUserAccessorTests
    {
        [Fact]
        public void V()
        {
            var token =
                "query_id=AAHF0D0OAAAAAMXQPQ4dKBBT&user=%7B%22id%22%3A238932165%2C%22first_name%22%3A%22Sergey%22%2C%22last_name%22%3A%22Nazarov%22%2C%22username%22%3A%22sanazarov%22%2C%22language_code%22%3A%22en%22%2C%22is_premium%22%3Atrue%2C%22allows_write_to_pm%22%3Atrue%2C%22photo_url%22%3A%22https%3A%5C%2F%5C%2Ft.me%5C%2Fi%5C%2Fuserpic%5C%2F320%5C%2FGPG1DYLiVdlIoxJ_2WIfwBTsJRJ81gsmcLCz3PABLBQ.svg%22%7D&auth_date=1731861317&signature=91Z5ikpqRSgvbVgMiYoN-7TDz8JjsM-V-AuyXqQSN7ScHjmrR1YHtVUzerlqITrNgwtAON_r9miNAGuozNdzCg&hash=5a87fc9e604f54f428cea3a40b058fd5b9ac041803175c1404cf6788cf28ccc1";

            Assert.True(TelegramAuthorizationContextValidator.IsValidTelegramMiniAppContext(token, "7888212791:AAHOf0quo22Rqfj_TYuHcYnKO051WMOKYB0", out _));
        }
        
        [Fact]
        public void Get_ShouldReturnTelegramUser_WhenRawAuthDataClaimIsPresent()
        {
            // Arrange
            var claims = new[]
            {
                new Claim(TgMiniAppAuthConstants.Claims.RawAuthData, "user=%7B%22id%22%3A123456%2C%22first_name%22%3A%22John%22%2C%22last_name%22%3A%22Doe%22%2C%22username%22%3A%22johndoe%22%2C%22language_code%22%3A%22en%22%2C%22is_premium%22%3Atrue%2C%22allows_write_to_pm%22%3Atrue%7D")
            };
            var identity = new ClaimsIdentity(claims);
            var principal = new ClaimsPrincipal(identity);
            var httpContext = new DefaultHttpContext { User = principal };
            var httpContextAccessor = Substitute.For<IHttpContextAccessor>();
            httpContextAccessor.HttpContext.Returns(httpContext);

            var accessor = new TelegramUserAccessor(httpContextAccessor);

            // Act
            var user = accessor.User;

            // Assert
            Assert.Equal(123456, user.Id);
            Assert.Equal("John", user.FirstName);
            Assert.Equal("Doe", user.LastName);
            Assert.Equal("johndoe", user.Username);
            Assert.Equal("en", user.LanguageCode);
            Assert.True(user.IsPremium);
            Assert.True(user.AllowWriteToPm);
        }

        [Fact]
        public void Get_ShouldThrowInvalidOperationException_WhenRawAuthDataClaimIsMissing()
        {
            // Arrange
            var httpContext = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity()) };
            var httpContextAccessor = Substitute.For<IHttpContextAccessor>();
            httpContextAccessor.HttpContext.Returns(httpContext);

            var accessor = new TelegramUserAccessor(httpContextAccessor);

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => accessor.User);
        }
    }
}