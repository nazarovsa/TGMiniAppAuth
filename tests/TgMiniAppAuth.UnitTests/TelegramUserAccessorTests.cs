using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using NSubstitute;
using TgMiniAppAuth;
using TgMiniAppAuth.AuthContext;
using TgMiniAppAuth.AuthContext.User;

namespace TgMIniAppAuth.UnitTests;

public class TelegramUserAccessorTests
{
    [Fact]
    public void Get_RawAuthDataClaimIsPresent_ReturnsTelegramUser()
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
    public void Get_RawAuthDataClaimIsMissing_ThrowsInvalidOperationException()
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