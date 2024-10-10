using System.Security.Claims;
using TgMiniAppAuth;
using TgMiniAppAuth.AuthContext;

namespace TgMIniAppAuth.UnitTests
{
    public class TelegramUserTests
    {
        [Fact]
        public void FromClaimsPrincipal_ShouldReturnTelegramUser_WhenAllClaimsArePresent()
        {
            // Arrange
            var claims = new[]
            {
                new Claim(TgMiniAppAuthConstants.Claims.Id, "123456"),
                new Claim(TgMiniAppAuthConstants.Claims.FirstName, "John"),
                new Claim(TgMiniAppAuthConstants.Claims.LastName, "Doe"),
                new Claim(TgMiniAppAuthConstants.Claims.Username, "johndoe"),
                new Claim(TgMiniAppAuthConstants.Claims.LanguageCode, "en"),
                new Claim(TgMiniAppAuthConstants.Claims.IsPremium, "true"),
                new Claim(TgMiniAppAuthConstants.Claims.AllowWriteToPm, "true")
            };
            var principal = new ClaimsPrincipal(new ClaimsIdentity(claims));

            // Act
            var user = TelegramUser.FromClaimsPrincipal(principal);

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
        public void FromClaimsPrincipal_ShouldThrowInvalidOperationException_WhenIdClaimIsMissing()
        {
            // Arrange
            var claims = new[]
            {
                new Claim(TgMiniAppAuthConstants.Claims.FirstName, "John"),
                new Claim(TgMiniAppAuthConstants.Claims.LastName, "Doe"),
                new Claim(TgMiniAppAuthConstants.Claims.Username, "johndoe"),
                new Claim(TgMiniAppAuthConstants.Claims.LanguageCode, "en"),
                new Claim(TgMiniAppAuthConstants.Claims.IsPremium, "true"),
                new Claim(TgMiniAppAuthConstants.Claims.AllowWriteToPm, "true")
            };
            var principal = new ClaimsPrincipal(new ClaimsIdentity(claims));

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => TelegramUser.FromClaimsPrincipal(principal));
        }

        [Fact]
        public void FromClaimsPrincipal_ShouldHandleMissingOptionalClaims()
        {
            // Arrange
            var claims = new[]
            {
                new Claim(TgMiniAppAuthConstants.Claims.Id, "123456")
            };
            var principal = new ClaimsPrincipal(new ClaimsIdentity(claims));

            // Act
            var user = TelegramUser.FromClaimsPrincipal(principal);

            // Assert
            Assert.Equal(123456, user.Id);
            Assert.Null(user.FirstName);
            Assert.Null(user.LastName);
            Assert.Null(user.Username);
            Assert.Null(user.LanguageCode);
            Assert.False(user.IsPremium);
            Assert.False(user.AllowWriteToPm);
        }
    }
}