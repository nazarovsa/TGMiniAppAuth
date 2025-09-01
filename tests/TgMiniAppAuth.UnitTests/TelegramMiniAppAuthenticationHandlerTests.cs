using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using TgMiniAppAuth;
using TgMiniAppAuth.Authentication;

namespace TgMIniAppAuth.UnitTests
{
    /// <summary>
    /// A testable version of TelegramMiniAppAuthenticationHandler that exposes the protected HandleAuthenticateAsync method
    /// </summary>
    public class TestableAuthenticationHandler : TelegramMiniAppAuthenticationHandler
    {
        public TestableAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder) : base(options, logger, encoder)
        {
        }

        public new Task<AuthenticateResult> HandleAuthenticateAsync() => base.HandleAuthenticateAsync();
    }

    public class TelegramMiniAppAuthenticationHandlerTests
    {
        private const string ValidFullDataAuth = "user=%7B%22id%22%3A238932165%2C%22first_name%22%3A%22John%22%2C%22last_name%22%3A%22Doe%22%2C%22username%22%3A%22johndoe%22%2C%22language_code%22%3A%22en%22%2C%22is_premium%22%3Atrue%7D&auth_date=1731861317&hash=5a87fc9e604f54f428cea3a40b058fd5b9ac041803175c1404cf6788cf28ccc1";
        private const string ValidMinimalDataAuth = "user=%7B%22id%22%3A238932165%2C%22first_name%22%3A%22John%22%7D&auth_date=1731861317&hash=5a87fc9e604f54f428cea3a40b058fd5b9ac041803175c1404cf6788cf28ccc1";
        
        private readonly IOptionsMonitor<AuthenticationSchemeOptions> _options;
        private readonly ILoggerFactory _loggerFactory;
        private readonly UrlEncoder _encoder;
        private readonly AuthenticationScheme _scheme;
        
        public TelegramMiniAppAuthenticationHandlerTests()
        {
            _options = Substitute.For<IOptionsMonitor<AuthenticationSchemeOptions>>();
            _options.Get(Arg.Any<string>()).Returns(new AuthenticationSchemeOptions());
            
            _loggerFactory = Substitute.For<ILoggerFactory>();
            _encoder = UrlEncoder.Default;
            
            _scheme = new AuthenticationScheme(
                TgMiniAppAuthConstants.AuthenticationScheme,
                TgMiniAppAuthConstants.AuthenticationScheme,
                typeof(TestableAuthenticationHandler));
        }
        
        private TestableAuthenticationHandler CreateHandler(HttpContext? context = null)
        {
            context ??= new DefaultHttpContext();
            
            var handler = new TestableAuthenticationHandler(
                _options,
                _loggerFactory, 
                _encoder);
            
            handler.InitializeAsync(_scheme, context).Wait();
            
            return handler;
        }
        
        [Fact]
        public async Task HandleAuthenticateAsync_ValidAuthorizationHeader_AllFields_ReturnsSuccess()
        {
            // Arrange
            var context = new DefaultHttpContext();
            context.Request.Headers["Authorization"] = $"{TgMiniAppAuthConstants.AuthenticationScheme} {ValidFullDataAuth}";
            
            var handler = CreateHandler(context);
            
            // Act
            var result = await handler.HandleAuthenticateAsync();
            
            // Assert
            Assert.True(result.Succeeded);
            Assert.NotNull(result.Principal);
            Assert.Equal(TgMiniAppAuthConstants.AuthenticationScheme, result.Ticket.AuthenticationScheme);
        }
        
        [Fact]
        public async Task HandleAuthenticateAsync_ValidAuthorizationHeader_RequiredFieldsOnly_ReturnsSuccess()
        {
            // Arrange
            var context = new DefaultHttpContext();
            context.Request.Headers["Authorization"] = $"{TgMiniAppAuthConstants.AuthenticationScheme} {ValidMinimalDataAuth}";
            
            var handler = CreateHandler(context);
            
            // Act
            var result = await handler.HandleAuthenticateAsync();
            
            // Assert
            Assert.True(result.Succeeded);
            Assert.NotNull(result.Principal);
            Assert.Equal(TgMiniAppAuthConstants.AuthenticationScheme, result.Ticket.AuthenticationScheme);
        }
        
        [Fact]
        public async Task HandleAuthenticateAsync_MissingAuthorizationHeader_ReturnsFail()
        {
            // Arrange
            var context = new DefaultHttpContext();
            var handler = CreateHandler(context);
            
            // Act
            var result = await handler.HandleAuthenticateAsync();
            
            // Assert
            Assert.False(result.Succeeded);
            Assert.Equal("Authorization header does not presented", result.Failure?.Message);
        }
        
        [Theory]
        [InlineData("")]
        [InlineData("    ")]
        public async Task HandleAuthenticateAsync_EmptyAuthorizationHeader_ReturnsFail(string headerValue)
        {
            // Arrange
            var context = new DefaultHttpContext();
            context.Request.Headers["Authorization"] = headerValue;
            
            var handler = CreateHandler(context);
            
            // Act
            var result = await handler.HandleAuthenticateAsync();
            
            // Assert
            Assert.False(result.Succeeded);
            Assert.Equal("Authorization header does not presented", result.Failure?.Message);
        }
        
        [Fact]
        public async Task HandleAuthenticateAsync_InvalidUrlEncodedData_ThrowsException()
        {
            // Arrange
            var context = new DefaultHttpContext();
            context.Request.Headers["Authorization"] = $"{TgMiniAppAuthConstants.AuthenticationScheme} invalid_data_without_user_parameter";
            
            var handler = CreateHandler(context);
            
            // Act & Assert
            await Assert.ThrowsAsync<InvalidOperationException>(() => handler.HandleAuthenticateAsync());
        }
        
        [Fact]
        public async Task HandleAuthenticateAsync_ValidAuthorizationHeader_CreatesExpectedClaims()
        {
            // Arrange
            var context = new DefaultHttpContext();
            context.Request.Headers["Authorization"] = $"{TgMiniAppAuthConstants.AuthenticationScheme} {ValidFullDataAuth}";
            
            var handler = CreateHandler(context);
            
            // Act
            var result = await handler.HandleAuthenticateAsync();
            
            // Assert
            Assert.True(result.Succeeded);
            Assert.NotNull(result.Principal);
            
            // Verify required claims
            Assert.Equal(ValidFullDataAuth, result.Principal.FindFirstValue(TgMiniAppAuthConstants.Claims.RawAuthData));
            Assert.Equal("238932165", result.Principal.FindFirstValue(TgMiniAppAuthConstants.Claims.Id));
            Assert.Equal("John", result.Principal.FindFirstValue(TgMiniAppAuthConstants.Claims.FirstName));
            
            // Verify optional claims
            Assert.Equal("Doe", result.Principal.FindFirstValue(TgMiniAppAuthConstants.Claims.LastName));
            Assert.Equal("johndoe", result.Principal.FindFirstValue(TgMiniAppAuthConstants.Claims.Username));
            Assert.Equal("en", result.Principal.FindFirstValue(TgMiniAppAuthConstants.Claims.LanguageCode));
            Assert.Equal("True", result.Principal.FindFirstValue(TgMiniAppAuthConstants.Claims.IsPremium));
        }
        
        [Fact]
        public async Task HandleAuthenticateAsync_ValidAuthorizationHeader_RequiredFieldsOnly_HasOnlyRequiredClaims()
        {
            // Arrange
            var context = new DefaultHttpContext();
            context.Request.Headers["Authorization"] = $"{TgMiniAppAuthConstants.AuthenticationScheme} {ValidMinimalDataAuth}";
            
            var handler = CreateHandler(context);
            
            // Act
            var result = await handler.HandleAuthenticateAsync();
            
            // Assert
            Assert.True(result.Succeeded);
            Assert.NotNull(result.Principal);
            
            // Verify required claims
            Assert.Equal(ValidMinimalDataAuth, result.Principal.FindFirstValue(TgMiniAppAuthConstants.Claims.RawAuthData));
            Assert.Equal("238932165", result.Principal.FindFirstValue(TgMiniAppAuthConstants.Claims.Id));
            Assert.Equal("John", result.Principal.FindFirstValue(TgMiniAppAuthConstants.Claims.FirstName));
            
            // Verify optional claims don't exist
            Assert.Null(result.Principal.FindFirstValue(TgMiniAppAuthConstants.Claims.LastName));
            Assert.Null(result.Principal.FindFirstValue(TgMiniAppAuthConstants.Claims.Username));
            Assert.Null(result.Principal.FindFirstValue(TgMiniAppAuthConstants.Claims.LanguageCode));
            Assert.Null(result.Principal.FindFirstValue(TgMiniAppAuthConstants.Claims.IsPremium));
            Assert.Null(result.Principal.FindFirstValue(TgMiniAppAuthConstants.Claims.IsBot));
            Assert.Null(result.Principal.FindFirstValue(TgMiniAppAuthConstants.Claims.AllowWriteToPm));
            Assert.Null(result.Principal.FindFirstValue(TgMiniAppAuthConstants.Claims.PhotoUrl));
        }
        
        [Fact]
        public async Task HandleAuthenticateAsync_SchemeNameMismatch_HandledCorrectly()
        {
            // Arrange
            var context = new DefaultHttpContext();
            context.Request.Headers["Authorization"] = $"{TgMiniAppAuthConstants.AuthenticationScheme} {ValidFullDataAuth}";
            
            var differentScheme = new AuthenticationScheme(
                "DifferentScheme",
                "DifferentScheme",
                typeof(TestableAuthenticationHandler));
            
            var handler = new TestableAuthenticationHandler(
                _options,
                _loggerFactory, 
                _encoder);
            
            await handler.InitializeAsync(differentScheme, context);
            
            // Act
            var result = await handler.HandleAuthenticateAsync();
            
            // Assert
            Assert.True(result.Succeeded);
            Assert.NotNull(result.Principal);
            Assert.Equal("DifferentScheme", result.Ticket.AuthenticationScheme);
        }
        
        [Fact]
        public async Task HandleAuthenticateAsync_VeryLongValues_ProcessedCorrectly()
        {
            // Arrange
            var veryLongName = new string('A', 1000);
            var veryLongNameEncoded = HttpUtility.UrlEncode(veryLongName);
            var rawData = $"user=%7B%22id%22%3A238932165%2C%22first_name%22%3A%22{veryLongNameEncoded}%22%7D&auth_date=1731861317&hash=5a87fc9e604f54f428cea3a40b058fd5b9ac041803175c1404cf6788cf28ccc1";
            
            var context = new DefaultHttpContext();
            context.Request.Headers["Authorization"] = $"{TgMiniAppAuthConstants.AuthenticationScheme} {rawData}";
            
            var handler = CreateHandler(context);
            
            // Act
            var result = await handler.HandleAuthenticateAsync();
            
            // Assert
            Assert.True(result.Succeeded);
            Assert.NotNull(result.Principal);
            Assert.Equal(veryLongName, result.Principal.FindFirstValue(TgMiniAppAuthConstants.Claims.FirstName));
        }
        
        [Fact]
        public async Task HandleAuthenticateAsync_InvalidJsonData_ThrowsException()
        {
            // Arrange
            var invalidJson = "user=%7B%22id%22%3A238932165%2C%22first_name";  // Incomplete JSON
            
            var context = new DefaultHttpContext();
            context.Request.Headers["Authorization"] = $"{TgMiniAppAuthConstants.AuthenticationScheme} {invalidJson}";
            
            var handler = CreateHandler(context);
            
            // Act & Assert
            await Assert.ThrowsAsync<JsonException>(() => handler.HandleAuthenticateAsync());
        }
    }
}