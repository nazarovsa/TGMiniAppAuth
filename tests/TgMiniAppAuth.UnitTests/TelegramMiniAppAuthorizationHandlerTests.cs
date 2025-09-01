using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using NSubstitute;
using System.Security.Claims;
using TgMiniAppAuth;
using TgMiniAppAuth.AuthContext;
using TgMiniAppAuth.Authentication;
using TgMiniAppAuth.Authorization;

namespace TgMIniAppAuth.UnitTests;

public class TelegramMiniAppAuthorizationHandlerTests
{
    private readonly ITelegramAuthorizationContextValidator _validator;
    private readonly IOptions<TelegramMiniAppAuthorizationOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly TelegramMiniAppAuthorizationHandler _handler;
    private readonly AuthorizationHandlerContext _context;
    private readonly ClaimsPrincipal _user;
    private readonly TelegramMiniAppAuthorizationRequirement _requirement;

    private const string ValidRawAuthData = "query_id=AAHF0D0OAAAAAMXQPQ4dKBBT&user=%7B%22id%22%3A238932165%2C%22first_name%22%3A%22Sergey%22%2C%22last_name%22%3A%22Nazarov%22%2C%22username%22%3A%22sanazarov%22%2C%22language_code%22%3A%22en%22%2C%22is_premium%22%3Atrue%2C%22allows_write_to_pm%22%3Atrue%2C%22photo_url%22%3A%22https%3A%5C%2F%5C%2Ft.me%5C%2Fi%5C%2Fuserpic%5C%2F320%5C%2FGPG1DYLiVdlIoxJ_2WIfwBTsJRJ81gsmcLCz3PABLBQ.svg%22%7D&auth_date=1731861317&signature=91Z5ikpqRSgvbVgMiYoN-7TDz8JjsM-V-AuyXqQSN7ScHjmrR1YHtVUzerlqITrNgwtAON_r9miNAGuozNdzCg&hash=5a87fc9e604f54f428cea3a40b058fd5b9ac041803175c1404cf6788cf28ccc1";
    private const string BotToken = "7888212791:AAHOf0quo22Rqfj_TYuHcYnKO051WMOKYB0";
    private const int StackThreshold = 1024;

    public TelegramMiniAppAuthorizationHandlerTests()
    {
        _validator = Substitute.For<ITelegramAuthorizationContextValidator>();
        _options = Substitute.For<IOptions<TelegramMiniAppAuthorizationOptions>>();
        _timeProvider = Substitute.For<TimeProvider>();
            
        _options.Value.Returns(new TelegramMiniAppAuthorizationOptions
        {
            Token = BotToken,
            AuthDataValidInterval = TimeSpan.FromHours(2),
            StackAllocationThreshold = StackThreshold
        });
            
        _handler = new TelegramMiniAppAuthorizationHandler(_options, _timeProvider, _validator);
            
        _user = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(TgMiniAppAuthConstants.Claims.RawAuthData, ValidRawAuthData)
        }));
            
        _requirement = new TelegramMiniAppAuthorizationRequirement();
        _context = new AuthorizationHandlerContext(new[] { _requirement }, _user, null);
    }

    [Fact]
    public async Task HandleRequirementAsync_ValidData_NotExpired_Succeeds()
    {
        // Arrange
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(1731861317);
        var now = issuedAt.AddMinutes(10); // 10 minutes after issuance (within 2 hour limit)
            
        _validator.IsValidTelegramMiniAppContext(
                Arg.Is(ValidRawAuthData), 
                Arg.Is(BotToken), 
                out Arg.Any<DateTimeOffset>(),
                Arg.Is(StackThreshold))
            .Returns(x =>
            {
                x[2] = issuedAt;
                return true;
            });
                
        _timeProvider.GetUtcNow().Returns(now);
            
        // Act
        await _handler.HandleAsync(_context);
            
        // Assert
        Assert.True(_context.HasSucceeded);
    }
        
    [Fact]
    public async Task HandleRequirementAsync_ValidData_Expired_Fails()
    {
        // Arrange
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(1731861317);
        var now = issuedAt.AddHours(3); // 3 hours after issuance (exceeds 2 hour limit)
            
        _validator.IsValidTelegramMiniAppContext(
                Arg.Is(ValidRawAuthData), 
                Arg.Is(BotToken), 
                out Arg.Any<DateTimeOffset>(),
                Arg.Is(StackThreshold))
            .Returns(x =>
            {
                x[2] = issuedAt;
                return true;
            });
                
        _timeProvider.GetUtcNow().Returns(now);
            
        // Act
        await _handler.HandleAsync(_context);
            
        // Assert
        Assert.False(_context.HasSucceeded);
    }
        
    [Fact]
    public async Task HandleRequirementAsync_InvalidHash_Fails()
    {
        // Arrange
        _validator.IsValidTelegramMiniAppContext(
                Arg.Is(ValidRawAuthData), 
                Arg.Is(BotToken), 
                out Arg.Any<DateTimeOffset>(),
                Arg.Is(StackThreshold))
            .Returns(false);
                
        // Act
        await _handler.HandleAsync(_context);
            
        // Assert
        Assert.False(_context.HasSucceeded);
    }
        
    [Fact]
    public async Task HandleRequirementAsync_MissingAuthDataClaim_Fails()
    {
        // Arrange
        var userWithoutAuthData = new ClaimsPrincipal(new ClaimsIdentity(new Claim[0]));
        var context = new AuthorizationHandlerContext(new[] { _requirement }, userWithoutAuthData, null);
            
        // Act
        await _handler.HandleAsync(context);
            
        // Assert
        Assert.False(context.HasSucceeded);
    }
}