using TgMiniAppAuth.Authorization;

namespace TgMIniAppAuth.UnitTests;

public class TelegramAuthorizationContextValidatorTests
{
    private const string Context =
        "query_id=AAHF0D0OAAAAAMXQPQ4dKBBT&user=%7B%22id%22%3A238932165%2C%22first_name%22%3A%22Sergey%22%2C%22last_name%22%3A%22Nazarov%22%2C%22username%22%3A%22sanazarov%22%2C%22language_code%22%3A%22en%22%2C%22is_premium%22%3Atrue%2C%22allows_write_to_pm%22%3Atrue%2C%22photo_url%22%3A%22https%3A%5C%2F%5C%2Ft.me%5C%2Fi%5C%2Fuserpic%5C%2F320%5C%2FGPG1DYLiVdlIoxJ_2WIfwBTsJRJ81gsmcLCz3PABLBQ.svg%22%7D&auth_date=1731861317&signature=91Z5ikpqRSgvbVgMiYoN-7TDz8JjsM-V-AuyXqQSN7ScHjmrR1YHtVUzerlqITrNgwtAON_r9miNAGuozNdzCg&hash=5a87fc9e604f54f428cea3a40b058fd5b9ac041803175c1404cf6788cf28ccc1";

    private const string Token = "7888212791:AAHOf0quo22Rqfj_TYuHcYnKO051WMOKYB0";

    [Fact]
    public void IsValidTelegramMiniAppContext_ValidContextAndDifferentToken_ReturnsFalse()
    {
        Assert.False(TelegramAuthorizationContextValidator.IsValidTelegramMiniAppContext(Context, "ha-ha", out _));
    }

    [Fact]
    public void IsValidTelegramMiniAppContext_ValidContextAndToken_ReturnsTrueAndExpectedDateTimeOffset()
    {
        var expectedDateTimeOffset = DateTimeOffset.FromUnixTimeSeconds(1731861317);

        var result =
            TelegramAuthorizationContextValidator.IsValidTelegramMiniAppContext(Context, Token, out var issuedAt);

        Assert.True(result);
        Assert.Equal(expectedDateTimeOffset, issuedAt);
    }
}