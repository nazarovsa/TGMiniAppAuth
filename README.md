# TgMiniAppAuth

TgMiniAppAuth is a .NET library that simplifies Telegram Mini App authentication and authorization for ASP.NET Core applications.

[![Build & test](https://github.com/nazarovsa/TgMiniAppAuth/actions/workflows/dotnet-build-and-test.yml/badge.svg)](https://github.com/nazarovsa/TgMiniAppAuth/actions/workflows/dotnet-build-and-test.yml)
[![NuGet](https://img.shields.io/nuget/v/TgMiniAppAuth.svg)](https://www.nuget.org/packages/TgMiniAppAuth/)

## Features

- Seamless integration with ASP.NET Core
- Built-in Telegram Mini App authentication handler
- Customizable authorization policies
- Easy access to authenticated Telegram user data
- Support for .NET 7.0 and 8.0

## Installation

```
dotnet add package TgMiniAppAuth
```

## Quick Start

1. Configure services in `Program.cs`:

```csharp
using TgMiniAppAuth;

services.AddTgMiniAppAuth(configuration);
```

2. Add to `appsettings.json`:

```json
"TelegramMiniAppAuthorizationOptions": {
  "Token": "YOUR_BOT_TOKEN",
  "AuthDataValidInterval": "01:00:00"
}
```

3. Use in your controller:

```csharp
[Authorize(AuthenticationSchemes = TgMiniAppAuthConstants.AuthenticationScheme)]
public class TelegramController : ControllerBase
{
    private readonly ITelegramUserAccessor _telegramUserAccessor;

    public TelegramController(ITelegramUserAccessor telegramUserAccessor)
    {
        _telegramUserAccessor = telegramUserAccessor;
    }

    [HttpGet("user")]
    public IActionResult GetUser()
    {
        return Ok(_telegramUserAccessor.User);
    }
}
```

4. Client-side implementation:

```javascript
const tgWebApp = window.Telegram.WebApp;

async function fetchUserData() {
    const response = await fetch('/api/telegram/user', {
        headers: {
            'Authorization': `TMiniApp ${tgWebApp.initData}`
        }
    });
    const userData = await response.json();
    console.log(userData);
}
```

## Advanced Usage

### Custom Authorization Policies

```csharp
services.AddAuthorization(options =>
{
    options.AddPolicy("PremiumUsers", policy =>
    {
        policy.AddAuthenticationSchemes(TgMiniAppAuthConstants.AuthenticationScheme);
        policy.RequireAuthenticatedUser();
        policy.RequireAssertion(context =>
        {
            var user = context.User;
            return user.HasClaim(c => c.Type == TgMiniAppAuthConstants.Claims.IsPremium && c.Value == "True");
        });
    });
});
```

Use the policy in your controllers:

```csharp
[Authorize(Policy = "PremiumUsers")]
public IActionResult PremiumContent()
{
    // ...
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.