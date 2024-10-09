# TgMiniAppAuth

TgMiniAppAuth is a .NET library that provides authentication and authorization functionality for Telegram Mini Apps. It simplifies the process of integrating Telegram's authentication mechanism into your ASP.NET Core applications.

[![Build & test](https://github.com/nazarovsa/TgMiniAppAuth/actions/workflows/dotnet-build-and-test.yml/badge.svg)](https://github.com/nazarovsa/TgMiniAppAuth/actions/workflows/dotnet-build-and-test.yml)
[![NuGet](https://img.shields.io/nuget/v/TgMiniAppAuth.svg)](https://www.nuget.org/packages/TgMiniAppAuth/)

## Features

- Easy integration with ASP.NET Core applications
- Telegram Mini App authentication handler
- Authorization policies for Telegram Mini Apps
- Access to Telegram user information
- Support for .NET 7.0 and .NET 8.0

## Installation

You can install the TgMiniAppAuth package via NuGet Package Manager:

```
dotnet add package TgMiniAppAuth
```

## Usage

### 1. Configure Services

In your `Program.cs` or `Startup.cs`, add the following:

```csharp
using TgMiniAppAuth;

public void ConfigureServices(IServiceCollection services)
{
    services.AddTgMiniAppAuth(configuration);

    // Options are now configured from the configuration
    // Make sure to add the following to your appsettings.json:
    // "TelegramMiniAppAuthorizationOptions": {
    //   "Token": "YOUR_BOT_TOKEN",
    //   "AuthDataValidInterval": "01:00:00"
    // }
}
```

### 2. Use Authentication and Authorization

In your controllers or API endpoints:

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
        var user = _telegramUserAccessor.User;
        return Ok(new
        {
            user.Id,
            user.FirstName,
            user.LastName,
            user.Username,
            user.LanguageCode,
            user.IsPremium,
            user.AllowWriteToPm
        });
    }
}
```

### 3. Client-side Implementation

In your Telegram Mini App, include the authentication data in the `Authorization` header of your HTTP requests:

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

You can create custom authorization policies using the `TgMiniAppAuthConstants.AuthenticationScheme`:

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

Then use the policy in your controllers:

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