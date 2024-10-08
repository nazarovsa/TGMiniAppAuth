using Microsoft.Extensions.DependencyInjection;
using TGMiniAppAuth.AuthContext;
using TGMiniAppAuth.Authorization;

namespace TGMiniAppAuth;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddTgMiniAppAuth(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services, nameof(services));

        services.AddAuthentication();
        services.AddAuthorization(options =>
        {
            options.AddPolicy("TelegramMiniApp", policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.Requirements.Add(new TelegramMiniAppAuthorizationRequirement());
            });
        });

        services.AddAuthContextAccessor();

        return services;
    }

    public static IServiceCollection AddAuthContextAccessor(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services,  nameof(services));

        services.AddScoped<IAuthContextAccessor, AuthContextAccessor>();

        return services;
    }
}