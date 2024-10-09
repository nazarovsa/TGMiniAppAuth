using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using TgMiniAppAuth.AuthContext;
using TgMiniAppAuth.Authentication;
using TgMiniAppAuth.Authorization;

namespace TgMiniAppAuth;

/// <summary>
/// Provides extension methods for adding Telegram Mini App authentication services to the service collection.
/// </summary>
public static class ServiceCollectionExtensions
{
  /// <summary>
  /// Adds Telegram Mini App authentication and authorization services to the specified service collection.
  /// </summary>
  /// <param name="services">The service collection to add the services to.</param>
  /// <returns>The updated service collection.</returns>
  /// <exception cref="ArgumentNullException">Thrown if the <paramref name="services"/> is null.</exception>
  public static IServiceCollection AddTgMiniAppAuth(this IServiceCollection services)
  {
    ArgumentNullException.ThrowIfNull(services, nameof(services));

    services.AddAuthentication(TgMiniAppAuthConstants.AuthenticationScheme)
      .AddScheme<AuthenticationSchemeOptions, TelegramMiniAppAuthenticationHandler>(
        TgMiniAppAuthConstants.AuthenticationScheme, _ => { });

    services.AddAuthorization(opt => opt.AddPolicy(TgMiniAppAuthConstants.AuthenticationScheme,
      policy =>
      {
        policy.RequireAuthenticatedUser();
        policy.Requirements.Add(new TelegramMiniAppAuthorizationRequirement());
      }));

    services.AddUserContextAccessor();

    return services;
  }

  /// <summary>
  /// Adds the authentication context accessor service to the specified service collection.
  /// </summary>
  /// <param name="services">The service collection to add the service to.</param>
  /// <returns>The updated service collection.</returns>
  /// <exception cref="ArgumentNullException">Thrown if the <paramref name="services"/> is null.</exception>
  public static IServiceCollection AddUserContextAccessor(this IServiceCollection services)
  {
    ArgumentNullException.ThrowIfNull(services, nameof(services));

    services.TryAddScoped<ITelegramUserAccessor, TelegramUserAccessor>();

    return services;
  }
}