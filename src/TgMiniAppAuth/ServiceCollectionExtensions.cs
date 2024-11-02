using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
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
  /// <param name="configuration">The configuration to bind the options to.</param>
  /// <returns>The updated service collection.</returns>
  /// <exception cref="ArgumentNullException">Thrown if the <paramref name="services"/> or <paramref name="configuration"/> is null.</exception>
  public static IServiceCollection AddTgMiniAppAuth(this IServiceCollection services, IConfiguration configuration)
  {
    ArgumentNullException.ThrowIfNull(services, nameof(services));
    ArgumentNullException.ThrowIfNull(configuration, nameof(configuration));

    services.Configure<TelegramMiniAppAuthorizationOptions>(
      configuration.GetSection(nameof(TelegramMiniAppAuthorizationOptions)));

    services.AddAuthentication(TgMiniAppAuthConstants.AuthenticationScheme)
      .AddScheme<AuthenticationSchemeOptions, TelegramMiniAppAuthenticationHandler>(
        TgMiniAppAuthConstants.AuthenticationScheme, _ => { });

    services.AddSingleton<IAuthorizationHandler, TelegramMiniAppAuthorizationHandler>();
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