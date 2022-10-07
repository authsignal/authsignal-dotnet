using Authsignal;

namespace Microsoft.Extensions.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddAuthsignal(this IServiceCollection services, string secret,
        string? redirectUrl = null, string? baseAddress = null)
    {
        return services.AddHttpClient()
            .AddTransient<IAuthsignalClient>(s =>
                new AuthsignalClient(s.GetRequiredService<IHttpClientFactory>(), secret, redirectUrl, baseAddress));
    }
}