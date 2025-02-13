using Authsignal;

namespace Microsoft.Extensions.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddAuthsignal(this IServiceCollection services, string apiSecretKey, string? apiUrl = null, int? retries = null)
    {
        return services.AddHttpClient()
            .AddTransient<IAuthsignalClient>(s =>
                new AuthsignalClient(s.GetRequiredService<IHttpClientFactory>(), apiSecretKey, apiUrl, retries));
    }
}