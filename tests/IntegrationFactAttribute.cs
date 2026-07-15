using System.Text.Json;

namespace Authsignal.Tests;

public sealed class IntegrationFactAttribute : FactAttribute
{
    private const string PlaceholderApiSecretKey = "YOUR_API_SECRET_KEY";

    public IntegrationFactAttribute()
    {
        var configurationPath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");

        if (!File.Exists(configurationPath))
        {
            Skip = "Integration tests require tests/appsettings.json.";
            return;
        }

        using var configuration = JsonDocument.Parse(File.ReadAllText(configurationPath));

        if (!configuration.RootElement.TryGetProperty("ApiSecretKey", out var apiSecretKey)
            || string.IsNullOrWhiteSpace(apiSecretKey.GetString())
            || apiSecretKey.GetString() == PlaceholderApiSecretKey)
        {
            Skip = "Integration tests require a configured Authsignal API secret key.";
        }
    }
}
