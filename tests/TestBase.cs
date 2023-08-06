using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Authsignal.Tests;

public partial class TestBase
{
    private readonly ServiceCollection _services = new ServiceCollection();
    protected readonly ServiceProvider ServiceProvider;

    protected IAuthsignalClient AuthsignalClient => ServiceProvider.GetRequiredService<IAuthsignalClient>();

    protected IConfigurationRoot Configuration = new ConfigurationBuilder()
        .SetBasePath(Directory.GetCurrentDirectory())
        .AddJsonFile("appsettings.json")
        .Build();

    public TestBase()
    {
        _services.AddAuthsignal(Configuration["Secret"], null, Configuration["BaseUrl"]);
        ServiceProvider = _services.BuildServiceProvider();
    }
}
