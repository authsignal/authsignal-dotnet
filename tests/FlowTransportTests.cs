using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;

namespace Authsignal.Tests;

public class FlowTransportTests
{
    public static IEnumerable<object[]> Operations => new[]
    {
        "start", "verify", "email-challenge", "email-verify",
        "sms-challenge", "sms-verify", "whatsapp-challenge", "whatsapp-verify"
    }.Select(operation => new object[] { operation });

    private sealed record Request(string Path, string Body, string? Authorization, string? Token);

    private sealed class Handler : HttpMessageHandler
    {
        public readonly ConcurrentQueue<Request> Requests = new();
        public int FailuresRemaining;
        public HttpStatusCode Status = HttpStatusCode.OK;
        public string Response = "{}";
        public bool HoldRequests;
        public int ExpectedRequests;
        public readonly TaskCompletionSource<bool> AllRequestsArrived = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly TaskCompletionSource<bool> ReleaseRequests = new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("application/json", request.Content!.Headers.ContentType!.MediaType);
            Assert.Contains("authsignal-dotnet", request.Headers.UserAgent.ToString());
            Requests.Enqueue(new Request(request.RequestUri!.AbsolutePath, await request.Content.ReadAsStringAsync(),
                request.Headers.Authorization?.ToString(),
                request.Headers.TryGetValues("X-Authsignal-Challenge-Token", out var tokens) ? tokens.Single() : null));

            if (Requests.Count == ExpectedRequests) AllRequestsArrived.TrySetResult(true);
            if (HoldRequests) await ReleaseRequests.Task.WaitAsync(cancellationToken);
            if (Interlocked.Decrement(ref FailuresRemaining) >= 0) throw new HttpRequestException("Connection failed");

            return new HttpResponseMessage(Status) { Content = new StringContent(Response, Encoding.UTF8, "application/json") };
        }
    }

    private static ServiceProvider Services(Handler handler, int retries = 2)
    {
        var services = new ServiceCollection();
        services.AddAuthsignal("secret", "https://example.test/v1/", retries);
        services.AddHttpClient(nameof(AuthsignalClient), httpClient =>
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "factory-default"))
            .ConfigurePrimaryHttpMessageHandler(() => handler);
        return services.BuildServiceProvider();
    }

    private static Task Invoke(IAuthsignalClient client, string operation, CancellationToken cancellationToken = default)
        => operation switch
        {
            "start" => client.StartFlow(new("sign-in"), cancellationToken),
            "verify" => client.VerifyFlow(new("sign-in", "server-token"), cancellationToken),
            "email-challenge" => client.Email.Challenge(new("email-token", "user@example.test"), cancellationToken),
            "email-verify" => client.Email.Verify(new("email-token", "001234"), cancellationToken),
            "sms-challenge" => client.Sms.Challenge(new("sms-token", "+123"), cancellationToken),
            "sms-verify" => client.Sms.Verify(new("sms-token", "001234"), cancellationToken),
            "whatsapp-challenge" => client.Whatsapp.Challenge(new("whatsapp-token", "+456"), cancellationToken),
            "whatsapp-verify" => client.Whatsapp.Verify(new("whatsapp-token", "001234"), cancellationToken),
            _ => throw new ArgumentException("Unknown operation", nameof(operation))
        };

    private static void AssertAuth(Request request)
    {
        if (request.Path.StartsWith("/v1/client/flows/"))
        {
            Assert.Null(request.Authorization);
            var channel = request.Path.Split('/').Last().Replace("email-otp", "email");
            Assert.Equal(channel + "-token", request.Token);
            Assert.DoesNotContain("challengeToken", request.Body);
        }
        else
        {
            Assert.Equal("Basic c2VjcmV0Og==", request.Authorization);
            Assert.Null(request.Token);
        }
    }

    [Theory]
    [MemberData(nameof(Operations))]
    public async Task RetryPreservesBodyAndRequestAuthentication(string operation)
    {
        var handler = new Handler { FailuresRemaining = 1 };
        using var services = Services(handler, retries: 1);
        await Invoke(services.GetRequiredService<IAuthsignalClient>(), operation);
        Assert.Equal(2, handler.Requests.Count);
        var requests = handler.Requests.ToArray();
        Assert.Equal(requests[0], requests[1]);
        AssertAuth(requests[1]);
    }

    [Theory]
    [MemberData(nameof(Operations))]
    public async Task DisabledRetriesPropagateTransportErrors(string operation)
    {
        var handler = new Handler { FailuresRemaining = 3 };
        using var services = Services(handler, retries: 0);
        await Assert.ThrowsAsync<HttpRequestException>(() => Invoke(services.GetRequiredService<IAuthsignalClient>(), operation));
        Assert.Single(handler.Requests);
    }

    [Theory]
    [MemberData(nameof(Operations))]
    public async Task PostServerErrorsAreNotRetried(string operation)
    {
        var handler = new Handler { Status = HttpStatusCode.ServiceUnavailable, Response = "{\"error\":\"unavailable\",\"errorDescription\":\"Try later\"}" };
        using var services = Services(handler);
        var error = await Assert.ThrowsAsync<AuthsignalException>(() => Invoke(services.GetRequiredService<IAuthsignalClient>(), operation));
        Assert.Equal(503, error.StatusCode);
        Assert.Equal("unavailable", error.Error);
        Assert.Equal("Try later", error.ErrorDescription);
        Assert.Single(handler.Requests);
    }

    [Theory]
    [MemberData(nameof(Operations))]
    public async Task InvalidCodeErrorsAreSpecializedOnlyForOtp(string operation)
    {
        var handler = new Handler { Status = HttpStatusCode.BadRequest, Response = "{\"error\":\"invalid_code\"}" };
        using var services = Services(handler);
        var error = await Assert.ThrowsAnyAsync<AuthsignalException>(() => Invoke(services.GetRequiredService<IAuthsignalClient>(), operation));
        Assert.Equal(operation.Contains('-'), error is InvalidCodeException);
        Assert.Equal(400, error.StatusCode);
        Assert.Equal("invalid_code", error.Error);
        Assert.Equal("invalid_code", error.ErrorDescription);
        Assert.Single(handler.Requests);
    }

    [Theory]
    [MemberData(nameof(Operations))]
    public async Task CancellationReachesEveryOperation(string operation)
    {
        var handler = new Handler { HoldRequests = true, ExpectedRequests = 1 };
        using var services = Services(handler);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var cancellation = new CancellationTokenSource();
        var pending = Invoke(services.GetRequiredService<IAuthsignalClient>(), operation, cancellation.Token);
        await handler.AllRequestsArrived.Task.WaitAsync(timeout.Token);
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task ConcurrentCallsKeepTokensAndBasicAuthenticationSeparate()
    {
        var handler = new Handler { HoldRequests = true, ExpectedRequests = 8 };
        using var services = Services(handler);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var client = services.GetRequiredService<IAuthsignalClient>();
        var pending = Operations.Select(row => Invoke(client, (string)row[0], timeout.Token)).ToArray();
        try
        {
            await handler.AllRequestsArrived.Task.WaitAsync(timeout.Token);
            Assert.Equal(8, handler.Requests.Count);
            Assert.All(handler.Requests, AssertAuth);
        }
        finally
        {
            handler.ReleaseRequests.TrySetResult(true);
            await Task.WhenAll(pending);
        }
    }

    [Theory]
    [InlineData("userId", "user")]
    [InlineData("email", "user@example.test")]
    [InlineData("phoneNumber", "+123")]
    [InlineData("username", "name")]
    public async Task StartFlowSupportsEachUserLookup(string field, string value)
    {
        var lookup = field switch
        {
            "userId" => new UserLookup(UserId: value),
            "email" => new UserLookup(Email: value),
            "phoneNumber" => new UserLookup(PhoneNumber: value),
            _ => new UserLookup(Username: value)
        };
        var handler = new Handler();
        using var services = Services(handler);
        await services.GetRequiredService<IAuthsignalClient>().StartFlow(new("sign-in", User: lookup));
        using var json = JsonDocument.Parse(handler.Requests.Single().Body);
        var user = json.RootElement.GetProperty("user");
        Assert.Single(user.EnumerateObject());
        Assert.Equal(value, user.GetProperty(field).GetString());
    }

    [Theory]
    [InlineData("email")]
    [InlineData("sms")]
    [InlineData("whatsapp")]
    public async Task MissingTokensNeverSendBasicAuthenticatedOtpRequests(string channel)
    {
        var handler = new Handler();
        using var services = Services(handler);
        var client = services.GetRequiredService<IAuthsignalClient>();
        foreach (var token in new[] { "", null })
        {
            Func<Task> challenge = channel switch
            {
                "email" => () => client.Email.Challenge(new(token!)),
                "sms" => () => client.Sms.Challenge(new(token!)),
                _ => () => client.Whatsapp.Challenge(new(token!))
            };
            Func<Task> verify = channel switch
            {
                "email" => () => client.Email.Verify(new(token!, "001234")),
                "sms" => () => client.Sms.Verify(new(token!, "001234")),
                _ => () => client.Whatsapp.Verify(new(token!, "001234"))
            };
            await Assert.ThrowsAsync<ArgumentException>(challenge);
            await Assert.ThrowsAsync<ArgumentException>(verify);
        }
        Assert.Empty(handler.Requests);
    }
}
