using System.Net;
using System.Text;
using Microsoft.Extensions.Http;

namespace Authsignal.Tests;

public class RetryTests
{
    private sealed class QueueHandler(params Func<HttpResponseMessage>[] responses) : HttpMessageHandler
    {
        private readonly Queue<Func<HttpResponseMessage>> _responses = new(responses);
        public int Attempts { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Attempts++;
            try
            {
                return Task.FromResult(_responses.Dequeue()());
            }
            catch (Exception exception)
            {
                return Task.FromException<HttpResponseMessage>(exception);
            }
        }
    }

    private sealed class TestHttpClientFactory(HttpClient client) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => client;
    }

    private static HttpResponseMessage Response(HttpStatusCode status, string body, string? retryAfter = null)
    {
        var response = new HttpResponseMessage(status)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };
        if (retryAfter != null)
        {
            response.Headers.TryAddWithoutValidation("Retry-After", retryAfter);
        }
        return response;
    }

    private static (AuthsignalClient Client, QueueHandler Handler, HttpClient HttpClient) CreateClient(
        int? retries,
        params HttpResponseMessage[] responses)
    {
        var handler = new QueueHandler(responses.Select<HttpResponseMessage, Func<HttpResponseMessage>>(response => () => response).ToArray());
        var httpClient = new HttpClient(handler);
        var client = new AuthsignalClient(new TestHttpClientFactory(httpClient), "secret", "https://api.test/", retries);
        return (client, handler, httpClient);
    }

    private static (AuthsignalClient Client, QueueHandler Handler) CreateClient(
        params Func<HttpResponseMessage>[] responses)
    {
        var handler = new QueueHandler(responses);
        var httpClient = new HttpClient(handler);
        var client = new AuthsignalClient(new TestHttpClientFactory(httpClient), "secret", "https://api.test/");
        return (client, handler);
    }

    [Fact]
    public async Task RetriesSafeRequestsTwiceOn5xx()
    {
        var (client, handler, _) = CreateClient(null,
            Response(HttpStatusCode.ServiceUnavailable, "{\"error\":\"unavailable\"}"),
            Response(HttpStatusCode.ServiceUnavailable, "{\"error\":\"unavailable\"}"),
            Response(HttpStatusCode.OK, "{\"isEnrolled\":false}"));

        await client.GetUser(new GetUserRequest("user"));

        Assert.Equal(3, handler.Attempts);
    }

    [Fact]
    public async Task Retries429Responses()
    {
        var (client, handler, _) = CreateClient(null,
            Response(HttpStatusCode.TooManyRequests, "{\"error\":\"rate_limited\"}", "0"),
            Response(HttpStatusCode.OK, "{\"isEnrolled\":false}"));

        await client.GetUser(new GetUserRequest("user"));

        Assert.Equal(2, handler.Attempts);
    }

    [Fact]
    public async Task RetriesTransientNetworkFailures()
    {
        var (client, handler) = CreateClient(
            () => throw new HttpRequestException("connection reset"),
            () => Response(HttpStatusCode.OK, "{\"isEnrolled\":false}"));

        await client.GetUser(new GetUserRequest("user"));

        Assert.Equal(2, handler.Attempts);
    }

    [Fact]
    public async Task RetriesIdempotentWrites()
    {
        var (client, handler, _) = CreateClient(null,
            Response(HttpStatusCode.ServiceUnavailable, "{\"error\":\"unavailable\"}"),
            Response(HttpStatusCode.OK,
                "{\"idempotencyKey\":\"key\",\"state\":\"ALLOW\",\"url\":\"\",\"token\":\"\",\"isEnrolled\":false}"));

        await client.Track(new TrackRequest("user", "withdrawal", new TrackAttributes(IdempotencyKey: "key")));

        Assert.Equal(2, handler.Attempts);
    }

    [Fact]
    public async Task DoesNotRetryNonIdempotentWritesOr499()
    {
        var (writeClient, writeHandler, _) = CreateClient(null,
            Response(HttpStatusCode.ServiceUnavailable, "{\"error\":\"unavailable\"}"));
        await Assert.ThrowsAsync<AuthsignalException>(() => writeClient.Track(new TrackRequest("user", "withdrawal")));
        Assert.Equal(1, writeHandler.Attempts);

        var (challengeClient, challengeHandler, _) = CreateClient(null,
            Response((HttpStatusCode)499, "{\"error\":\"challenge_required\"}"));
        await Assert.ThrowsAsync<AuthsignalException>(() => challengeClient.GetUser(new GetUserRequest("user")));
        Assert.Equal(1, challengeHandler.Attempts);
    }

    [Fact]
    public async Task AllowsRetriesToBeDisabledAndUsesBoundedTimeout()
    {
        var (client, handler, httpClient) = CreateClient(0,
            Response(HttpStatusCode.ServiceUnavailable, "{\"error\":\"unavailable\"}"));

        await Assert.ThrowsAsync<AuthsignalException>(() => client.GetUser(new GetUserRequest("user")));

        Assert.Equal(1, handler.Attempts);
        Assert.Equal(TimeSpan.FromSeconds(10), httpClient.Timeout);
    }
}
