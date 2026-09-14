using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;

namespace Authsignal.Tests;

public class FlowsTests
{
    private const string Action = "{\"state\":\"CHALLENGE_SUCCEEDED\",\"completedSteps\":[{\"stepType\":\"VERIFICATION_REQUIRED\",\"verificationMethod\":\"SMS\",\"userAuthenticatorId\":\"auth\"}]}";
    private const string User = "{\"userId\":\"user\",\"email\":\"a@example.test\",\"phoneNumber\":\"+123\",\"username\":\"name\",\"displayName\":\"Name\",\"authenticators\":[{\"userAuthenticatorId\":\"auth\",\"verificationMethod\":\"SMS\",\"phoneNumber\":\"+123\"}]}";

    private sealed class Handler : HttpMessageHandler
    {
        public string Response = "{}";
        public HttpStatusCode Status = HttpStatusCode.OK;
        public readonly List<(string Path, string Body, string? Auth, string? Token, HttpMethod Method)> Requests = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Assert.True(request.Headers.Contains("X-Authsignal-Version"));
            Requests.Add((request.RequestUri!.AbsolutePath, request.Content == null ? "" : await request.Content.ReadAsStringAsync(),
                request.Headers.Authorization?.ToString(),
                request.Headers.TryGetValues("X-Authsignal-Challenge-Token", out var tokens) ? tokens.Single() : null, request.Method));
            return new HttpResponseMessage(Status) { Content = new StringContent(Response, Encoding.UTF8, "application/json") };
        }
    }

    private static ServiceProvider Services(Handler handler)
    {
        var services = new ServiceCollection();
        services.AddAuthsignal("secret", "https://example.test/v1", retries: 0);
        services.AddHttpClient(nameof(AuthsignalClient)).ConfigurePrimaryHttpMessageHandler(() => handler);
        return services.BuildServiceProvider();
    }

    private static void AssertRequest(Handler handler, string path, string body, string? token = null)
    {
        var request = handler.Requests.Last();
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("/v1/" + path, request.Path);
        Assert.Equal(token, request.Token);
        Assert.Equal(token == null ? "Basic c2VjcmV0Og==" : null, request.Auth);
        using var expected = JsonDocument.Parse(body);
        using var actual = JsonDocument.Parse(request.Body);
        AssertJson(expected.RootElement, actual.RootElement);
    }

    private static void AssertJson(JsonElement expected, JsonElement actual)
    {
        Assert.Equal(expected.ValueKind, actual.ValueKind);
        if (expected.ValueKind == JsonValueKind.Object)
        {
            Assert.Equal(expected.EnumerateObject().Count(), actual.EnumerateObject().Count());
            foreach (var p in expected.EnumerateObject()) AssertJson(p.Value, actual.GetProperty(p.Name));
        }
        else Assert.Equal(expected.ToString(), actual.ToString());
    }

    [Fact]
    public async Task StartFullAndMinimalFlow()
    {
        var handler = new Handler { Response = "{\"action\":{\"state\":\"CHALLENGE_REQUIRED\",\"completedSteps\":[],\"nextStep\":{\"stepType\":\"ENROLLMENT_OPTIONAL\",\"verificationMethods\":[\"EMAIL_OTP\"]}},\"challengeToken\":\"token\",\"challengeUrl\":\"url\",\"user\":" + User + "}" };
        using var services = Services(handler);
        var client = services.GetRequiredService<IAuthsignalClient>();
        var response = await client.StartFlow(new StartFlowRequest("sign-in", new UserLookup(UserId: "üser"),
            new ChallengeAttributes(DeviceId: "d", IpAddress: "127.0.0.1", UserAgent: "test", Locale: "en", Custom: new() { ["keep_this"] = false }),
            "https://example.test/done", "client"));
        Assert.Equal(FlowState.CHALLENGE_REQUIRED, response.Action.State);
        Assert.Equal(ActionStepType.ENROLLMENT_OPTIONAL, response.Action.NextStep!.StepType);
        Assert.Equal(VerificationMethod.EMAIL_OTP, response.Action.NextStep.VerificationMethods.Single());
        Assert.Equal("token", response.ChallengeToken); Assert.Equal("url", response.ChallengeUrl);
        Assert.Equal("Name", response.User!.DisplayName);
        AssertRequest(handler, "flows", "{\"actionCode\":\"sign-in\",\"clientId\":\"client\",\"redirectUrl\":\"https://example.test/done\",\"user\":{\"userId\":\"üser\"},\"attributes\":{\"deviceId\":\"d\",\"ipAddress\":\"127.0.0.1\",\"userAgent\":\"test\",\"locale\":\"en\",\"custom\":{\"keep_this\":false}}}");
        await client.StartFlow(new StartFlowRequest("sign-in"));
        AssertRequest(handler, "flows", "{\"actionCode\":\"sign-in\"}");
    }

    [Fact]
    public async Task SupportsEveryNodeVerificationMethod()
    {
        const string methods = "[\"SMS\",\"EMAIL_OTP\",\"EMAIL_MAGIC_LINK\",\"AUTHENTICATOR_APP\",\"PASSKEY\",\"SECURITY_KEY\",\"PUSH\",\"VERIFF\",\"IPROOV\",\"IDVERSE\",\"PALM_BIOMETRICS_RR\",\"RECOVERY_CODE\",\"DEVICE\",\"WHATSAPP\"]";
        var handler = new Handler { Response = "{\"action\":{\"state\":\"CHALLENGE_REQUIRED\",\"completedSteps\":[],\"nextStep\":{\"stepType\":\"ENROLLMENT_REQUIRED\",\"verificationMethods\":" + methods + "}},\"challengeToken\":\"token\",\"challengeUrl\":\"url\"}" };
        using var services = Services(handler);
        var response = await services.GetRequiredService<IAuthsignalClient>().StartFlow(new("sign-in"));
        Assert.Null(response.User);
        Assert.Empty(response.Action.CompletedSteps!);
        Assert.Equal(ActionStepType.ENROLLMENT_REQUIRED, response.Action.NextStep!.StepType);
        using var expected = JsonDocument.Parse(methods);
        Assert.Equal(expected.RootElement.EnumerateArray().Select(m => m.GetString()), response.Action.NextStep.VerificationMethods.Select(m => m.ToString()));
    }

    [Fact]
    public async Task VerifyFlowAndOptionalResponses()
    {
        var handler = new Handler { Response = "{\"action\":" + Action + ",\"user\":" + User + ",\"session\":{\"accessToken\":\"a\",\"refreshToken\":\"r\"}}" };
        using var services = Services(handler);
        var client = services.GetRequiredService<IAuthsignalClient>();
        var response = await client.VerifyFlow(new VerifyFlowRequest("sign-in", "rotated"));
        Assert.Equal(new AuthenticationSession("a", "r"), response.Session);
        Assert.Equal("user", response.User!.UserId);
        Assert.Equal("a@example.test", response.User.Email);
        Assert.Equal("+123", response.User.PhoneNumber);
        Assert.Equal("name", response.User.Username);
        Assert.Equal("Name", response.User.DisplayName);
        Assert.Equal(new FlowUserAuthenticator("auth", VerificationMethod.SMS, PhoneNumber: "+123"), response.User.Authenticators.Single());
        Assert.Equal(FlowState.CHALLENGE_SUCCEEDED, response.Action.State);
        Assert.Equal(new CompletedActionStep(ActionStepType.VERIFICATION_REQUIRED, VerificationMethod.SMS, "auth"), response.Action.CompletedSteps!.Single());
        AssertRequest(handler, "flows/verify", "{\"actionCode\":\"sign-in\",\"challengeToken\":\"rotated\"}");
        handler.Response = "{\"action\":{\"state\":\"CHALLENGE_FAILED\",\"completedSteps\":[]}}";
        response = await client.VerifyFlow(new VerifyFlowRequest("sign-in", "rotated"));
        Assert.Null(response.Session); Assert.Null(response.User); Assert.Null(response.Action.NextStep);
        Assert.Equal(FlowState.CHALLENGE_FAILED, response.Action.State);
    }

    private static Task<OtpChallengeResponse> Challenge(IAuthsignalClient c, string channel, string? value)
        => channel switch { "email-otp" => c.Email.Challenge(new("first", value)), "sms" => c.Sms.Challenge(new("first", value)), _ => c.Whatsapp.Challenge(new("first", value)) };

    [Fact]
    public async Task LiveResponsesCanOmitCompletedSteps()
    {
        var handler = new Handler { Response = """
            {"action":{"state":"CHALLENGE_REQUIRED","nextStep":{"stepType":"ENROLLMENT_REQUIRED","verificationMethods":["EMAIL_OTP"]}},"challengeToken":"initial","challengeUrl":"https://example.test/challenge","user":{"userId":"user","authenticators":[]}}
            """ };
        using var services = Services(handler);
        var client = services.GetRequiredService<IAuthsignalClient>();
        var started = await client.StartFlow(new("signup-v2", User: new(UserId: "user")));
        Assert.Null(started.Action.CompletedSteps);
        Assert.Equal(ActionStepType.ENROLLMENT_REQUIRED, started.Action.NextStep!.StepType);

        handler.Response = """
            {"action":{"state":"CHALLENGE_SUCCEEDED"},"challengeToken":"rotated","user":{"userId":"user","authenticators":[{"userAuthenticatorId":"auth","verificationMethod":"EMAIL_OTP"}]}}
            """;
        var verified = await client.Email.Verify(new(started.ChallengeToken, "001234"));
        Assert.Null(verified.Action.CompletedSteps);
        Assert.Null(verified.Action.NextStep);
        Assert.Equal(FlowState.CHALLENGE_SUCCEEDED, verified.Action.State);

        handler.Response = """
            {"action":{"state":"CHALLENGE_SUCCEEDED","completedSteps":[{"stepType":"ENROLLMENT_REQUIRED","completedAt":"2026-09-14T05:49:35.778Z","verificationMethod":"EMAIL_OTP"}]}}
            """;
        var finished = await client.VerifyFlow(new("signup-v2", verified.ChallengeToken));
        var step = Assert.Single(finished.Action.CompletedSteps!);
        Assert.Equal(ActionStepType.ENROLLMENT_REQUIRED, step.StepType);
        Assert.Equal(VerificationMethod.EMAIL_OTP, step.VerificationMethod);
        Assert.Null(step.UserAuthenticatorId);
        Assert.Null(finished.Action.NextStep);
        Assert.Equal(FlowState.CHALLENGE_SUCCEEDED, finished.Action.State);
    }

    private static Task<OtpVerifyResponse> Verify(IAuthsignalClient c, string channel)
        => channel switch { "email-otp" => c.Email.Verify(new("second", "001234")), "sms" => c.Sms.Verify(new("second", "001234")), _ => c.Whatsapp.Verify(new("second", "001234")) };

    [Theory]
    [InlineData("email-otp")]
    [InlineData("sms")]
    [InlineData("whatsapp")]
    public async Task OtpChannel(string channel)
    {
        var handler = new Handler { Response = "{\"retryAfterSeconds\":0}" };
        using var services = Services(handler);
        var client = services.GetRequiredService<IAuthsignalClient>();
        Assert.Equal(0, (await Challenge(client, channel, "destination")).RetryAfterSeconds);
        AssertRequest(handler, "client/flows/challenge/" + channel, "{\"" + (channel == "email-otp" ? "email" : "phoneNumber") + "\":\"destination\"}", "first");
        handler.Response = "{}";
        Assert.Null((await Challenge(client, channel, null)).RetryAfterSeconds);
        AssertRequest(handler, "client/flows/challenge/" + channel, "{}", "first");
        handler.Response = "{\"action\":" + Action + ",\"user\":" + User + ",\"challengeToken\":\"rotated\"}";
        var response = await Verify(client, channel);
        Assert.Equal("rotated", response.ChallengeToken); Assert.Equal("user", response.User.UserId);
        Assert.Equal(FlowState.CHALLENGE_SUCCEEDED, response.Action.State);
        AssertRequest(handler, "client/flows/verify/" + channel, "{\"verificationCode\":\"001234\"}", "second");
        handler.Response = "{}";
        await client.StartFlow(new("sign-in"));
        AssertRequest(handler, "flows", "{\"actionCode\":\"sign-in\"}");
    }

    [Theory]
    [InlineData("email-otp")]
    [InlineData("sms")]
    [InlineData("whatsapp")]
    public async Task OtpErrors(string channel)
    {
        var handler = new Handler { Response = "{\"error\":\"invalid_code\",\"errorDescription\":\"wrong code\"}", Status = HttpStatusCode.BadRequest };
        using var services = Services(handler);
        var client = services.GetRequiredService<IAuthsignalClient>();
        var error = await Assert.ThrowsAsync<InvalidCodeException>(() => Verify(client, channel));
        Assert.Equal(400, error.StatusCode); Assert.Equal("invalid_code", error.Error); Assert.Equal("wrong code", error.ErrorDescription);
        handler.Status = HttpStatusCode.Unauthorized; handler.Response = "{\"error\":\"expired_token\"}";
        var other = await Assert.ThrowsAsync<AuthsignalException>(() => Verify(client, channel));
        Assert.Equal("expired_token", other.Error);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task PublicConstructorUsesCorrectAuthOnTheWire(bool otp)
    {
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var received = Task.Run(async () =>
            {
                using var socket = await listener.AcceptTcpClientAsync();
                using var stream = socket.GetStream();
                using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
                var headers = new List<string>();
                string? line;
                while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync())) headers.Add(line);
                var bytes = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}");
                await stream.WriteAsync(bytes);
                return headers;
            });
            var client = new AuthsignalClient("secret", $"http://127.0.0.1:{port}/v1", retries: 0);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            if (otp) await client.Sms.Challenge(new("token"), cts.Token);
            else await client.StartFlow(new("sign-in"), cts.Token);
            var headers = await received.WaitAsync(cts.Token);
            Assert.Contains("User-Agent: authsignal-dotnet", headers);
            if (otp)
            {
                Assert.Equal("POST /v1/client/flows/challenge/sms HTTP/1.1", headers[0]);
                Assert.Contains("X-Authsignal-Challenge-Token: token", headers);
                Assert.DoesNotContain(headers, h => h.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase));
            }
            else
            {
                Assert.Equal("POST /v1/flows HTTP/1.1", headers[0]);
                Assert.Contains("Authorization: Basic c2VjcmV0Og==", headers);
                Assert.DoesNotContain(headers, h => h.StartsWith("X-Authsignal-Challenge-Token:", StringComparison.OrdinalIgnoreCase));
            }
        }
        finally { listener.Stop(); }
    }

    [Fact]
    public async Task ExistingMethodsKeepBasicAuthAfterOtp()
    {
        var handler = new Handler();
        using var services = Services(handler);
        var client = services.GetRequiredService<IAuthsignalClient>();
        await client.Email.Challenge(new("token"));
        await client.GetUser(new("user"));
        var request = handler.Requests.Last();
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal("/v1/users/user", request.Path);
        Assert.Equal("Basic c2VjcmV0Og==", request.Auth);
        Assert.Null(request.Token);
    }

    [Fact]
    public async Task ServerErrors()
    {
        var handler = new Handler { Response = "{\"error\":\"invalid_action\"}", Status = HttpStatusCode.BadRequest };
        using var services = Services(handler);
        var client = services.GetRequiredService<IAuthsignalClient>();
        Assert.Equal("invalid_action", (await Assert.ThrowsAsync<AuthsignalException>(() => client.StartFlow(new("bad")))).Error);
        Assert.Equal("invalid_action", (await Assert.ThrowsAsync<AuthsignalException>(() => client.VerifyFlow(new("bad", "token")))).Error);
    }
}
