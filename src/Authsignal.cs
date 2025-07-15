using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Authsignal;

public class AuthsignalClient : IAuthsignalClient
{
    internal const string DEFAULT_API_URL = "https://api.authsignal.com/v1/";
    internal const int DEFAULT_RETRIES = 2;
    internal string[] SAFE_HTTP_METHODS = ["GET", "HEAD", "OPTIONS"];

    private readonly HttpClient _httpClient;
    private readonly JsonSerializerOptions _serializeOptions;
    private readonly int _retries;
    private readonly Webhook _webhook;

    public Webhook Webhook { get => _webhook; }

    private static readonly string _version = "3.5.0";

    internal AuthsignalClient(IHttpClientFactory httpClientFactory, string apiSecretKey, string? apiUrl = null, int? retries = null)
    {
        string baseAddress = apiUrl ?? DEFAULT_API_URL;

        if (!baseAddress.EndsWith("/"))
        {
            baseAddress += "/";
        }

        _httpClient = httpClientFactory.CreateClient(nameof(AuthsignalClient));

        _httpClient.BaseAddress = new Uri(baseAddress);

        _serializeOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        _httpClient.DefaultRequestHeaders.Add("Authorization", $"Basic {Base64Encode($"{apiSecretKey}:")}");

        _httpClient.DefaultRequestHeaders.Add("X-Authsignal-Version", _version);

        _httpClient.DefaultRequestHeaders.Add("User-Agent", "authsignal-dotnet");

        _retries = retries ?? DEFAULT_RETRIES;

        _webhook = new Webhook(apiSecretKey);
    }

    public AuthsignalClient(string apiSecretKey, string? apiUrl = null, int? retries = null)
    {
        string baseAddress = apiUrl ?? DEFAULT_API_URL;

        if (!baseAddress.EndsWith("/"))
        {
            baseAddress += "/";
        }

        _httpClient = new HttpClient
        {
            BaseAddress = new Uri(baseAddress)
        };

        _serializeOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        _httpClient.DefaultRequestHeaders.Add("Authorization", $"Basic {Base64Encode($"{apiSecretKey}:")}");

        _httpClient.DefaultRequestHeaders.Add("X-Authsignal-Version", _version);

        _retries = retries ?? DEFAULT_RETRIES;

        _webhook = new Webhook(apiSecretKey);
    }

    public async Task<GetUserResponse> GetUser(GetUserRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new AuthsignalHttpRequest(HttpMethod.Get, $"users/{request.UserId}");

        using var response = await SendHttpRequest(httpRequest, cancellationToken);

        var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        return JsonSerializer.Deserialize<GetUserResponse>(content, _serializeOptions)!;
    }

    public async Task<UserAttributes> UpdateUser(UpdateUserRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new AuthsignalHttpRequest(new HttpMethod("PATCH"), $"users/{request.UserId}")
        {
            Content = new StringContent(JsonSerializer.Serialize(request.Attributes, _serializeOptions), Encoding.UTF8, "application/json")
        };

        using var response = await SendHttpRequest(httpRequest, cancellationToken);

        var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        return JsonSerializer.Deserialize<UserAttributes>(content, _serializeOptions)!;
    }

    public async Task DeleteUser(DeleteUserRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new AuthsignalHttpRequest(HttpMethod.Delete, $"users/{request.UserId}");

        await SendHttpRequest(httpRequest, cancellationToken);
    }

    public async Task<UserAuthenticator[]> GetAuthenticators(GetAuthenticatorsRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new AuthsignalHttpRequest(HttpMethod.Get, $"users/{request.UserId}/authenticators");

        using var response = await SendHttpRequest(httpRequest, cancellationToken);

        var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        return JsonSerializer.Deserialize<UserAuthenticator[]>(content, _serializeOptions)!;
    }

    public async Task<EnrollVerifiedAuthenticatorResponse> EnrollVerifiedAuthenticator(EnrollVerifiedAuthenticatorRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new AuthsignalHttpRequest(HttpMethod.Post, $"users/{request.UserId}/authenticators")
        {
            Content = new StringContent(JsonSerializer.Serialize(request.Attributes, _serializeOptions), Encoding.UTF8, "application/json")
        };

        using var response = await SendHttpRequest(httpRequest, cancellationToken);

        var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        return JsonSerializer.Deserialize<EnrollVerifiedAuthenticatorResponse>(content, _serializeOptions)!;
    }

    public async Task DeleteAuthenticator(DeleteAuthenticatorRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new AuthsignalHttpRequest(HttpMethod.Delete, $"users/{request.UserId}/authenticators/{request.UserAuthenticatorId}");

        await SendHttpRequest(httpRequest, cancellationToken);
    }

    public async Task<TrackResponse> Track(TrackRequest request, CancellationToken cancellationToken = default)
    {
        var body = request.Attributes ?? new TrackAttributes();

        var httpRequest = new AuthsignalHttpRequest(HttpMethod.Post, $"users/{request.UserId}/actions/{request.Action}")
        {
            Content = new StringContent(JsonSerializer.Serialize(body, _serializeOptions), Encoding.UTF8, "application/json")
        };

        using var response = await SendHttpRequest(httpRequest, cancellationToken);

        var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        return JsonSerializer.Deserialize<TrackResponse>(content, _serializeOptions)!;
    }

    public async Task<ValidateChallengeResponse> ValidateChallenge(ValidateChallengeRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new AuthsignalHttpRequest(HttpMethod.Post, "validate")
        {
            Content = new StringContent(JsonSerializer.Serialize(request, _serializeOptions), Encoding.UTF8, "application/json")
        };

        using var response = await SendHttpRequest(httpRequest, cancellationToken);

        var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        return JsonSerializer.Deserialize<ValidateChallengeResponse>(content, _serializeOptions)!;
    }

    public async Task<GetActionResponse> GetAction(GetActionRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new AuthsignalHttpRequest(HttpMethod.Get, $"users/{request.UserId}/actions/{request.Action}/{request.IdempotencyKey}");

        using var response = await SendHttpRequest(httpRequest, cancellationToken);

        var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        return JsonSerializer.Deserialize<GetActionResponse>(content, _serializeOptions)!;
    }

    public async Task<ActionAttributes> UpdateAction(UpdateActionRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new AuthsignalHttpRequest(new HttpMethod("PATCH"), $"users/{request.UserId}/actions/{request.Action}/{request.IdempotencyKey}")
        {
            Content = new StringContent(JsonSerializer.Serialize(request.Attributes, _serializeOptions), Encoding.UTF8, "application/json")
        };

        using var response = await SendHttpRequest(httpRequest, cancellationToken);

        var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        return JsonSerializer.Deserialize<ActionAttributes>(content, _serializeOptions)!;
    }

    public async Task<ChallengeResponse> Challenge(ChallengeRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new AuthsignalHttpRequest(HttpMethod.Post, "challenge")
        {
            Content = new StringContent(JsonSerializer.Serialize(request, _serializeOptions), Encoding.UTF8, "application/json")
        };

        using var response = await SendHttpRequest(httpRequest, cancellationToken);

        var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        return JsonSerializer.Deserialize<ChallengeResponse>(content, _serializeOptions)!;
    }

    public async Task<VerifyResponse> Verify(VerifyRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new AuthsignalHttpRequest(HttpMethod.Post, "verify")
        {
            Content = new StringContent(JsonSerializer.Serialize(request, _serializeOptions), Encoding.UTF8, "application/json")
        };

        using var response = await SendHttpRequest(httpRequest, cancellationToken);

        var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        return JsonSerializer.Deserialize<VerifyResponse>(content, _serializeOptions)!;
    }

    public async Task<ClaimChallengeResponse> ClaimChallenge(ClaimChallengeRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new AuthsignalHttpRequest(HttpMethod.Post, "claim")
        {
            Content = new StringContent(JsonSerializer.Serialize(request, _serializeOptions), Encoding.UTF8, "application/json")
        };

        using var response = await SendHttpRequest(httpRequest, cancellationToken);

        var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        return JsonSerializer.Deserialize<ClaimChallengeResponse>(content, _serializeOptions)!;
    }

    public async Task<GetChallengeResponse> GetChallenge(GetChallengeRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new AuthsignalHttpRequest(HttpMethod.Post, "challenges")
        {
            Content = new StringContent(JsonSerializer.Serialize(request, _serializeOptions), Encoding.UTF8, "application/json"),
            QueryParams = []
        };

        if (request.ChallengeId != null)
        {
            httpRequest.QueryParams.Add("challengeId", request.ChallengeId);
        }

        if (request.UserId != null)
        {
            httpRequest.QueryParams.Add("userId", request.UserId);
        }

        if (request.Action != null)
        {
            httpRequest.QueryParams.Add("action", request.Action);
        }

        if (request.VerificationMethod != null)
        {
            httpRequest.QueryParams.Add("verificationMethod", request.VerificationMethod);
        }

        using var response = await SendHttpRequest(httpRequest, cancellationToken);

        var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        return JsonSerializer.Deserialize<GetChallengeResponse>(content, _serializeOptions)!;
    }

    public async Task<CreateSessionResponse> CreateSession(CreateSessionRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new AuthsignalHttpRequest(HttpMethod.Post, "sessions")
        {
            Content = new StringContent(JsonSerializer.Serialize(request, _serializeOptions), Encoding.UTF8, "application/json")
        };

        using var response = await SendHttpRequest(httpRequest, cancellationToken);

        var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        return JsonSerializer.Deserialize<CreateSessionResponse>(content, _serializeOptions)!;
    }

    public async Task<ValidateSessionResponse> ValidateSession(ValidateSessionRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new AuthsignalHttpRequest(HttpMethod.Post, "sessions/validate")
        {
            Content = new StringContent(JsonSerializer.Serialize(request, _serializeOptions), Encoding.UTF8, "application/json")
        };

        using var response = await SendHttpRequest(httpRequest, cancellationToken);

        var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        return JsonSerializer.Deserialize<ValidateSessionResponse>(content, _serializeOptions)!;
    }

    public async Task<RefreshSessionResponse> RefreshSession(RefreshSessionRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new AuthsignalHttpRequest(HttpMethod.Post, "sessions/refresh")
        {
            Content = new StringContent(JsonSerializer.Serialize(request, _serializeOptions), Encoding.UTF8, "application/json")
        };

        using var response = await SendHttpRequest(httpRequest, cancellationToken);

        var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        return JsonSerializer.Deserialize<RefreshSessionResponse>(content, _serializeOptions)!;
    }

    public async Task RevokeSession(RevokeSessionRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new AuthsignalHttpRequest(HttpMethod.Post, "sessions/revoke")
        {
            Content = new StringContent(JsonSerializer.Serialize(request, _serializeOptions), Encoding.UTF8, "application/json")
        };

        using var response = await SendHttpRequest(httpRequest, cancellationToken);

        await response.Content.ReadAsStringAsync().ConfigureAwait(false);
    }

    public async Task RevokeUserSessions(RevokeUserSessionsRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new AuthsignalHttpRequest(HttpMethod.Post, "sessions/user/revoke")
        {
            Content = new StringContent(JsonSerializer.Serialize(request, _serializeOptions), Encoding.UTF8, "application/json")
        };

        using var response = await SendHttpRequest(httpRequest, cancellationToken);

        await response.Content.ReadAsStringAsync().ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendHttpRequest(AuthsignalHttpRequest request, CancellationToken cancellationToken)
    {
        Exception? requestException;
        HttpResponseMessage? response = null;
        int retryCount = 0;

        while (true)
        {
            var httpRequestMessage = BuildHttpRequestMessage(request);

            requestException = null;

            try
            {
                response = await _httpClient.SendAsync(httpRequestMessage, cancellationToken).ConfigureAwait(false);
            }
            catch (HttpRequestException exception)
            {
                requestException = exception;
            }
            catch (OperationCanceledException exception)
                when (!cancellationToken.IsCancellationRequested)
            {
                requestException = exception;
            }

            if (!ShouldRetry(retryCount, requestException, response?.StatusCode, httpRequestMessage.Method))
            {
                break;
            }

            retryCount++;

            await Task.Delay(SleepTime(retryCount)).ConfigureAwait(false);
        }


        if (requestException != null)
        {
            throw requestException;
        }

        if (response == null)
        {
            throw new Exception("No response received.");
        }

        if (!response.IsSuccessStatusCode)
        {
            throw await AuthsignalExceptionUtils.NewResponseException(response);
        }

        return response;
    }

    private bool ShouldRetry(
            int retryCount,
            Exception? requestException,
            HttpStatusCode? statusCode,
            HttpMethod? httpMethod)
    {
        if (retryCount >= _retries)
        {
            return false;
        }

        // Retry on connection error
        if (requestException != null)
        {
            return true;
        }

        if (statusCode.HasValue && ((int)statusCode.Value >= 500))
        {
            if (httpMethod != null && SAFE_HTTP_METHODS.Any(m => m == httpMethod.Method))
            {
                return true;
            }
        }

        return false;
    }

    private static TimeSpan SleepTime(int retryCount)
    {
        long interval = 100;

        var delay = TimeSpan.FromMilliseconds((long)(interval * Math.Pow(2, retryCount - 1)));

        return delay;
    }

    private static HttpRequestMessage BuildHttpRequestMessage(AuthsignalHttpRequest request)
    {
        var httpRequestMessage = new HttpRequestMessage(request.HttpMethod, request.Path);

        if (request.Content != null)
        {
            httpRequestMessage.Content = request.Content;
        }

        if (request.QueryParams != null && request.QueryParams.Count > 0)
        {
            var uriBuilder = new UriBuilder(httpRequestMessage.RequestUri!);
            var query = System.Web.HttpUtility.ParseQueryString(uriBuilder.Query);

            foreach (var kvp in request.QueryParams)
            {
                query[kvp.Key] = kvp.Value;
            }

            uriBuilder.Query = query.ToString();
            httpRequestMessage.RequestUri = uriBuilder.Uri;
        }

        return httpRequestMessage;
    }

    private static string Base64Encode(string textToEncode)
    {
        var textAsBytes = Encoding.UTF8.GetBytes(textToEncode);
        return Convert.ToBase64String(textAsBytes);
    }
}
