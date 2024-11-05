using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Authsignal;

public class AuthsignalClient : IAuthsignalClient
{
    internal const string DEFAULT_BASE_URL = "https://api.authsignal.com/v1/";

    private readonly HttpClient _httpClient;
    private readonly JsonSerializerOptions _serializeOptions;

    internal AuthsignalClient(IHttpClientFactory httpClientFactory, string secret, string? baseUrl = null)
    {
        string baseAddress = baseUrl ?? DEFAULT_BASE_URL;

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

        _httpClient.DefaultRequestHeaders.Add("Authorization", $"Basic {Base64Encode($"{secret}:")}");
    }

    public AuthsignalClient(string secret, string? baseUrl = null)
    {
        string baseAddress = baseUrl ?? DEFAULT_BASE_URL;

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

        _httpClient.DefaultRequestHeaders.Add("Authorization", $"Basic {Base64Encode($"{secret}:")}");
    }

    public async Task<UserResponse> GetUser(UserRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new HttpRequestMessage(HttpMethod.Get, $"users/{request.UserId}");

        using var response = await _httpClient
            .SendAsync(httpRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.OK)
        {
            var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            return JsonSerializer.Deserialize<UserResponse>(content, _serializeOptions)!;
        }

        var responseData = response.Content == null
            ? null
            : await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        throw new AuthsignalException((int)response.StatusCode, responseData);
    }

    public async Task<UserResponse> UpdateUser(UpdateUserRequest request, CancellationToken cancellationToken = default)
    {
        var body = new UpdateUserRequestBody(
            Email: request.Email,
            PhoneNumber: request.PhoneNumber,
            Username: request.Username,
            DisplayName: request.DisplayName,
            Custom: request.Custom);

        var httpRequest = new HttpRequestMessage(HttpMethod.Post, $"users/{request.UserId}")
        {
            Content = new StringContent(JsonSerializer.Serialize(body, _serializeOptions), Encoding.UTF8, "application/json")
        };

        using var response = await _httpClient.SendAsync(httpRequest, cancellationToken).ConfigureAwait(false);

        switch (response.StatusCode)
        {
            case HttpStatusCode.OK:
                var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                return JsonSerializer.Deserialize<UserResponse>(content, _serializeOptions)!;

            default:
                var responseData = response.Content == null
                    ? null
                    : await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                throw new AuthsignalException((int)response.StatusCode, responseData);
        }
    }

    public async Task<UserAuthenticator[]> GetAuthenticators(UserRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new HttpRequestMessage(HttpMethod.Get, $"users/{request.UserId}/authenticators");

        using var response = await _httpClient
            .SendAsync(httpRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.OK)
        {
            var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            return JsonSerializer.Deserialize<UserAuthenticator[]>(content, _serializeOptions)!;
        }

        var responseData = response.Content == null
            ? null
            : await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        throw new AuthsignalException((int)response.StatusCode, responseData);
    }

    public async Task<TrackResponse> Track(TrackRequest request, CancellationToken cancellationToken = default)
    {
        var body = new TrackRequestBody(
            Email: request.Email,
            PhoneNumber: request.PhoneNumber,
            Username: request.Username,
            IdempotencyKey: request.IdempotencyKey,
            RedirectUrl: request.RedirectUrl,
            IpAddress: request.IpAddress,
            UserAgent: request.UserAgent,
            DeviceId: request.DeviceId,
            Scope: request.Scope,
            Custom: request.Custom,
            RedirectToSettings: request.RedirectToSettings,
            ChallengeId: request.ChallengeId);

        var httpRequest = new HttpRequestMessage(HttpMethod.Post, $"users/{request.UserId}/actions/{request.Action}")
        {
            Content = new StringContent(JsonSerializer.Serialize(body, _serializeOptions), Encoding.UTF8, "application/json")
        };

        using var response = await _httpClient.SendAsync(httpRequest, cancellationToken).ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.OK)
        {
            var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            return JsonSerializer.Deserialize<TrackResponse>(content, _serializeOptions)!;
        }

        var responseData = response.Content == null
            ? null
            : await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        throw new AuthsignalException((int)response.StatusCode, responseData);
    }

    public async Task<ActionResponse?> GetAction(ActionRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new HttpRequestMessage(HttpMethod.Get, $"users/{request.UserId}/actions/{request.Action}/{request.IdempotencyKey}");

        using var response = await _httpClient
            .SendAsync(httpRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);

        switch (response.StatusCode)
        {
            case HttpStatusCode.OK:
                var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                return JsonSerializer.Deserialize<ActionResponse>(content, _serializeOptions)!;

            case HttpStatusCode.NotFound:
                return default;

            default:
                var responseData = response.Content == null
                    ? null
                    : await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                throw new AuthsignalException((int)response.StatusCode, responseData);
        }
    }

    public async Task<EnrollVerifiedAuthenticatorResponse> EnrollVerifiedAuthenticator(EnrollVerifiedAuthenticatorRequest request, CancellationToken cancellationToken = default)
    {
        var body = new EnrollVerifiedAuthenticatorRequestBody(
            request.VerificationMethod,
            Email: request.Email,
            PhoneNumber: request.PhoneNumber);

        var httpRequest = new HttpRequestMessage(HttpMethod.Post, $"users/{request.UserId}/authenticators")
        {
            Content = new StringContent(JsonSerializer.Serialize(body, _serializeOptions), Encoding.UTF8, "application/json")
        };

        using var response = await _httpClient
            .SendAsync(httpRequest, cancellationToken)
            .ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.OK)
        {
            var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            return JsonSerializer.Deserialize<EnrollVerifiedAuthenticatorResponse>(content, _serializeOptions)!;
        }

        var responseData = response.Content == null
            ? null
            : await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        throw new AuthsignalException((int)response.StatusCode, responseData);
    }

    public async Task<DeleteAuthenticatorResponse> DeleteAuthenticator(AuthenticatorRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new HttpRequestMessage(HttpMethod.Delete, $"users/{request.UserId}/authenticators/{request.UserAuthenticatorId}");

        using var response = await _httpClient.SendAsync(httpRequest, cancellationToken).ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.OK)
        {
            var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            return JsonSerializer.Deserialize<DeleteAuthenticatorResponse>(content, _serializeOptions)!;
        }

        var responseData = response.Content == null
            ? null
            : await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        throw new AuthsignalException((int)response.StatusCode, responseData);
    }

    public async Task<ValidateChallengeResponse> ValidateChallenge(ValidateChallengeRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new HttpRequestMessage(HttpMethod.Post, "validate")
        {
            Content = new StringContent(JsonSerializer.Serialize(request, _serializeOptions), Encoding.UTF8, "application/json")
        };

        using var response = await _httpClient.SendAsync(httpRequest, cancellationToken).ConfigureAwait(false);

        switch (response.StatusCode)
        {
            case HttpStatusCode.OK:
                var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                return JsonSerializer.Deserialize<ValidateChallengeResponse>(content, _serializeOptions)!;

            default:
                var responseData = response.Content == null
                    ? null
                    : await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                throw new AuthsignalException((int)response.StatusCode, responseData);
        }
    }

    private static string Base64Encode(string textToEncode)
    {
        var textAsBytes = Encoding.UTF8.GetBytes(textToEncode);
        return Convert.ToBase64String(textAsBytes);
    }
}
