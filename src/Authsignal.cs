using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Authsignal;

public class AuthsignalClient : IAuthsignalClient
{
    internal const string DEFAULT_API_URL = "https://api.authsignal.com/v1/";

    private readonly HttpClient _httpClient;
    private readonly JsonSerializerOptions _serializeOptions;

    internal AuthsignalClient(IHttpClientFactory httpClientFactory, string apiSecretKey, string? apiUrl = null)
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
    }

    public AuthsignalClient(string apiSecretKey, string? apiUrl = null)
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
    }

    public async Task<GetUserResponse> GetUser(GetUserRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new HttpRequestMessage(HttpMethod.Get, $"users/{request.UserId}");

        using var response = await _httpClient
            .SendAsync(httpRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);

        if (response.IsSuccessStatusCode)
        {
            var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            return JsonSerializer.Deserialize<GetUserResponse>(content, _serializeOptions)!;
        }

        throw await AuthsignalExceptionUtils.NewResponseException(response);
    }

    public async Task<UserAttributes> UpdateUser(UpdateUserRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new HttpRequestMessage(new HttpMethod("PATCH"), $"users/{request.UserId}")
        {
            Content = new StringContent(JsonSerializer.Serialize(request.Attributes, _serializeOptions), Encoding.UTF8, "application/json")
        };

        using var response = await _httpClient.SendAsync(httpRequest, cancellationToken).ConfigureAwait(false);

        switch (response.StatusCode)
        {
            case HttpStatusCode.OK:
                var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                return JsonSerializer.Deserialize<UserAttributes>(content, _serializeOptions)!;

            default:
                throw await AuthsignalExceptionUtils.NewResponseException(response);
        }
    }

    public async Task DeleteUser(DeleteUserRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new HttpRequestMessage(HttpMethod.Delete, $"users/{request.UserId}");

        using var response = await _httpClient.SendAsync(httpRequest, cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            throw await AuthsignalExceptionUtils.NewResponseException(response);
        }
    }

    public async Task<UserAuthenticator[]> GetAuthenticators(GetAuthenticatorsRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new HttpRequestMessage(HttpMethod.Get, $"users/{request.UserId}/authenticators");

        using var response = await _httpClient
            .SendAsync(httpRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);

        if (response.IsSuccessStatusCode)
        {
            var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            return JsonSerializer.Deserialize<UserAuthenticator[]>(content, _serializeOptions)!;
        }

        throw await AuthsignalExceptionUtils.NewResponseException(response);
    }

    public async Task<EnrollVerifiedAuthenticatorResponse> EnrollVerifiedAuthenticator(EnrollVerifiedAuthenticatorRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new HttpRequestMessage(HttpMethod.Post, $"users/{request.UserId}/authenticators")
        {
            Content = new StringContent(JsonSerializer.Serialize(request.Attributes, _serializeOptions), Encoding.UTF8, "application/json")
        };

        using var response = await _httpClient
            .SendAsync(httpRequest, cancellationToken)
            .ConfigureAwait(false);

        if (response.IsSuccessStatusCode)
        {
            var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            return JsonSerializer.Deserialize<EnrollVerifiedAuthenticatorResponse>(content, _serializeOptions)!;
        }

        throw await AuthsignalExceptionUtils.NewResponseException(response);
    }

    public async Task DeleteAuthenticator(DeleteAuthenticatorRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new HttpRequestMessage(HttpMethod.Delete, $"users/{request.UserId}/authenticators/{request.UserAuthenticatorId}");

        using var response = await _httpClient.SendAsync(httpRequest, cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            throw await AuthsignalExceptionUtils.NewResponseException(response);
        }
    }

    public async Task<TrackResponse> Track(TrackRequest request, CancellationToken cancellationToken = default)
    {
        var body = request.Attributes ?? new TrackAttributes();

        var httpRequest = new HttpRequestMessage(HttpMethod.Post, $"users/{request.UserId}/actions/{request.Action}")
        {
            Content = new StringContent(JsonSerializer.Serialize(body, _serializeOptions), Encoding.UTF8, "application/json")
        };

        using var response = await _httpClient.SendAsync(httpRequest, cancellationToken).ConfigureAwait(false);

        if (response.IsSuccessStatusCode)
        {
            var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            return JsonSerializer.Deserialize<TrackResponse>(content, _serializeOptions)!;
        }

        throw await AuthsignalExceptionUtils.NewResponseException(response);
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
                throw await AuthsignalExceptionUtils.NewResponseException(response);
        }
    }

    public async Task<GetActionResponse> GetAction(GetActionRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new HttpRequestMessage(HttpMethod.Get, $"users/{request.UserId}/actions/{request.Action}/{request.IdempotencyKey}");

        using var response = await _httpClient
            .SendAsync(httpRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);

        switch (response.StatusCode)
        {
            case HttpStatusCode.OK:
                var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                return JsonSerializer.Deserialize<GetActionResponse>(content, _serializeOptions)!;

            default:
                throw await AuthsignalExceptionUtils.NewResponseException(response);
        }
    }

    public async Task<ActionAttributes> UpdateAction(UpdateActionRequest request, CancellationToken cancellationToken = default)
    {
        var httpRequest = new HttpRequestMessage(new HttpMethod("PATCH"), $"users/{request.UserId}/actions/{request.Action}/{request.IdempotencyKey}")
        {
            Content = new StringContent(JsonSerializer.Serialize(request.Attributes, _serializeOptions), Encoding.UTF8, "application/json")
        };

        using var response = await _httpClient.SendAsync(httpRequest, cancellationToken).ConfigureAwait(false);

        switch (response.StatusCode)
        {
            case HttpStatusCode.OK:
                var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                return JsonSerializer.Deserialize<ActionAttributes>(content, _serializeOptions)!;

            default:
                throw await AuthsignalExceptionUtils.NewResponseException(response);
        }
    }

    private static string Base64Encode(string textToEncode)
    {
        var textAsBytes = Encoding.UTF8.GetBytes(textToEncode);
        return Convert.ToBase64String(textAsBytes);
    }
}
