using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Authsignal;

public class AuthsignalClient : IAuthsignalClient
{
    internal const string DEFAULT_BASE_ADDRESS = "https://signal.authsignal.com/v1/";

    private readonly HttpClient _httpClient;
    private readonly string? _redirectUrl;
    private readonly string _secret;
    private readonly JsonSerializerOptions _serializeOptions;

    internal AuthsignalClient(IHttpClientFactory httpClientFactory, string secret, string? redirectUrl = null,
        string? baseAddress = null)
    {
        _secret = secret;
        _redirectUrl = redirectUrl;
        _httpClient = httpClientFactory.CreateClient(nameof(AuthsignalClient));
        _httpClient.BaseAddress = new Uri(baseAddress ?? DEFAULT_BASE_ADDRESS);

        _serializeOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };
        _httpClient.DefaultRequestHeaders.Add("Authorization", $"Basic {Base64Encode($"{secret}:")}");
    }

    public AuthsignalClient(string secret, string? redirectUrl = null, string baseAddress = DEFAULT_BASE_ADDRESS)
    {
        _secret = secret;
        _redirectUrl = redirectUrl;
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
        using (var response = await _httpClient
                   .SendAsync(new HttpRequestMessage(HttpMethod.Get, $"users/{request.UserId}"),
                       HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false))
        {
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
    }

    public async Task<TrackResponse> Track(TrackRequest request, CancellationToken cancellationToken = default)
    {
        var body = new TrackRequestBody(
            request.Email,
            request.IdempotencyKey,
            request.RedirectUrl ?? _redirectUrl,
            request.IpAddress,
            request.UserAgent,
            request.DeviceId,
            request.Custom,
            RedirectToSettings: request.RedirectToSettings);

        using (var response = await _httpClient.SendAsync(
                   new HttpRequestMessage(HttpMethod.Post, $"users/{request.UserId}/actions/{request.Action}")
                   {
                       Content = new StringContent(JsonSerializer.Serialize(body, _serializeOptions), Encoding.UTF8, "application/json")
                   }, cancellationToken).ConfigureAwait(false))
        {
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
    }

    public async Task<ActionResponse?> GetAction(ActionRequest request, CancellationToken cancellationToken = default)
    {
        using var response = await _httpClient.SendAsync(
            new HttpRequestMessage(HttpMethod.Get,
                $"users/{request.UserId}/actions/{request.Action}/{request.IdempotencyKey}"),
            HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);

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

    public async Task<ValidateChallengeResponse> ValidateChallenge(ValidateChallengeRequest request, CancellationToken cancellationToken = default)
    {
        var jwtToken = ValidateToken(request.Token, _secret);

        var userId = jwtToken.Subject;
        var json = jwtToken.Claims.First(x => x.Type == "other").Value;
        var other = JsonSerializer.Deserialize<JwtOtherData>(json, _serializeOptions);
        var idempotencyKey = other?.IdempotencyKey;
        var actionCode = other?.ActionCode;

        if (userId == null || idempotencyKey == null || actionCode == null) throw new Exception("Invalid token");

        if (request.UserId != userId) throw new Exception("Invalid user");

        var action = await GetAction(new ActionRequest(userId, actionCode, idempotencyKey), cancellationToken).ConfigureAwait(false);

        var success = action?.State == UserActionState.CHALLENGE_SUCCEEDED;

        return new ValidateChallengeResponse(success, action?.State);
    }

    public async Task<AuthenticatorResponse> EnrollVerifiedAuthenticator(AuthenticatorRequest request,
        CancellationToken cancellationToken = default)
    {
        var body = new AuthenticatorRequestBody(
            request.OobChannel,
            Email: request.Email,
            PhoneNumber: request.PhoneNumber);

        using var response = await _httpClient.SendAsync(
            new HttpRequestMessage(HttpMethod.Post, $"users/{request.UserId}/authenticators")
            {
                Content = new StringContent(JsonSerializer.Serialize(body, _serializeOptions), Encoding.UTF8, "application/json")
            }, cancellationToken).ConfigureAwait(false);

        if (response.StatusCode == HttpStatusCode.OK)
        {
            var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            return JsonSerializer.Deserialize<AuthenticatorResponse>(content, _serializeOptions)!;
        }

        var responseData = response.Content == null
            ? null
            : await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        throw new AuthsignalException((int)response.StatusCode, responseData);
    }

    private static string Base64Encode(string textToEncode)
    {
        var textAsBytes = Encoding.UTF8.GetBytes(textToEncode);
        return Convert.ToBase64String(textAsBytes);
    }

    private static JwtSecurityToken ValidateToken(string token, string secret)
    {
        var tokenHandler = new JwtSecurityTokenHandler();

        var hmac = new HMACSHA256(Encoding.ASCII.GetBytes(secret));
        var securityKey = new SymmetricSecurityKey(hmac.Key);

        tokenHandler.ValidateToken(token, new TokenValidationParameters
        {
            IssuerSigningKey = securityKey,
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true
        }, out var validatedToken);

        var jwtToken = (JwtSecurityToken)validatedToken;

        return jwtToken;
    }
}