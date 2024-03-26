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
    internal const string DEFAULT_BASE_ADDRESS = "https://api.authsignal.com/v1/";
    internal const int DEFAULT_JWKS_CACHE_EXPIRY = 10;

    private readonly string _tenantId;
    private readonly string _secret;
    private readonly string _baseAddress;
    private readonly string? _redirectUrl;

    private readonly HttpClient _httpClient;
    private readonly JsonSerializerOptions _serializeOptions;

    private JsonWebKeySet? _jwks;
    private DateTime _lastJwksRequest;
    private readonly int _jwksCacheExpiry;

    internal AuthsignalClient(
      IHttpClientFactory httpClientFactory,
      string tenantId,
      string secret,
      string baseAddress = DEFAULT_BASE_ADDRESS,
      string? redirectUrl = null,
      int jwksCacheExpiry = DEFAULT_JWKS_CACHE_EXPIRY
      )
    {
        _tenantId = tenantId;
        _secret = secret;
        _redirectUrl = redirectUrl;
        _jwksCacheExpiry = jwksCacheExpiry;

        if (!baseAddress.EndsWith("/"))
        {
            baseAddress += "/";
        }

        _baseAddress = baseAddress;

        _httpClient = httpClientFactory.CreateClient(nameof(AuthsignalClient));
        _httpClient.BaseAddress = new Uri(_baseAddress);

        _serializeOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        _httpClient.DefaultRequestHeaders.Add("Authorization", $"Basic {Base64Encode($"{secret}:")}");
    }

    public AuthsignalClient(
      string tenantId,
      string secret,
      string baseAddress = DEFAULT_BASE_ADDRESS,
      string? redirectUrl = null,
      int jwksCacheExpiry = DEFAULT_JWKS_CACHE_EXPIRY)
    {
        _tenantId = tenantId;
        _secret = secret;
        _redirectUrl = redirectUrl;
        _jwksCacheExpiry = jwksCacheExpiry;

        if (!baseAddress.EndsWith("/"))
        {
            baseAddress += "/";
        }

        _baseAddress = baseAddress;

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
        using var response = await _httpClient
                   .SendAsync(new HttpRequestMessage(HttpMethod.Get, $"users/{request.UserId}"),
                       HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);

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

    public async Task<TrackResponse> Track(TrackRequest request, CancellationToken cancellationToken = default)
    {
        var body = new TrackRequestBody(
            Email: request.Email,
            PhoneNumber: request.PhoneNumber,
            Username: request.Username,
            IdempotencyKey: request.IdempotencyKey,
            RedirectUrl: request.RedirectUrl ?? _redirectUrl,
            IpAddress: request.IpAddress,
            UserAgent: request.UserAgent,
            DeviceId: request.DeviceId,
            Scope: request.Scope,
            Custom: request.Custom,
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
        var jwtToken = await ValidateToken(request.Token, _secret);

        var userId = jwtToken.Subject;
        var json = jwtToken.Claims.First(x => x.Type == "other").Value;
        var other = JsonSerializer.Deserialize<JwtOtherData>(json, _serializeOptions);
        var idempotencyKey = other?.IdempotencyKey;
        var actionCode = other?.ActionCode;

        if (userId == null || idempotencyKey == null || actionCode == null) throw new Exception("Invalid token");

        if (request.UserId != null && request.UserId != userId) throw new Exception("Invalid user");
        var action = await GetAction(new ActionRequest(userId, actionCode, idempotencyKey), cancellationToken).ConfigureAwait(false);

        var success = action?.State == UserActionState.CHALLENGE_SUCCEEDED;

        return new ValidateChallengeResponse(success, action?.State, userId);
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

    private async Task<JwtSecurityToken> ValidateToken(string token, string secret)
    {
        var tokenHandler = new JwtSecurityTokenHandler();

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
        };

        var tokenHeader = tokenHandler.ReadJwtToken(token).Header;

        if (tokenHeader.Alg == "RS256")
        {
            if (_jwks == null || _lastJwksRequest.AddMinutes(_jwksCacheExpiry) < DateTime.Now)
            {
                var jwksUriPath = $"client/public/{_tenantId}/.well-known/jwks";
                var request = new HttpRequestMessage(HttpMethod.Get, jwksUriPath);

                using var response = await _httpClient
                       .SendAsync(request, HttpCompletionOption.ResponseHeadersRead)
                       .ConfigureAwait(false);

                var responseString = await response.Content.ReadAsStringAsync();

                _jwks = new JsonWebKeySet(responseString);
                _lastJwksRequest = DateTime.Now;
            }

            validationParameters.IssuerSigningKeys = _jwks.Keys;
        }
        else
        {
            var hmac = new HMACSHA256(Encoding.ASCII.GetBytes(secret));
            var securityKey = new SymmetricSecurityKey(hmac.Key);

            validationParameters.IssuerSigningKey = securityKey;
        }

        tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

        var jwtToken = (JwtSecurityToken)validatedToken;

        return jwtToken;
    }
}
