namespace Authsignal
{
  using System.Net;
  using System.Net.Http.Json;
  using System.Text;
  using System.Text.Json;
  using System.Text.Json.Serialization;

  public class AuthsignalClient
  {
    private const string DEFAULT_BASE_ADDRESS = "https://signal.authsignal.com/v1/";

    private static JsonSerializerOptions serializeOptions = new JsonSerializerOptions
    {
      PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
      DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    HttpClient _httpClient;
    string? _redirectUrl;

    public AuthsignalClient(string secret, string? redirectUrl = null, string baseAddress = DEFAULT_BASE_ADDRESS)
    {
      _redirectUrl = redirectUrl;

      _httpClient = new HttpClient()
      {
        BaseAddress = new Uri(baseAddress)
      };

      _httpClient.DefaultRequestHeaders.Add("Authorization", $"Basic {Base64Encode($"{secret}:")}");
    }

    public async Task<UserResponse?> GetUser(UserRequest request)
    {
      var path = $"users/{request.UserId}";

      var userResponse = await _httpClient.GetFromJsonAsync<UserResponse>(path);

      return userResponse!;
    }

    public async Task<TrackResponse> Track(TrackRequest request)
    {
      var path = $"users/{request.UserId}/actions/{request.Action}";

      var body = new TrackRequestBody
      {
        Email = request.Email,
        IdempotencyKey = request.IdempotencyKey,
        RedirectUrl = request.RedirectUrl,
        IpAddress = request.IpAddress,
        UserAgent = request.UserAgent,
        DeviceId = request.DeviceId,
        RedirectToSettings = request.RedirectToSettings
      };

      var response = await _httpClient.PostAsJsonAsync(path, body, serializeOptions);


      var trackResponse = await response.Content.ReadFromJsonAsync<TrackResponse>();

      return trackResponse!;
    }

    public async Task<ActionResponse?> GetAction(ActionRequest request)
    {
      try
      {
        var path = $"users/{request.UserId}/actions/{request.Action}/{request.IdempotencyKey}";

        var actionResponse = await _httpClient.GetFromJsonAsync<ActionResponse>(path);

        return actionResponse;
      }
      catch (HttpRequestException ex)
      {
        if (ex.StatusCode == HttpStatusCode.NotFound)
        {
          return null;
        }

        throw ex;
      }
    }

    public async Task<AuthenticatorResponse> EnrollVerifiedAuthenticator(AuthenticatorRequest request)
    {
      var path = $"users/{request.UserId}/authenticators";

      var body = new AuthenticatorRequestBody(
        OobChannel: request.OobChannel,
        Email: request.Email,
        PhoneNumber: request.PhoneNumber
        );

      var response = await _httpClient.PostAsJsonAsync(path, body, serializeOptions);

      var authenticatorResponse = await response.Content.ReadFromJsonAsync<AuthenticatorResponse>();

      return authenticatorResponse!;
    }

    public async Task<EmailResponse> LoginWithEmail(EmailRequest request)
    {
      var path = $"users/email/{request.Email}/challenge";

      var body = new EmailRequestBody(
        RedirectUrl: request.RedirectUrl
        );

      var response = await _httpClient.PostAsJsonAsync(path, body, serializeOptions);

      var emailResponse = await response.Content.ReadFromJsonAsync<EmailResponse>();

      return emailResponse!;
    }

    private static string Base64Encode(string textToEncode)
    {
      byte[] textAsBytes = Encoding.UTF8.GetBytes(textToEncode);
      return Convert.ToBase64String(textAsBytes);
    }
  }
}
