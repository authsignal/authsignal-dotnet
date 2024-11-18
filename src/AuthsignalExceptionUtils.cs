using System.Text.Json;
using System.Text.Json.Serialization;

namespace Authsignal;

public static class AuthsignalExceptionUtils
{
    private static readonly JsonSerializerOptions serializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static async Task<AuthsignalException> NewResponseException(HttpResponseMessage response)
    {
        var content = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        var errorResponse = JsonSerializer.Deserialize<AuthsignalErrorResponse>(content, serializerOptions)!;

        var errorMessage = errorResponse.ErrorDescription != null && errorResponse.ErrorDescription.Length > 0
            ? errorResponse.ErrorDescription
            : errorResponse.Error;

        return new AuthsignalException((int)response.StatusCode, errorMessage);
    }
}