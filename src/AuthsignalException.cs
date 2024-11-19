namespace Authsignal;

public class AuthsignalException(int statusCode, AuthsignalErrorResponse response) : Exception(message: FormatMessage(statusCode, response))
{
    public int StatusCode { get; } = statusCode;
    public string Error { get; } = response.Error;
    public string ErrorDescription { get; } = FormatDescription(response);

    private static string FormatMessage(int statusCode, AuthsignalErrorResponse response)
    {
        return $"Status {statusCode} - {FormatDescription(response)}";
    }

    private static string FormatDescription(AuthsignalErrorResponse response)
    {
        return response.ErrorDescription != null && response.ErrorDescription.Length > 0 ? response.ErrorDescription : response.Error;
    }
}