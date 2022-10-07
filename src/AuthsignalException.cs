namespace Authsignal;

public sealed class AuthsignalException : Exception
{
    public AuthsignalException(int statusCode, string? message) : base($"Unexpected response {statusCode}: {message}")
    {
    }
}