namespace Authsignal;

public class InvalidCodeException(int statusCode, AuthsignalErrorResponse response)
    : AuthsignalException(statusCode, response);
