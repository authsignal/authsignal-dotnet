namespace Authsignal;

public class AuthsignalFlowsEmail
{
    private readonly AuthsignalClient _client;

    internal AuthsignalFlowsEmail(AuthsignalClient client) => _client = client;

    public Task<OtpChallengeResponse> Challenge(EmailChallengeRequest request, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(request.ChallengeToken))
        {
            throw new ArgumentException("ChallengeToken is required.", nameof(request));
        }

        return _client.PostFlow<OtpChallengeResponse>("client/flows/challenge/email-otp",
            new { request.Email }, request.ChallengeToken, cancellationToken);
    }

    /// <exception cref="InvalidCodeException">The verification code did not match.</exception>
    public Task<OtpVerifyResponse> Verify(OtpVerifyRequest request, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(request.ChallengeToken))
        {
            throw new ArgumentException("ChallengeToken is required.", nameof(request));
        }

        return _client.PostFlow<OtpVerifyResponse>("client/flows/verify/email-otp",
            new { request.VerificationCode }, request.ChallengeToken, cancellationToken);
    }
}
