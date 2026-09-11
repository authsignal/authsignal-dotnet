namespace Authsignal;

public class AuthsignalFlowsSms
{
    private readonly AuthsignalClient _client;

    internal AuthsignalFlowsSms(AuthsignalClient client) => _client = client;

    public Task<OtpChallengeResponse> Challenge(SmsChallengeRequest request, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(request.ChallengeToken))
        {
            throw new ArgumentException("ChallengeToken is required.", nameof(request));
        }

        return _client.PostFlow<OtpChallengeResponse>("client/flows/challenge/sms",
            new { request.PhoneNumber }, request.ChallengeToken, cancellationToken);
    }

    /// <exception cref="InvalidCodeException">The verification code did not match.</exception>
    public Task<OtpVerifyResponse> Verify(OtpVerifyRequest request, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(request.ChallengeToken))
        {
            throw new ArgumentException("ChallengeToken is required.", nameof(request));
        }

        return _client.PostFlow<OtpVerifyResponse>("client/flows/verify/sms",
            new { request.VerificationCode }, request.ChallengeToken, cancellationToken);
    }
}
