namespace Authsignal;

public interface IAuthsignalClient
{
    Task<UserResponse> GetUser(UserRequest request, CancellationToken cancellationToken = default);

    Task<TrackResponse> Track(TrackRequest request, CancellationToken cancellationToken = default);

    Task<ActionResponse?> GetAction(ActionRequest request, CancellationToken cancellationToken = default);

    Task<ValidateChallengeResponse> ValidateChallenge(ValidateChallengeRequest request, CancellationToken cancellationToken = default);

    Task<AuthenticatorResponse> EnrollVerifiedAuthenticator(AuthenticatorRequest request,
        CancellationToken cancellationToken = default);
}