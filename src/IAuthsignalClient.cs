namespace Authsignal;

public interface IAuthsignalClient
{
    Task<UserResponse> GetUser(UserRequest request, CancellationToken cancellationToken = default);

    Task<UpdateUserResponse> UpdateUser(UpdateUserRequest request, CancellationToken cancellationToken = default);

    Task DeleteUser(UserRequest request, CancellationToken cancellationToken = default);

    Task<UserAuthenticator[]> GetAuthenticators(UserRequest request, CancellationToken cancellationToken = default);

    Task<EnrollVerifiedAuthenticatorResponse> EnrollVerifiedAuthenticator(EnrollVerifiedAuthenticatorRequest request, CancellationToken cancellationToken = default);

    Task DeleteAuthenticator(AuthenticatorRequest request, CancellationToken cancellationToken = default);

    Task<TrackResponse> Track(TrackRequest request, CancellationToken cancellationToken = default);

    Task<ValidateChallengeResponse> ValidateChallenge(ValidateChallengeRequest request, CancellationToken cancellationToken = default);

    Task<ActionResponse?> GetAction(ActionRequest request, CancellationToken cancellationToken = default);

    Task<ActionResponse> UpdateActionState(UpdateActionStateRequest request, CancellationToken cancellationToken = default);
}