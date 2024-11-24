namespace Authsignal;

public interface IAuthsignalClient
{
    Task<GetUserResponse> GetUser(GetUserRequest request, CancellationToken cancellationToken = default);

    Task<UserAttributes> UpdateUser(UpdateUserRequest request, CancellationToken cancellationToken = default);

    Task DeleteUser(DeleteUserRequest request, CancellationToken cancellationToken = default);

    Task<UserAuthenticator[]> GetAuthenticators(GetAuthenticatorsRequest request, CancellationToken cancellationToken = default);

    Task<EnrollVerifiedAuthenticatorResponse> EnrollVerifiedAuthenticator(EnrollVerifiedAuthenticatorRequest request, CancellationToken cancellationToken = default);

    Task DeleteAuthenticator(DeleteAuthenticatorRequest request, CancellationToken cancellationToken = default);

    Task<TrackResponse> Track(TrackRequest request, CancellationToken cancellationToken = default);

    Task<ValidateChallengeResponse> ValidateChallenge(ValidateChallengeRequest request, CancellationToken cancellationToken = default);

    Task<GetActionResponse> GetAction(GetActionRequest request, CancellationToken cancellationToken = default);

    Task<ActionAttributes> UpdateAction(UpdateActionRequest request, CancellationToken cancellationToken = default);
}