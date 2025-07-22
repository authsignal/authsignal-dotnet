namespace Authsignal;

public interface IAuthsignalClient
{
    public Webhook Webhook { get; }

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

    Task<ChallengeResponse> Challenge(ChallengeRequest request, CancellationToken cancellationToken = default);

    Task<VerifyResponse> Verify(VerifyRequest request, CancellationToken cancellationToken = default);

    Task<ClaimChallengeResponse> ClaimChallenge(ClaimChallengeRequest request, CancellationToken cancellationToken = default);

    Task<GetChallengeResponse> GetChallenge(GetChallengeRequest request, CancellationToken cancellationToken = default);

    Task<CreateSessionResponse> CreateSession(CreateSessionRequest request, CancellationToken cancellationToken = default);

    Task<ValidateSessionResponse> ValidateSession(ValidateSessionRequest request, CancellationToken cancellationToken = default);

    Task<RefreshSessionResponse> RefreshSession(RefreshSessionRequest request, CancellationToken cancellationToken = default);

    Task RevokeSession(RevokeSessionRequest request, CancellationToken cancellationToken = default);

    Task RevokeUserSessions(RevokeUserSessionsRequest request, CancellationToken cancellationToken = default);

}