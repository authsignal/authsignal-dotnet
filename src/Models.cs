using System.Text.Json.Serialization;

namespace Authsignal;

public record class UserRequest(
    string UserId
);

public record class UserResponse(
    bool IsEnrolled,
    string? Email = null,
    string? PhoneNumber = null,
    string? Username = null,
    string? DisplayName = null,
    VerificationMethod[]? EnrolledVerificationMethods = null,
    VerificationMethod[]? AllowedVerificationMethods = null,
    Dictionary<string, string>? Custom = null
);

public record class UpdateUserRequest(
    string UserId,
    string? Email = null,
    string? PhoneNumber = null,
    string? Username = null,
    string? DisplayName = null,
    Dictionary<string, string>? Custom = null
);

public record class UpdateUserRequestBody(
    string? Email = null,
    string? PhoneNumber = null,
    string? Username = null,
    string? DisplayName = null,
    Dictionary<string, string>? Custom = null
);

public record class TrackRequest(
    string UserId,
    string Action,
    string? Email = null,
    string? PhoneNumber = null,
    string? Username = null,
    string? IdempotencyKey = null,
    string? RedirectUrl = null,
    string? IpAddress = null,
    string? UserAgent = null,
    string? DeviceId = null,
    string? Scope = null,
    Dictionary<string, string>? Custom = null,
    bool? RedirectToSettings = false,
    string? ChallengeId = null
);

public record class TrackRequestBody(
    string? Email = null,
    string? PhoneNumber = null,
    string? Username = null,
    string? IdempotencyKey = null,
    string? RedirectUrl = null,
    string? IpAddress = null,
    string? UserAgent = null,
    string? DeviceId = null,
    string? Scope = null,
    Dictionary<string, string>? Custom = null,
    bool? RedirectToSettings = false,
    string? ChallengeId = null
);

public record class TrackResponse(
    UserActionState State,
    string IdempotencyKey,
    string Url,
    string Token,
    bool IsEnrolled,
    VerificationMethod[] EnrolledVerificationMethods,
    VerificationMethod[] AllowedVerificationMethods
);

public record class ActionRequest(
    string UserId,
    string Action,
    string IdempotencyKey
);

public record class ActionResponse(
    UserActionState State,
    VerificationMethod VerificationMethod
);

public record class ValidateChallengeRequest(
    string Token,
    string? UserId = null
);

public record class ValidateChallengeResponse(
    bool IsValid,
    UserActionState State,
    string? StateUpdatedAt,
    string? UserId,
    [property: JsonPropertyName("actionCode")] string? Action,
    string? IdempotencyKey,
    VerificationMethod? VerificationMethod
);

public record class EnrollVerifiedAuthenticatorRequest(
    string UserId,
    VerificationMethod VerificationMethod,
    string? PhoneNumber = null,
    string? Email = null
);

public record class EnrollVerifiedAuthenticatorRequestBody(
   VerificationMethod VerificationMethod,
    string? PhoneNumber = null,
    string? Email = null
);

public record class EnrollVerifiedAuthenticatorResponse(
    UserAuthenticator Authenticator,
    List<string> RecoveryCodes
);

public record class AuthenticatorRequest(
    string UserId,
    string UserAuthenticatorId
);

public record class DeleteAuthenticatorResponse(
    bool Success
);

public record class UserAuthenticator(
    string UserId,
    string UserAuthenticatorId,
    VerificationMethod VerificationMethod,
    string CreatedAt,
    string? VerifiedAt = null,
    string? Email = null,
    string? PhoneNumber = null
);

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum UserActionState
{
    ALLOW,
    BLOCK,
    CHALLENGE_REQUIRED,
    CHALLENGE_SUCCEEDED,
    CHALLENGE_FAILED
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum VerificationMethod
{
    SMS,
    EMAIL_MAGIC_LINK,
    EMAIL_OTP,
    AUTHENTICATOR_APP,
    PASSKEY,
    SECURITY_KEY,
    PUSH,
    VERIFF,
    IPROOV,
    IDVERSE,
    RECOVERY_CODE,
}