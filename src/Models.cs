
using System.Text.Json.Serialization;

namespace Authsignal;

public record class AuthsignalHttpRequest(
    HttpMethod HttpMethod,
    string Path,
    HttpContent? Content = null
);

public record class GetUserRequest(
    string UserId
);

public record class GetUserResponse(
    bool IsEnrolled,
    string? Email = null,
    string? PhoneNumber = null,
    string? Username = null,
    string? DisplayName = null,
    VerificationMethod[]? EnrolledVerificationMethods = null,
    VerificationMethod[]? AllowedVerificationMethods = null,
    VerificationMethod? DefaultVerificationMethod = null,
    Dictionary<string, string>? Custom = null
);

public record class UpdateUserRequest(
    string UserId,
    UserAttributes Attributes
);

public record class UserAttributes(
    string? Email = null,
    string? PhoneNumber = null,
    string? Username = null,
    string? DisplayName = null,
    Dictionary<string, string>? Custom = null
);

public record class DeleteUserRequest(
    string UserId
);

public record class TrackRequest(
    string UserId,
    string Action,
    TrackAttributes? Attributes = default
);

public record class TrackAttributes(
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
    string IdempotencyKey,
    UserActionState State,
    string Url,
    string Token,
    bool IsEnrolled,
    VerificationMethod[]? EnrolledVerificationMethods = null,
    VerificationMethod[]? AllowedVerificationMethods = null,
    VerificationMethod? DefaultVerificationMethod = null
);

public record class GetActionRequest(
    string UserId,
    string Action,
    string IdempotencyKey
);

public record class GetActionResponse(
    UserActionState State,
    string StateUpdatedAt,
    string CreatedAt,
    VerificationMethod? VerificationMethod = null,
    Rule[]? Rules = null,
    dynamic? Output = null
);

public record class Rule(
    string RuleId,
    string Name,
    string? Description = null
);

public record class UpdateActionRequest(
    string UserId,
    string Action,
    string IdempotencyKey,
    ActionAttributes Attributes
);

public record class ActionAttributes(
    UserActionState State
);

public record class ValidateChallengeRequest(
    string Token,
    string? UserId = null,
    string? Action = null
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

public record class GetAuthenticatorsRequest(
    string UserId
);

public record class EnrollVerifiedAuthenticatorRequest(
    string UserId,
    EnrollVerifiedAuthenticatorAttributes Attributes
);

public record class EnrollVerifiedAuthenticatorAttributes(
   VerificationMethod VerificationMethod,
    string? PhoneNumber = null,
    string? Email = null
);

public record class EnrollVerifiedAuthenticatorResponse(
    UserAuthenticator Authenticator,
    List<string> RecoveryCodes
);

public record class DeleteAuthenticatorRequest(
    string UserId,
    string UserAuthenticatorId
);

public record class UserAuthenticator(
    string UserId,
    string UserAuthenticatorId,
    VerificationMethod VerificationMethod,
    string CreatedAt,
    string? VerifiedAt = null,
    string? LastVerifiedAt = null,
    string? Email = null,
    string? PhoneNumber = null,
    string? Username = null,
    string? DisplayName = null,
    WebauthnCredential? WebauthnCredential = null
);

public record class WebauthnCredential(
    string CredentialId,
    string DeviceId,
    string Name,
    string? Aaguid = null,
    AaguidMapping? AaguidMapping = null,
    bool? CredentialBackedUp = null,
    string? CredentialDeviceType = null,
    string? AuthenticatorAttachment = null,
    UserAgent? ParsedUserAgent = null
);

public record class AaguidMapping(
    string Name,
    string SvgIconLight,
    string SvgIconDark
);

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum UserActionState
{
    ALLOW,
    BLOCK,
    CHALLENGE_REQUIRED,
    CHALLENGE_SUCCEEDED,
    CHALLENGE_FAILED,
    REVIEW_REQUIRED,
    REVIEW_SUCCEEDED,
    REVIEW_FAILED
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

public record class AuthsignalErrorResponse(
    string Error,
    string ErrorDescription
);

public record class UserAgent(
    string Ua,
    UserAgentBrowser? Browser = null,
    UserAgentDevice? Device = null,
    UserAgentEngine? Engine = null,
    UserAgentOs? Os = null,
    UserAgentCpu? Cpu = null
);

public record class UserAgentBrowser(
    string Name,
    string Version,
    string Major
);

public record class UserAgentDevice(
    string Model,
    string Type,
    string Vendor
);

public record class UserAgentEngine(
    string Name,
    string Version
);

public record class UserAgentOs(
    string Name,
    string Version
);

public record class UserAgentCpu(
    string Architecture
);
