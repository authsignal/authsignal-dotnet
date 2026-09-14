using System.Text.Json.Serialization;

namespace Authsignal;

public record class StartFlowRequest(
    string ActionCode,
    UserLookup? User = null,
    ChallengeAttributes? Attributes = null,
    string? RedirectUrl = null,
    string? ClientId = null
);

public record class StartFlowResponse(
    FlowAction Action,
    string ChallengeToken,
    string ChallengeUrl,
    FlowUser? User = null
);

public record class VerifyFlowRequest(
    string ActionCode,
    string ChallengeToken
);

public record class VerifyFlowResponse(
    FlowAction Action,
    AuthenticationSession? Session = null,
    FlowUser? User = null
);

public record class UserLookup(
    string? UserId = null,
    string? Email = null,
    string? PhoneNumber = null,
    string? Username = null
);

public record class FlowAction(
    FlowState State,
    CompletedActionStep[]? CompletedSteps = null,
    ActionStep? NextStep = null
);

public record class ActionStep(
    ActionStepType StepType,
    VerificationMethod[] VerificationMethods
);

public record class CompletedActionStep(
    ActionStepType StepType,
    VerificationMethod VerificationMethod,
    string? UserAuthenticatorId = null
);

public record class ChallengeAttributes(
    string? DeviceId = null,
    string? IpAddress = null,
    string? UserAgent = null,
    Dictionary<string, object>? Custom = null,
    string? Locale = null
);

public record class FlowUser(
    string UserId,
    FlowUserAuthenticator[] Authenticators,
    string? Email = null,
    string? PhoneNumber = null,
    string? Username = null,
    string? DisplayName = null
);

public record class FlowUserAuthenticator(
    string UserAuthenticatorId,
    VerificationMethod VerificationMethod,
    string? Email = null,
    string? PhoneNumber = null,
    string? Username = null,
    string? DisplayName = null
);

public record class AuthenticationSession(
    string AccessToken,
    string RefreshToken
);

public record class EmailChallengeRequest(
    string ChallengeToken,
    string? Email = null
);

public record class SmsChallengeRequest(
    string ChallengeToken,
    string? PhoneNumber = null
);

public record class WhatsappChallengeRequest(
    string ChallengeToken,
    string? PhoneNumber = null
);

public record class OtpChallengeResponse(
    int? RetryAfterSeconds = null
);

public record class OtpVerifyRequest(
    string ChallengeToken,
    string VerificationCode
);

public record class OtpVerifyResponse(
    FlowAction Action,
    string ChallengeToken,
    FlowUser User
);

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum FlowState
{
    CHALLENGE_REQUIRED,
    CHALLENGE_SUCCEEDED,
    CHALLENGE_FAILED
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ActionStepType
{
    VERIFICATION_REQUIRED,
    ENROLLMENT_REQUIRED,
    ENROLLMENT_OPTIONAL
}
