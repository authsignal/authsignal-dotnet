namespace Authsignal.Tests;

public class ClientTests : TestBase
{
    [Fact]
    public async Task TestUser()
    {
        var userId = Guid.NewGuid().ToString();

        var enrollRequest = new EnrollVerifiedAuthenticatorRequest(
           UserId: userId,
           VerificationMethod: VerificationMethod.SMS,
           PhoneNumber: "+6427000000");

        var enrollResponse = await AuthsignalClient.EnrollVerifiedAuthenticator(enrollRequest);

        Assert.NotNull(enrollResponse);

        var userRequest = new UserRequest(UserId: userId);

        var userResponse = await AuthsignalClient.GetUser(userRequest);

        Assert.True(userResponse.IsEnrolled);
        Assert.Null(userResponse.Email);

        var email = "test@example.com";
        var phoneNumber = "+6427123456";
        var username = email;
        var displayName = "Test User";
        var custom = new Dictionary<string, string> { { "foo", "bar" } };

        var updateUserRequest = new UpdateUserRequest(
            UserId: userId,
            Email: email,
            PhoneNumber: phoneNumber,
            Username: username,
            DisplayName: displayName,
            Custom: custom);

        var updateUserResponse = await AuthsignalClient.UpdateUser(updateUserRequest);

        Assert.Equal(email, updateUserResponse.Email);
        Assert.Equal(phoneNumber, updateUserResponse.PhoneNumber);
        Assert.Equal(username, updateUserResponse.Username);
        Assert.Equal(displayName, updateUserResponse.DisplayName);
        Assert.Equal("bar", custom["foo"]);

        await AuthsignalClient.DeleteUser(userRequest);

        var deletedUserResponse = await AuthsignalClient.GetUser(userRequest);

        Assert.False(deletedUserResponse.IsEnrolled);
    }

    [Fact]
    public async Task TestAuthenticator()
    {
        var userId = Guid.NewGuid().ToString();

        var enrollRequest = new EnrollVerifiedAuthenticatorRequest(
           UserId: userId,
           VerificationMethod: VerificationMethod.SMS,
           PhoneNumber: "+6427000000");

        var enrollResponse = await AuthsignalClient.EnrollVerifiedAuthenticator(enrollRequest);

        Assert.NotNull(enrollResponse);

        var userRequest = new UserRequest(UserId: userId);

        var authenticatorsResponse = await AuthsignalClient.GetAuthenticators(userRequest);

        Assert.NotNull(authenticatorsResponse);
        Assert.NotEmpty(authenticatorsResponse);

        var authenticator = authenticatorsResponse.First();

        Assert.NotNull(authenticator);
        Assert.Equal(VerificationMethod.SMS, authenticator.VerificationMethod);

        var authenticatorRequest = new AuthenticatorRequest(
            UserId: userId,
            UserAuthenticatorId: authenticator.UserAuthenticatorId);

        await AuthsignalClient.DeleteAuthenticator(authenticatorRequest);

        var emptyAuthenticatorsResponse = await AuthsignalClient.GetAuthenticators(userRequest);

        Assert.Empty(emptyAuthenticatorsResponse);
    }

    [Fact]
    public async Task TestAction()
    {
        var userId = Guid.NewGuid().ToString();
        var action = "Login";

        var enrollRequest = new EnrollVerifiedAuthenticatorRequest(
           UserId: userId,
           VerificationMethod: VerificationMethod.SMS,
           PhoneNumber: "+6427000000");

        var enrollResponse = await AuthsignalClient.EnrollVerifiedAuthenticator(enrollRequest);

        Assert.NotNull(enrollResponse);

        var trackRequest = new TrackRequest(UserId: userId, Action: action);

        var trackResponse = await AuthsignalClient.Track(trackRequest);

        var idempotencyKey = trackResponse.IdempotencyKey;

        Assert.NotNull(trackResponse);
        Assert.Equal(UserActionState.CHALLENGE_REQUIRED, trackResponse.State);

        var validateRequest = new ValidateChallengeRequest(Token: trackResponse.Token);

        var validateResponse = await AuthsignalClient.ValidateChallenge(validateRequest);

        Assert.NotNull(validateResponse);
        Assert.Equal(action, validateResponse.Action);
        Assert.Equal(userId, validateResponse.UserId);
        Assert.Equal(UserActionState.CHALLENGE_REQUIRED, validateResponse.State);
        Assert.False(validateResponse.IsValid);

        var updateActionStateRequest = new UpdateActionStateRequest(
            UserId: userId,
            Action: action,
            IdempotencyKey: idempotencyKey,
            State: UserActionState.REVIEW_REQUIRED);

        var updateActionStateResponse = await AuthsignalClient.UpdateActionState(updateActionStateRequest);

        Assert.NotNull(updateActionStateResponse);

        var actionRequest = new ActionRequest(
           UserId: userId,
           Action: action,
           IdempotencyKey: idempotencyKey);

        var actionResponse = await AuthsignalClient.GetAction(actionRequest);

        Assert.NotNull(actionResponse);
        Assert.Equal(UserActionState.REVIEW_REQUIRED, actionResponse.State);
    }

    [Fact]
    public async Task TestInvalidSecretError()
    {
        var baseUrl = Configuration["BaseUrl"]!;

        var secret = "invalid_secret";

        var client = new AuthsignalClient(secret, baseUrl);

        var userRequest = new UserRequest(UserId: Guid.NewGuid().ToString());

        try
        {
            var userResponse = await client.GetUser(userRequest);
        }
        catch (AuthsignalException e)
        {
            Assert.Equal(401, e.StatusCode);
            Assert.Equal("unauthorized", e.Error);
            Assert.Equal("The request is unauthorized. Check that your API key and region base URL are correctly configured.", e.ErrorDescription);
        }
    }
}
