namespace Authsignal.Tests;

public class ClientTests : TestBase
{
    [Fact]
    public async Task TestUser()
    {
        var userId = Guid.NewGuid().ToString();

        var enrollRequest = new EnrollVerifiedAuthenticatorRequest(
            UserId: userId,
            Attributes: new(
                VerificationMethod: VerificationMethod.SMS,
                PhoneNumber: "+6427000000"));

        var enrollResponse = await AuthsignalClient.EnrollVerifiedAuthenticator(enrollRequest);

        Assert.NotNull(enrollResponse);

        var userRequest = new GetUserRequest(UserId: userId);

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
            Attributes: new(
                Email: email,
                PhoneNumber: phoneNumber,
                Username: username,
                DisplayName: displayName,
                Custom: custom));

        var updatedAttributes = await AuthsignalClient.UpdateUser(updateUserRequest);

        Assert.Equal(email, updatedAttributes.Email);
        Assert.Equal(phoneNumber, updatedAttributes.PhoneNumber);
        Assert.Equal(username, updatedAttributes.Username);
        Assert.Equal(displayName, updatedAttributes.DisplayName);
        Assert.Equal("bar", custom["foo"]);

        var deleteUserRequest = new DeleteUserRequest(UserId: userId);

        await AuthsignalClient.DeleteUser(deleteUserRequest);

        var deletedUserResponse = await AuthsignalClient.GetUser(userRequest);

        Assert.False(deletedUserResponse.IsEnrolled);
    }

    [Fact]
    public async Task TestAuthenticator()
    {
        var userId = Guid.NewGuid().ToString();

        var enrollRequest = new EnrollVerifiedAuthenticatorRequest(
            UserId: userId,
            Attributes: new(
                VerificationMethod: VerificationMethod.SMS,
                PhoneNumber: "+6427000000"));

        var enrollResponse = await AuthsignalClient.EnrollVerifiedAuthenticator(enrollRequest);

        Assert.NotNull(enrollResponse);

        var authenticatorsRequest = new GetAuthenticatorsRequest(UserId: userId);

        var authenticators = await AuthsignalClient.GetAuthenticators(authenticatorsRequest);

        Assert.NotNull(authenticators);
        Assert.NotEmpty(authenticators);

        var authenticator = authenticators.First();

        Assert.NotNull(authenticator);
        Assert.Equal(VerificationMethod.SMS, authenticator.VerificationMethod);

        var authenticatorRequest = new DeleteAuthenticatorRequest(
            UserId: userId,
            UserAuthenticatorId: authenticator.UserAuthenticatorId);

        await AuthsignalClient.DeleteAuthenticator(authenticatorRequest);

        var emptyAuthenticatorsResponse = await AuthsignalClient.GetAuthenticators(authenticatorsRequest);

        Assert.Empty(emptyAuthenticatorsResponse);
    }

    [Fact]
    public async Task TestAction()
    {
        var userId = Guid.NewGuid().ToString();
        var action = "Login";

        var enrollRequest = new EnrollVerifiedAuthenticatorRequest(
           UserId: userId,
           Attributes: new(
               VerificationMethod: VerificationMethod.SMS,
               PhoneNumber: "+6427000000"));

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

        var updateActionRequest = new UpdateActionRequest(
            UserId: userId,
            Action: action,
            IdempotencyKey: idempotencyKey,
            Attributes: new(State: UserActionState.REVIEW_REQUIRED));

        var updatedAttributes = await AuthsignalClient.UpdateAction(updateActionRequest);

        Assert.NotNull(updatedAttributes);

        var actionRequest = new GetActionRequest(
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

        var userRequest = new GetUserRequest(UserId: Guid.NewGuid().ToString());

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

    [Fact]
    public async Task TestPasskeyAuthenticator()
    {
        var userId = "b60429a1-6288-43dc-80c0-6a3e73dd51b9";

        var authenticatorsRequest = new GetAuthenticatorsRequest(UserId: userId);

        var authenticators = await AuthsignalClient.GetAuthenticators(authenticatorsRequest);

        Assert.NotNull(authenticators);
        Assert.NotEmpty(authenticators);

        foreach (var authenticator in authenticators)
        {
            if (authenticator.VerificationMethod == VerificationMethod.PASSKEY)
            {
                var name = authenticator.WebauthnCredential?.AaguidMapping?.Name;

                Assert.NotNull(name);

                if (name != null)
                {
                    Assert.Contains(name, ["Google Password Manager", "iCloud Keychain"]);
                }

                Assert.Equal("Chrome", authenticator.WebauthnCredential?.ParsedUserAgent?.Browser?.Name);
            }
        }
    }
}