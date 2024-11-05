namespace Authsignal.Tests;

public class ClientTests : TestBase
{
    [Fact]
    public async Task GetUser()
    {
        var request = new UserRequest(UserId: Configuration["UserId"]!);

        var response = await AuthsignalClient.GetUser(request);

        Assert.NotNull(response);
    }

    [Fact]
    public async Task Track()
    {
        var request = new TrackRequest(UserId: Configuration["UserId"]!, Action: "Login");

        var response = await AuthsignalClient.Track(request);

        Assert.NotNull(response);
    }

    [Fact]
    public async Task GetAction()
    {
        var trackRequest = new TrackRequest(UserId: Configuration["UserId"]!, Action: "Login");

        var trackResponse = await AuthsignalClient.Track(trackRequest);

        var actionRequest = new ActionRequest(
            UserId: Configuration["UserId"]!,
            Action: "Login",
            IdempotencyKey: trackResponse.IdempotencyKey);

        var actionResponse = await AuthsignalClient.GetAction(actionRequest);

        Assert.NotNull(actionResponse);
    }

    [Fact]
    public async Task EnrollVerifiedAuthenticator()
    {
        var request = new EnrollVerifiedAuthenticatorRequest(
            UserId: Configuration["UserId"]!,
            VerificationMethod: VerificationMethod.SMS,
            PhoneNumber: "+6427000000");

        var response = await AuthsignalClient.EnrollVerifiedAuthenticator(request);

        Assert.NotNull(response);
    }

    [Fact]
    public async Task ValidateChallenge()
    {
        var trackRequest = new TrackRequest(UserId: Configuration["UserId"]!, Action: "Login");

        var trackResponse = await AuthsignalClient.Track(trackRequest);

        var validateRequest = new ValidateChallengeRequest(Token: trackResponse.Token);

        var validateResponse = await AuthsignalClient.ValidateChallenge(validateRequest);

        Assert.NotNull(validateResponse);
        Assert.Equal("Login", validateResponse.Action);
        Assert.Equal(Configuration["UserId"]!, validateResponse.UserId);
    }

    [Fact]
    public async Task TestAuthenticators()
    {
        var userId = Configuration["UserId"]!;

        var enrollRequest = new EnrollVerifiedAuthenticatorRequest(
           UserId: userId,
           VerificationMethod: VerificationMethod.SMS,
           PhoneNumber: "+6427000000");

        var enrollResponse = await AuthsignalClient.EnrollVerifiedAuthenticator(enrollRequest);

        var userAuthenticatorId = enrollResponse.Authenticator.UserAuthenticatorId;

        var userRequest = new UserRequest(UserId: userId);

        var allAuthenticators = await AuthsignalClient.GetAuthenticators(userRequest);

        var match = allAuthenticators.FirstOrDefault(a => a.UserAuthenticatorId == userAuthenticatorId);

        Assert.NotNull(match);

        var deleteRequest = new AuthenticatorRequest(UserId: userId, UserAuthenticatorId: userAuthenticatorId);

        var deleteResponse = await AuthsignalClient.DeleteAuthenticator(deleteRequest);

        Assert.True(deleteResponse.Success);

        var updatedAuthenticators = await AuthsignalClient.GetAuthenticators(userRequest);

        var updatedMatch = updatedAuthenticators.FirstOrDefault(a => a.UserAuthenticatorId == userAuthenticatorId);

        Assert.Null(updatedMatch);
    }

    [Fact]
    public async Task TestUser()
    {
        var userId = Guid.NewGuid().ToString();

        var userRequest = new UserRequest(UserId: userId);

        var userResponse = await AuthsignalClient.GetUser(userRequest);

        Assert.False(userResponse.IsEnrolled);
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

        Assert.False(updateUserResponse.IsEnrolled);
        Assert.Equal(email, updateUserResponse.Email);
        Assert.Equal(phoneNumber, updateUserResponse.PhoneNumber);
        Assert.Equal(username, updateUserResponse.Username);
        Assert.Equal(displayName, updateUserResponse.DisplayName);
        Assert.Equal("bar", custom["foo"]);
    }
}
