namespace TokenExchangeApi.Models;

public sealed class TokenExchangeRequest
{
    public required string GrantType { get; init; }
    public required string SubjectToken { get; init; }
    public required string SubjectTokenType { get; init; }
    public required string Audience { get; init; }
    public required string Scope { get; init; }
}

public sealed class TokenExchangeResponse
{
    public required string AccessToken { get; init; }
    public string IssuedTokenType { get; init; } = "urn:ietf:params:oauth:token-type:jwt";
    public string TokenType { get; init; } = "Bearer";
    public required int ExpiresIn { get; init; }
    public required string Scope { get; init; }
}

public sealed class TokenExchangeError
{
    public required string Error { get; init; }
    public required string ErrorDescription { get; init; }
}
