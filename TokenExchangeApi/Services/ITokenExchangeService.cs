using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace TokenExchangeApi.Services;

public sealed class TokenSettings
{
    public required string Issuer { get; init; }
    public required string SigningKey { get; init; }
    public required int ExchangedTokenLifetimeSeconds { get; init; }
}

public sealed class SubjectTokenInvalidException(string reason) : Exception(reason);
public interface ITokenExchangeService
{
    string ValidateSubjectTokenAndGetUserId(string subjectToken);

    (string AccessToken, int ExpiresIn) IssueExchangedToken(
        string subjectUserId,
        string actorClientId,
        string audience,
        IEnumerable<string> grantedScopes);
}
public sealed class JwtTokenExchangeService : ITokenExchangeService
{
    private readonly TokenSettings _settings;
    private readonly SymmetricSecurityKey _signingKey;

    public JwtTokenExchangeService(IOptions<TokenSettings> settings)
    {
        _settings = settings.Value;
        _signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.SigningKey));
    }

    public string ValidateSubjectTokenAndGetUserId(string subjectToken)
    {
        var handler = new JwtSecurityTokenHandler();

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = _settings.Issuer,
            ValidateAudience = true,
            ValidAudience = "collaborate-sts",
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _signingKey,
            ClockSkew = TimeSpan.FromSeconds(30),
        };

        ClaimsPrincipal principal;
        try
        {
            principal = handler.ValidateToken(subjectToken, validationParameters, out _);
        }
        catch (Exception ex)
        {
            throw new SubjectTokenInvalidException(ex.Message);
        }

        var userId = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            throw new SubjectTokenInvalidException("subject_token has no 'sub' claim.");
        }

        return userId;
    }
    public (string AccessToken, int ExpiresIn) IssueExchangedToken(
    string subjectUserId,
    string actorClientId,
    string audience,
    IEnumerable<string> grantedScopes)
    {
        var now = DateTime.UtcNow;
        var expires = now.AddSeconds(_settings.ExchangedTokenLifetimeSeconds);
        var scopeString = string.Join(' ', grantedScopes);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, subjectUserId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("scope", scopeString),
            new("act", $"{{\"sub\":\"{actorClientId}\"}}", JsonClaimValueTypes.Json),
        };

        var credentials = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _settings.Issuer,
            audience: audience,
            claims: claims,
            notBefore: now,
            expires: expires,
            signingCredentials: credentials);

        var accessToken = new JwtSecurityTokenHandler().WriteToken(token);
        return (accessToken, _settings.ExchangedTokenLifetimeSeconds);
    }
}