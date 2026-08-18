namespace TokenExchangeApi.Services;

public interface IPermissionService
{
    Task<IReadOnlySet<string>> GetEntitledScopesAsync(string userId, string audience, CancellationToken ct);

    Task<IReadOnlySet<string>> GetAllowedRequestScopesAsync(string clientId, string audience, CancellationToken ct);
}
public sealed class InMemoryPermissionService : IPermissionService
{
    private static readonly Dictionary<(string User, string Audience), HashSet<string>> UserEntitlements = new()
    {
        [("user-123", "https://api.collaborate.caseware.com/documents")] =
            new HashSet<string> { "documents.read", "documents.comment" },
        [("user-123", "https://api.collaborate.caseware.com/financial-data")] =
            new HashSet<string> { "financial-data.read" },
    };

    private static readonly Dictionary<(string Client, string Audience), HashSet<string>> ClientAllowedScopes = new()
    {
        [("notification-service", "https://api.collaborate.caseware.com/documents")] =
            new HashSet<string> { "documents.read" },
        [("client-integration-acme", "https://api.collaborate.caseware.com/financial-data")] =
            new HashSet<string> { "financial-data.read" },
    };

    public Task<IReadOnlySet<string>> GetEntitledScopesAsync(string userId, string audience, CancellationToken ct)
    {
        UserEntitlements.TryGetValue((userId, audience), out var scopes);
        return Task.FromResult<IReadOnlySet<string>>(scopes ?? new HashSet<string>());
    }

    public Task<IReadOnlySet<string>> GetAllowedRequestScopesAsync(string clientId, string audience, CancellationToken ct)
    {
        ClientAllowedScopes.TryGetValue((clientId, audience), out var scopes);
        return Task.FromResult<IReadOnlySet<string>>(scopes ?? new HashSet<string>());
    }
}
