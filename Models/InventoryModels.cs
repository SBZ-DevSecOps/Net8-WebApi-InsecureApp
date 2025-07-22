namespace Net8_WebApi_InsecureApp.Models
{
    // ===== MODÈLES POUR IMPROPER INVENTORY MANAGEMENT =====

    public class ApiEndpoint
    {
        public int Id { get; set; }
        public string Path { get; set; } = string.Empty;
        public string Method { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public bool IsDeprecated { get; set; }
        public bool IsInternal { get; set; }
        public bool RequiresAuth { get; set; }
        public string? Description { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? DeprecatedAt { get; set; }
        public List<string> Permissions { get; set; } = new();
    }

    public class ApiVersion
    {
        public int Id { get; set; }
        public string Version { get; set; } = string.Empty;
        public bool IsActive { get; set; }
        public bool IsPublic { get; set; }
        public DateTime ReleaseDate { get; set; }
        public DateTime? EndOfLifeDate { get; set; }
        public string? ReleaseNotes { get; set; }
        public List<string> Features { get; set; } = new();
        public Dictionary<string, object> Configuration { get; set; } = new();
    }

    public class ServiceRegistry
    {
        public int Id { get; set; }
        public string ServiceName { get; set; } = string.Empty;
        public string ServiceUrl { get; set; } = string.Empty;
        public string Environment { get; set; } = string.Empty;
        public bool IsActive { get; set; }
        public string? ApiKey { get; set; }
        public string? ConnectionString { get; set; }
        public Dictionary<string, string> Headers { get; set; } = new();
        public List<string> AllowedIPs { get; set; } = new();
    }

    public class DebugInfo
    {
        public string ServerVersion { get; set; } = string.Empty;
        public string FrameworkVersion { get; set; } = string.Empty;
        public List<string> LoadedAssemblies { get; set; } = new();
        public Dictionary<string, string> EnvironmentVariables { get; set; } = new();
        public Dictionary<string, object> ServerConfig { get; set; } = new();
        public List<string> RegisteredMiddleware { get; set; } = new();
        public List<string> RegisteredServices { get; set; } = new();
    }

    public class SwaggerConfig
    {
        public int Id { get; set; }
        public string Version { get; set; } = string.Empty;
        public bool ExposeInternalEndpoints { get; set; }
        public bool ShowDetailedErrors { get; set; }
        public bool IncludeDebugInfo { get; set; }
        public List<string> HiddenEndpoints { get; set; } = new();
        public Dictionary<string, string> CustomHeaders { get; set; } = new();
    }

    public class LegacyEndpoint
    {
        public int Id { get; set; }
        public string OriginalPath { get; set; } = string.Empty;
        public string LegacyPath { get; set; } = string.Empty;
        public string Method { get; set; } = string.Empty;
        public bool IsStillActive { get; set; }
        public string? RedirectTo { get; set; }
        public DateTime CreatedAt { get; set; }
        public string? SecurityIssues { get; set; }
    }

    public class InternalService
    {
        public int Id { get; set; }
        public string ServiceName { get; set; } = string.Empty;
        public string InternalUrl { get; set; } = string.Empty;
        public string? DatabaseConnection { get; set; }
        public string? AdminCredentials { get; set; }
        public bool IsExposedExternally { get; set; }
        public int Port { get; set; }
        public Dictionary<string, string> Secrets { get; set; } = new();
    }

    public class ApiDocumentation
    {
        public int Id { get; set; }
        public string EndpointPath { get; set; } = string.Empty;
        public string Method { get; set; } = string.Empty;
        public string? RequestSchema { get; set; }
        public string? ResponseSchema { get; set; }
        public List<string> RequiredHeaders { get; set; } = new();
        public Dictionary<string, string> Examples { get; set; } = new();
        public bool IsPubliclyDocumented { get; set; }
        public string? InternalNotes { get; set; }
    }

    // ===== MODÈLES DE REQUÊTE =====

    public class EndpointDiscoveryRequest
    {
        public string? Pattern { get; set; }
        public bool IncludeDeprecated { get; set; }
        public bool IncludeInternal { get; set; }
        public bool IncludeHidden { get; set; }
    }

    public class VersionCheckRequest
    {
        public string? CurrentVersion { get; set; }
        public bool IncludePrerelease { get; set; }
        public bool ShowAllVersions { get; set; }
    }

    public class ServiceDiscoveryRequest
    {
        public string? Environment { get; set; }
        public bool IncludeInactive { get; set; }
        public bool IncludeCredentials { get; set; }
    }

    // ===== MODÈLES DE RÉPONSE =====

    public class SystemInfoResponse
    {
        public string Hostname { get; set; } = string.Empty;
        public string IpAddress { get; set; } = string.Empty;
        public string MachineName { get; set; } = string.Empty;
        public string OperatingSystem { get; set; } = string.Empty;
        public int ProcessorCount { get; set; }
        public long TotalMemory { get; set; }
        public Dictionary<string, string> NetworkInterfaces { get; set; } = new();
        public List<int> OpenPorts { get; set; } = new();
        public Dictionary<string, object> DetailedInfo { get; set; } = new();
    }

    public class ApiInventoryResponse
    {
        public List<ApiEndpoint> Endpoints { get; set; } = new();
        public List<ApiVersion> Versions { get; set; } = new();
        public List<ServiceRegistry> Services { get; set; } = new();
        public Dictionary<string, int> Statistics { get; set; } = new();
        public DebugInfo? DebugInformation { get; set; }
    }
}