using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Net8_WebApi_InsecureApp.Data;
using Net8_WebApi_InsecureApp.Models;
using System.Collections;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Net8_WebApi_InsecureApp.Controllers
{
    /// <summary>
    /// Contrôleur démontrant la vulnérabilité API9:2023 - Improper Inventory Management
    /// Ce contrôleur contient intentionnellement des vulnérabilités pour des fins éducatives
    /// NE PAS UTILISER EN PRODUCTION
    /// </summary>
    [ApiController]
    [Route("api")]
    public class Api09InventoryController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IWebHostEnvironment _env;
        private readonly IConfiguration _configuration;
        private readonly ILogger<Api09InventoryController> _logger;

        public Api09InventoryController(
            AppDbContext context,
            IWebHostEnvironment env,
            IConfiguration configuration,
            ILogger<Api09InventoryController> logger)
        {
            _context = context;
            _env = env;
            _configuration = configuration;
            _logger = logger;
        }

        #region Endpoints non documentés et versions multiples

        /// <summary>
        /// VULNÉRABLE: Ancien endpoint v1 toujours actif
        /// </summary>
        [HttpGet("v1/users")]
        public async Task<IActionResult> GetUsersV1()
        {
            // VULNÉRABLE: Ancienne version sans pagination ni filtrage
            var users = await _context.Users.ToListAsync();
            return Ok(new
            {
                data = users,
                version = "1.0",
                deprecated = true,
                message = "This endpoint is deprecated, use /api/v2/users"
            });
        }

        /// <summary>
        /// VULNÉRABLE: Version beta exposée en production
        /// </summary>
        [HttpGet("v2-beta/users")]
        public async Task<IActionResult> GetUsersBeta()
        {
            // VULNÉRABLE: Endpoint beta avec fonctionnalités expérimentales
            var users = await _context.Users
                .Include(u => u.Orders)
                .Include(u => u.BankAccounts)
                .ToListAsync();

            return Ok(new
            {
                data = users,
                version = "2.0-beta",
                experimental_features = new[]
                {
                    "include_financial_data",
                    "include_internal_notes",
                    "bypass_authorization"
                }
            });
        }

        /// <summary>
        /// VULNÉRABLE: Endpoint interne exposé
        /// </summary>
        [HttpGet("internal/debug/users")]
        public async Task<IActionResult> GetUsersInternal()
        {
            // VULNÉRABLE: Endpoint interne qui ne devrait pas être accessible
            var users = await _context.Users.ToListAsync();
            return Ok(new
            {
                data = users,
                debug_info = new
                {
                    query_time_ms = 42,
                    connection_string = _configuration.GetConnectionString("DefaultConnection"),
                    server_name = Environment.MachineName,
                    is_production = _env.IsProduction()
                }
            });
        }

        /// <summary>
        /// VULNÉRABLE: Endpoint legacy non sécurisé
        /// </summary>
        [HttpGet("legacy/api/userData.php")]
        public async Task<IActionResult> GetUsersLegacy()
        {
            // VULNÉRABLE: Simule un ancien endpoint PHP migré
            Response.Headers.Add("X-Powered-By", "PHP/5.3.0");
            var users = await _context.Users.ToListAsync();
            return Ok(users);
        }

        #endregion

        #region Discovery et énumération d'endpoints

        /// <summary>
        /// VULNÉRABLE: Expose tous les endpoints disponibles
        /// </summary>
        [HttpGet("inventory/endpoints")]
        public async Task<IActionResult> DiscoverEndpoints([FromQuery] EndpointDiscoveryRequest request)
        {
            var endpoints = await _context.Set<ApiEndpoint>().ToListAsync();

            // VULNÉRABLE: Expose les endpoints internes et dépréciés
            if (request.IncludeInternal || request.IncludeDeprecated)
            {
                return Ok(endpoints);
            }

            // VULNÉRABLE: Même la version "filtrée" expose trop d'informations
            var publicEndpoints = endpoints.Where(e => !e.IsInternal).ToList();

            // Ajouter des endpoints découverts dynamiquement
            var discoveredEndpoints = DiscoverRuntimeEndpoints();
            publicEndpoints.AddRange(discoveredEndpoints);

            return Ok(new
            {
                endpoints = publicEndpoints,
                total_count = publicEndpoints.Count,
                server_time = DateTime.UtcNow,
                api_versions = new[] { "v1", "v2", "v2-beta", "v3-alpha", "internal" }
            });
        }

        /// <summary>
        /// VULNÉRABLE: Expose la configuration Swagger/OpenAPI
        /// </summary>
        [HttpGet("inventory/swagger-config")]
        public async Task<IActionResult> GetSwaggerConfig()
        {
            var config = await _context.Set<SwaggerConfig>().FirstOrDefaultAsync();

            // VULNÉRABLE: Expose la configuration interne
            return Ok(new
            {
                swagger_config = config,
                hidden_endpoints = new[]
                {
                    "/api/internal/*",
                    "/api/admin/*",
                    "/api/debug/*"
                },
                available_at = new[]
                {
                    "/swagger/v1/swagger.json",
                    "/swagger/internal/swagger.json",
                    "/swagger/admin/swagger.json"
                }
            });
        }

        /// <summary>
        /// VULNÉRABLE: Permet de scanner les endpoints
        /// </summary>
        [HttpPost("inventory/scan")]
        public IActionResult ScanEndpoints([FromBody] Dictionary<string, string> patterns)
        {
            var results = new List<object>();

            // VULNÉRABLE: Permet de tester l'existence d'endpoints
            foreach (var pattern in patterns)
            {
                var exists = Url.IsLocalUrl(pattern.Value);
                results.Add(new
                {
                    pattern = pattern.Key,
                    url = pattern.Value,
                    exists = exists,
                    accessible = true, // VULNÉRABLE: Toujours true
                    requires_auth = pattern.Value.Contains("admin")
                });
            }

            return Ok(results);
        }

        #endregion

        #region Informations système et debug

        /// <summary>
        /// VULNÉRABLE: Expose les informations système
        /// </summary>
        [HttpGet("inventory/system-info")]
        public IActionResult GetSystemInfo()
        {
            // VULNÉRABLE: Expose des informations système sensibles
            var systemInfo = new SystemInfoResponse
            {
                Hostname = Dns.GetHostName(),
                MachineName = Environment.MachineName,
                OperatingSystem = RuntimeInformation.OSDescription,
                ProcessorCount = Environment.ProcessorCount,
                TotalMemory = GC.GetTotalMemory(false),
                DetailedInfo = new Dictionary<string, object>
                {
                    ["DotNetVersion"] = RuntimeInformation.FrameworkDescription,
                    ["ProcessArchitecture"] = RuntimeInformation.ProcessArchitecture.ToString(),
                    ["OSArchitecture"] = RuntimeInformation.OSArchitecture.ToString(),
                    ["SystemDirectory"] = Environment.SystemDirectory,
                    ["CurrentDirectory"] = Environment.CurrentDirectory,
                    ["UserName"] = Environment.UserName,
                    ["UserDomainName"] = Environment.UserDomainName
                }
            };

            // VULNÉRABLE: Tenter d'obtenir l'IP et les interfaces réseau
            try
            {
                var host = Dns.GetHostEntry(Dns.GetHostName());
                systemInfo.IpAddress = host.AddressList
                    .FirstOrDefault(ip => ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    ?.ToString() ?? "Unknown";

                var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var ni in interfaces)
                {
                    if (ni.OperationalStatus == OperationalStatus.Up)
                    {
                        systemInfo.NetworkInterfaces[ni.Name] = ni.GetPhysicalAddress().ToString();
                    }
                }
            }
            catch { }

            return Ok(systemInfo);
        }

        /// <summary>
        /// VULNÉRABLE: Expose les variables d'environnement
        /// </summary>
        [HttpGet("inventory/environment")]
        public IActionResult GetEnvironmentInfo()
        {
            // VULNÉRABLE: Expose toutes les variables d'environnement
            var envVars = new Dictionary<string, string>();
            foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
            {
                envVars[entry.Key.ToString()!] = entry.Value?.ToString() ?? "";
            }

            return Ok(new
            {
                environment = _env.EnvironmentName,
                is_development = _env.IsDevelopment(),
                content_root = _env.ContentRootPath,
                web_root = _env.WebRootPath,
                application_name = _env.ApplicationName,
                environment_variables = envVars,
                connection_strings = _configuration.GetSection("ConnectionStrings").Get<Dictionary<string, string>>(),
                app_settings = _configuration.AsEnumerable().ToDictionary(k => k.Key, v => v.Value)
            });
        }

        /// <summary>
        /// VULNÉRABLE: Expose les assemblies chargées
        /// </summary>
        [HttpGet("inventory/assemblies")]
        public IActionResult GetLoadedAssemblies()
        {
            // VULNÉRABLE: Expose tous les assemblies chargés
            var assemblies = AppDomain.CurrentDomain.GetAssemblies();
            var assemblyInfo = assemblies.Select(a => new
            {
                name = a.GetName().Name,
                version = a.GetName().Version?.ToString(),
                location = a.IsDynamic ? "Dynamic" : a.Location,
                is_dynamic = a.IsDynamic,
                referenced_assemblies = a.GetReferencedAssemblies().Select(r => r.Name).ToList()
            });

            return Ok(new
            {
                total_count = assemblies.Length,
                assemblies = assemblyInfo,
                entry_assembly = Assembly.GetEntryAssembly()?.GetName().Name,
                executing_assembly = Assembly.GetExecutingAssembly().GetName().Name
            });
        }

        #endregion

        #region Service Discovery

        /// <summary>
        /// VULNÉRABLE: Expose le registre des services
        /// </summary>
        [HttpGet("inventory/services")]
        public async Task<IActionResult> DiscoverServices([FromQuery] ServiceDiscoveryRequest request)
        {
            var services = await _context.Set<ServiceRegistry>().ToListAsync();

            // VULNÉRABLE: Expose les credentials si demandé
            if (request.IncludeCredentials)
            {
                return Ok(services);
            }

            // VULNÉRABLE: Même sans le flag, expose des URLs internes
            var sanitized = services.Select(s => new
            {
                s.ServiceName,
                s.ServiceUrl,
                s.Environment,
                s.IsActive,
                has_api_key = !string.IsNullOrEmpty(s.ApiKey),
                has_connection_string = !string.IsNullOrEmpty(s.ConnectionString)
            });

            return Ok(new
            {
                services = sanitized,
                environments = services.Select(s => s.Environment).Distinct(),
                internal_services = services.Where(s => s.ServiceUrl.Contains("internal")).Count()
            });
        }

        /// <summary>
        /// VULNÉRABLE: Expose les services internes
        /// </summary>
        [HttpGet("inventory/internal-services")]
        public async Task<IActionResult> GetInternalServices()
        {
            var internalServices = await _context.Set<InternalService>().ToListAsync();

            // VULNÉRABLE: Expose tous les services internes avec leurs secrets
            return Ok(new
            {
                services = internalServices,
                warning = "These are internal services - do not expose publicly",
                total_exposed = internalServices.Count(s => s.IsExposedExternally)
            });
        }

        #endregion

        #region Documentation et schémas

        /// <summary>
        /// VULNÉRABLE: Expose la documentation interne
        /// </summary>
        [HttpGet("inventory/documentation")]
        public async Task<IActionResult> GetApiDocumentation([FromQuery] bool includeInternal = false)
        {
            var docs = await _context.Set<ApiDocumentation>().ToListAsync();

            if (includeInternal)
            {
                // VULNÉRABLE: Expose la documentation interne
                return Ok(docs);
            }

            // VULNÉRABLE: Même la doc publique peut contenir des infos sensibles
            var publicDocs = docs.Where(d => d.IsPubliclyDocumented).ToList();
            return Ok(new
            {
                documentation = publicDocs,
                internal_endpoints_count = docs.Count(d => !d.IsPubliclyDocumented),
                hint = "Add ?includeInternal=true to see all documentation"
            });
        }

        /// <summary>
        /// VULNÉRABLE: Génère un inventaire complet
        /// </summary>
        [HttpGet("inventory/complete")]
        public async Task<IActionResult> GetCompleteInventory()
        {
            // VULNÉRABLE: Expose un inventaire complet de l'API
            var inventory = new ApiInventoryResponse
            {
                Endpoints = await _context.Set<ApiEndpoint>().ToListAsync(),
                Versions = await _context.Set<ApiVersion>().ToListAsync(),
                Services = await _context.Set<ServiceRegistry>().ToListAsync(),
                Statistics = new Dictionary<string, int>
                {
                    ["total_endpoints"] = await _context.Set<ApiEndpoint>().CountAsync(),
                    ["deprecated_endpoints"] = await _context.Set<ApiEndpoint>().CountAsync(e => e.IsDeprecated),
                    ["internal_endpoints"] = await _context.Set<ApiEndpoint>().CountAsync(e => e.IsInternal),
                    ["public_endpoints"] = await _context.Set<ApiEndpoint>().CountAsync(e => !e.IsInternal && !e.IsDeprecated)
                },
                DebugInformation = _env.IsDevelopment() ? GetDebugInfo() : null
            };

            return Ok(inventory);
        }

        #endregion

        #region Version Management

        /// <summary>
        /// VULNÉRABLE: Expose toutes les versions d'API
        /// </summary>
        [HttpGet("versions")]
        public async Task<IActionResult> GetApiVersions([FromQuery] VersionCheckRequest request)
        {
            var versions = await _context.Set<ApiVersion>().ToListAsync();

            // VULNÉRABLE: Expose toutes les versions y compris les non publiques
            if (request.ShowAllVersions)
            {
                return Ok(new
                {
                    current_version = "2.0",
                    all_versions = versions,
                    deprecated_versions = versions.Where(v => v.EndOfLifeDate < DateTime.UtcNow),
                    beta_versions = versions.Where(v => v.Version.Contains("beta") || v.Version.Contains("alpha")),
                    internal_versions = versions.Where(v => !v.IsPublic)
                });
            }

            return Ok(new
            {
                current_version = "2.0",
                supported_versions = versions.Where(v => v.IsActive && v.IsPublic),
                hint = "Add ?showAllVersions=true to see all versions including internal"
            });
        }

        #endregion

        #region Helper Methods

        private List<ApiEndpoint> DiscoverRuntimeEndpoints()
        {
            // VULNÉRABLE: Découverte dynamique des endpoints
            var endpoints = new List<ApiEndpoint>();

            // Simuler la découverte d'endpoints
            var controllers = Assembly.GetExecutingAssembly()
                .GetTypes()
                .Where(t => t.IsSubclassOf(typeof(ControllerBase)))
                .ToList();

            foreach (var controller in controllers)
            {
                var methods = controller.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                    .Where(m => m.IsPublic && !m.IsSpecialName)
                    .ToList();

                foreach (var method in methods)
                {
                    endpoints.Add(new ApiEndpoint
                    {
                        Path = $"/api/{controller.Name.Replace("Controller", "").ToLower()}/{method.Name.ToLower()}",
                        Method = "GET/POST",
                        Version = "discovered",
                        IsInternal = method.Name.Contains("Internal"),
                        Description = $"Discovered endpoint from {controller.Name}.{method.Name}"
                    });
                }
            }

            return endpoints;
        }

        private DebugInfo GetDebugInfo()
        {
            return new DebugInfo
            {
                ServerVersion = Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? "Unknown",
                FrameworkVersion = RuntimeInformation.FrameworkDescription,
                LoadedAssemblies = AppDomain.CurrentDomain.GetAssemblies().Select(a => a.GetName().Name ?? "").ToList(),
                EnvironmentVariables = Environment.GetEnvironmentVariables()
                    .Cast<DictionaryEntry>()
                    .ToDictionary(e => e.Key.ToString()!, e => e.Value?.ToString() ?? ""),
                RegisteredServices = HttpContext.RequestServices.GetType()
                    .GetProperties()
                    .Select(p => p.Name)
                    .ToList()
            };
        }

        #endregion
    }
}