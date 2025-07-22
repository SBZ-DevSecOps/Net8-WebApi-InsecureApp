using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Net8_WebApi_InsecureApp.Data;
using Net8_WebApi_InsecureApp.Models;
using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace Net8_WebApi_InsecureApp.Controllers
{
    /// <summary>
    /// API8:2023 - Security Misconfiguration (VULNÉRABLE)
    /// Ce contrôleur démontre les mauvaises configurations de sécurité
    /// comme CORS permissif, headers manquants, endpoints de debug exposés, etc.
    /// </summary>
    [ApiController]
    [Route("api/config")]
    public class Api08SecurityMisconfigController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly ILogger<Api08SecurityMisconfigController> _logger;
        private readonly IConfiguration _configuration;
        private readonly IWebHostEnvironment _env;

        public Api08SecurityMisconfigController(
            AppDbContext context,
            ILogger<Api08SecurityMisconfigController> logger,
            IConfiguration configuration,
            IWebHostEnvironment env)
        {
            _context = context;
            _logger = logger;
            _configuration = configuration;
            _env = env;
        }

        #region Endpoints de debug exposés

        /// <summary>
        /// VULNÉRABLE: Endpoint de debug exposé en production
        /// </summary>
        [HttpGet("debug/info")]
        public IActionResult GetDebugInfo()
        {
            // VULNÉRABLE: Expose des informations sensibles sur l'environnement
            return Ok(new
            {
                environment = _env.EnvironmentName,
                applicationName = _env.ApplicationName,
                contentRoot = _env.ContentRootPath,
                webRoot = _env.WebRootPath,
                isDevelopment = _env.IsDevelopment(),
                machineName = Environment.MachineName,
                osVersion = Environment.OSVersion.ToString(),
                processId = Environment.ProcessId,
                is64BitProcess = Environment.Is64BitProcess,
                processorCount = Environment.ProcessorCount,
                userName = Environment.UserName,
                userDomainName = Environment.UserDomainName,
                workingSet = Environment.WorkingSet,
                version = Environment.Version.ToString(),
                systemDirectory = Environment.SystemDirectory,
                currentDirectory = Environment.CurrentDirectory,
                commandLine = Environment.CommandLine,
                // VULNÉRABLE: Variables d'environnement exposées
                environmentVariables = Environment.GetEnvironmentVariables()
            });
        }

        /// <summary>
        /// VULNÉRABLE: Stack trace complet exposé
        /// </summary>
        [HttpGet("debug/error-test")]
        public IActionResult TriggerError()
        {
            try
            {
                throw new Exception("Test exception with sensitive data in stack trace");
            }
            catch (Exception ex)
            {
                // VULNÉRABLE: Stack trace complet retourné au client
                return StatusCode(500, new
                {
                    error = ex.Message,
                    stackTrace = ex.StackTrace,
                    source = ex.Source,
                    targetSite = ex.TargetSite?.ToString(),
                    data = ex.Data,
                    innerException = ex.InnerException?.ToString()
                });
            }
        }

        /// <summary>
        /// VULNÉRABLE: Endpoints de métrique sans authentification
        /// </summary>
        [HttpGet("metrics")]
        public IActionResult GetMetrics()
        {
            // VULNÉRABLE: Métriques sensibles exposées
            var process = Process.GetCurrentProcess();

            return Ok(new
            {
                memory = new
                {
                    workingSet = process.WorkingSet64,
                    privateMemory = process.PrivateMemorySize64,
                    virtualMemory = process.VirtualMemorySize64,
                    pagedMemory = process.PagedMemorySize64,
                    gcTotalMemory = GC.GetTotalMemory(false),
                    gcCollectionCounts = new
                    {
                        gen0 = GC.CollectionCount(0),
                        gen1 = GC.CollectionCount(1),
                        gen2 = GC.CollectionCount(2)
                    }
                },
                cpu = new
                {
                    totalProcessorTime = process.TotalProcessorTime,
                    userProcessorTime = process.UserProcessorTime,
                    privilegedProcessorTime = process.PrivilegedProcessorTime
                },
                threads = process.Threads.Count,
                handles = process.HandleCount,
                startTime = process.StartTime,
                // VULNÉRABLE: Informations sur les modules chargés
                modules = process.Modules.Cast<ProcessModule>().Select(m => new
                {
                    moduleName = m.ModuleName,
                    fileName = m.FileName,
                    fileVersion = m.FileVersionInfo.FileVersion,
                    productVersion = m.FileVersionInfo.ProductVersion
                })
            });
        }

        #endregion

        #region Configuration exposée

        /// <summary>
        /// VULNÉRABLE: Configuration complète exposée
        /// </summary>
        [HttpGet("settings/all")]
        public IActionResult GetAllSettings()
        {
            // VULNÉRABLE: Expose toute la configuration incluant les secrets
            var settings = new Dictionary<string, string>();

            foreach (var kvp in _configuration.AsEnumerable())
            {
                settings[kvp.Key] = kvp.Value ?? "null";
            }

            var configRoot = _configuration as IConfigurationRoot;

            return Ok(new
            {
                configuration = settings,
                connectionStrings = GetConnectionStrings(),
                providers = configRoot?.Providers.Select(p => p.GetType().Name).ToList()
            });
        }


        /// <summary>
        /// VULNÉRABLE: Permet de modifier la configuration à chaud
        /// </summary>
        [HttpPost("settings/update")]
        public IActionResult UpdateSettings([FromBody] Dictionary<string, string> settings)
        {
            // VULNÉRABLE: Modification de configuration sans authentification
            foreach (var setting in settings)
            {
                _configuration[setting.Key] = setting.Value;
            }

            return Ok(new
            {
                message = "Settings updated",
                updatedCount = settings.Count,
                // VULNÉRABLE: Confirme les valeurs mises à jour
                updatedSettings = settings
            });
        }

        #endregion

        #region Headers de sécurité manquants

        /// <summary>
        /// VULNÉRABLE: Endpoint sans headers de sécurité appropriés
        /// </summary>
        [HttpGet("insecure-response")]
        public IActionResult GetInsecureResponse()
        {
            // VULNÉRABLE: Pas de headers de sécurité
            // Manque: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, etc.

            Response.Headers.Remove("X-Content-Type-Options");
            Response.Headers.Remove("X-Frame-Options");
            Response.Headers.Remove("X-XSS-Protection");
            Response.Headers.Remove("Strict-Transport-Security");
            Response.Headers.Remove("Content-Security-Policy");
            Response.Headers.Remove("Referrer-Policy");

            // VULNÉRABLE: Ajoute des headers qui révèlent des informations
            Response.Headers.Add("Server", "Net8-WebApi-InsecureApp/1.0");
            Response.Headers.Add("X-Powered-By", "ASP.NET Core 8.0");
            Response.Headers.Add("X-AspNet-Version", "8.0.0");
            Response.Headers.Add("X-Debug-Token", Guid.NewGuid().ToString());

            return Ok(new
            {
                message = "Response without security headers",
                timestamp = DateTime.UtcNow
            });
        }

        #endregion

        #region CORS mal configuré

        /// <summary>
        /// VULNÉRABLE: Test de configuration CORS
        /// </summary>
        [HttpOptions("cors-test")]
        public IActionResult TestCors()
        {
            // VULNÉRABLE: CORS complètement ouvert (configuré dans Program.cs)
            // Accepte toutes les origines, méthodes et headers

            return Ok(new
            {
                message = "CORS is misconfigured",
                allowedOrigins = "*",
                allowedMethods = "*",
                allowedHeaders = "*",
                allowCredentials = true // TRÈS DANGEREUX avec Origin: *
            });
        }

        #endregion

        #region Logs et traces sensibles

        /// <summary>
        /// VULNÉRABLE: Accès aux logs sans authentification
        /// </summary>
        [HttpGet("logs/view")]
        public IActionResult ViewLogs([FromQuery] int lines = 100)
        {
            // VULNÉRABLE: Expose les logs de l'application
            var logPath = Path.Combine(_env.ContentRootPath, "logs");
            var logs = new List<string>();

            if (Directory.Exists(logPath))
            {
                var logFiles = Directory.GetFiles(logPath, "*.txt")
                    .OrderByDescending(f => System.IO.File.GetLastWriteTime(f))
                    .Take(5);

                foreach (var file in logFiles)
                {
                    try
                    {
                        var content = System.IO.File.ReadLines(file)
                            .TakeLast(lines)
                            .ToList();
                        logs.AddRange(content);
                    }
                    catch { }
                }
            }

            // On assemble tous les logs dans un seul fichier texte à télécharger
            var logText = string.Join(Environment.NewLine, logs);
            var bytes = System.Text.Encoding.UTF8.GetBytes(logText);
            return this.File(bytes, "text/plain", "logs.txt");
        }

        /// <summary>
        /// VULNÉRABLE: Trace de requêtes HTTP
        /// </summary>
        [HttpGet("trace/requests")]
        public IActionResult GetRequestTrace()
        {
            // VULNÉRABLE: Expose l'historique des requêtes
            return Ok(new
            {
                currentRequest = new
                {
                    method = Request.Method,
                    path = Request.Path,
                    queryString = Request.QueryString.ToString(),
                    headers = Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString()),
                    cookies = Request.Cookies.ToDictionary(c => c.Key, c => c.Value),
                    host = Request.Host.ToString(),
                    scheme = Request.Scheme,
                    protocol = Request.Protocol,
                    isHttps = Request.IsHttps,
                    remoteIp = HttpContext.Connection.RemoteIpAddress?.ToString(),
                    localIp = HttpContext.Connection.LocalIpAddress?.ToString()
                },
                // VULNÉRABLE: Historique fictif mais révélateur
                recentRequests = GenerateFakeRequestHistory()
            });
        }

        #endregion

        #region Base de données mal configurée

        /// <summary>
        /// VULNÉRABLE: Informations de connexion à la base de données exposées
        /// </summary>
        [HttpGet("database/info")]
        public async Task<IActionResult> GetDatabaseInfo()
        {
            // VULNÉRABLE: Expose la configuration de la base de données
            var dbConnection = _context.Database.GetDbConnection();

            return Ok(new
            {
                provider = _context.Database.ProviderName,
                connectionString = dbConnection.ConnectionString, // TRÈS DANGEREUX!
                database = dbConnection.Database,
                dataSource = dbConnection.DataSource,
                serverVersion = dbConnection.ServerVersion,
                connectionTimeout = dbConnection.ConnectionTimeout,
                canCreateCommand = dbConnection.State,
                // VULNÉRABLE: Requêtes SQL directes
                tableCount = await _context.Database.ExecuteSqlRawAsync("SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES"),
                pendingMigrations = await _context.Database.GetPendingMigrationsAsync()
            });
        }

        /// <summary>
        /// VULNÉRABLE: Exécution de requêtes SQL arbitraires
        /// </summary>
        [HttpPost("database/query")]
        public async Task<IActionResult> ExecuteQuery([FromBody] SqlQueryRequest request)
        {
            try
            {
                // VULNÉRABLE: Exécution directe de SQL sans validation
                var result = await _context.Database.ExecuteSqlRawAsync(request.Query);

                return Ok(new
                {
                    message = "Query executed",
                    affectedRows = result,
                    query = request.Query // VULNÉRABLE: Echo de la requête
                });
            }
            catch (Exception ex)
            {
                // VULNÉRABLE: Message d'erreur SQL complet
                return BadRequest(new
                {
                    error = "Query failed",
                    message = ex.Message,
                    query = request.Query
                });
            }
        }

        #endregion

        #region API Keys et secrets exposés

        /// <summary>
        /// VULNÉRABLE: Génération d'API key faible
        /// </summary>
        [HttpPost("apikey/generate")]
        public IActionResult GenerateApiKey([FromQuery] string? prefix = "sk")
        {
            // VULNÉRABLE: Génération prévisible
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var random = new Random((int)timestamp);
            var keyPart = random.Next(100000, 999999);

            var apiKey = $"{prefix}_{timestamp}_{keyPart}";

            return Ok(new
            {
                apiKey = apiKey,
                // VULNÉRABLE: Expose l'algorithme de génération
                algorithm = "timestamp + random(100000-999999)",
                seed = timestamp,
                createdAt = DateTime.UtcNow
            });
        }

        /// <summary>
        /// VULNÉRABLE: Liste toutes les clés API
        /// </summary>
        [HttpGet("apikey/list")]
        public async Task<IActionResult> ListAllApiKeys()
        {
            // VULNÉRABLE: Expose toutes les clés API
            var apiKeys = await _context.Set<UserApiKey>()
                .Include(k => k.User)
                .Select(k => new
                {
                    k.Id,
                    k.Key, // VULNÉRABLE: Clé complète exposée
                    k.Name,
                    k.UserId,
                    UserEmail = k.User.Email,
                    k.CreatedAt,
                    k.LastUsedAt,
                    k.ExpiresAt
                })
                .ToListAsync();

            return Ok(new
            {
                totalKeys = apiKeys.Count,
                keys = apiKeys,
                // VULNÉRABLE: Statistiques révélatrices
                statistics = new
                {
                    activeKeys = apiKeys.Count(k => k.ExpiresAt == null || k.ExpiresAt > DateTime.UtcNow),
                    expiredKeys = apiKeys.Count(k => k.ExpiresAt != null && k.ExpiresAt <= DateTime.UtcNow),
                    neverUsedKeys = apiKeys.Count(k => k.LastUsedAt == null)
                }
            });
        }

        #endregion

        #region Méthodes HTTP non sécurisées

        /// <summary>
        /// VULNÉRABLE: TRACE method activée
        /// </summary>
        [AcceptVerbs("TRACE")]
        [Route("trace-enabled")]
        public IActionResult TraceMethod()
        {
            // VULNÉRABLE: TRACE peut exposer des informations sensibles
            return Ok(new
            {
                method = "TRACE",
                headers = Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString()),
                body = "TRACE method should be disabled"
            });
        }

        /// <summary>
        /// VULNÉRABLE: OPTIONS révèle trop d'informations
        /// </summary>
        [HttpOptions("options-verbose")]
        public IActionResult OptionsVerbose()
        {
            // VULNÉRABLE: Expose toutes les méthodes disponibles
            Response.Headers.Add("Allow", "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, TRACE");
            Response.Headers.Add("X-Supported-Methods", "ALL");
            Response.Headers.Add("X-API-Version", "1.0.0-vulnerable");

            return Ok(new
            {
                supportedMethods = new[] { "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE" },
                endpoints = GetAllEndpoints(),
                deprecated = new[] { "/api/v1/*", "/api/legacy/*" },
                upcoming = new[] { "/api/v3/*" }
            });
        }

        #endregion

        #region Helpers

        private Dictionary<string, string> GetConnectionStrings()
        {
            var connectionStrings = new Dictionary<string, string>();
            var section = _configuration.GetSection("ConnectionStrings");

            foreach (var child in section.GetChildren())
            {
                connectionStrings[child.Key] = child.Value ?? "";
            }

            return connectionStrings;
        }

        private List<object> GenerateFakeRequestHistory()
        {
            return new List<object>
            {
                new { timestamp = DateTime.UtcNow.AddMinutes(-5), path = "/api/users/1", method = "GET", ip = "192.168.1.100" },
                new { timestamp = DateTime.UtcNow.AddMinutes(-4), path = "/api/auth/login", method = "POST", ip = "10.0.0.50" },
                new { timestamp = DateTime.UtcNow.AddMinutes(-3), path = "/api/admin/users", method = "DELETE", ip = "172.16.0.10" }
            };
        }

        private List<string> GetAllEndpoints()
        {
            // Simule la liste de tous les endpoints (vulnérable)
            return new List<string>
            {
                "/api/config/debug/info",
                "/api/config/settings/all",
                "/api/config/database/query",
                "/api/admin/shutdown",
                "/api/admin/restart"
            };
        }

        #endregion
    }

    // ===== MODÈLES DE REQUÊTE =====

    public class SqlQueryRequest
    {
        public string Query { get; set; } = string.Empty;
    }
}