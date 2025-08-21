using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Net8_WebApi_InsecureApp.Data;
using Net8_WebApi_InsecureApp.Models;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;

namespace Net8_WebApi_InsecureApp.Controllers
{
    /// <summary>
    /// API7:2023 - Server Side Request Forgery (SSRF) (VULNÉRABLE)
    /// Ce contrôleur démontre les vulnérabilités SSRF permettant à un attaquant
    /// de faire des requêtes depuis le serveur vers des ressources internes/externes
    /// </summary>
    [ApiController]
    [Route("api/ssrf")]
    public class Api07SsrfController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly ILogger<Api07SsrfController> _logger;
        private readonly HttpClient _httpClient;
        private readonly IWebHostEnvironment _env;

        public Api07SsrfController(
            AppDbContext context,
            ILogger<Api07SsrfController> logger,
            IHttpClientFactory httpClientFactory,
            IWebHostEnvironment env)
        {
            _context = context;
            _logger = logger;
            _httpClient = httpClientFactory.CreateClient();
            _env = env;

            // VULNÉRABLE: Timeout très long permettant des attaques de déni de service
            _httpClient.Timeout = TimeSpan.FromMinutes(5);
        }

        #region Import d'images depuis URL

        /// <summary>
        /// VULNÉRABLE: Import d'image depuis URL arbitraire
        /// </summary>
        [HttpPost("image/import")]
        public async Task<IActionResult> ImportImageFromUrl([FromBody] ImageImportRequest request)
        {
            try
            {
                // VULNÉRABLE: Pas de validation de l'URL
                // VULNÉRABLE: Pas de vérification du schéma (file://, gopher://, etc.)
                // VULNÉRABLE: Pas de vérification de l'hôte (localhost, IP internes)

                var response = await _httpClient.GetAsync(request.ImageUrl);
                var imageBytes = await response.Content.ReadAsByteArrayAsync();

                // VULNÉRABLE: Pas de validation du type de contenu
                var fileName = $"imported_{Guid.NewGuid()}.jpg";
                var filePath = Path.Combine(_env.WebRootPath, "uploads", fileName);

                await System.IO.File.WriteAllBytesAsync(filePath, imageBytes);

                // VULNÉRABLE: Exposition d'informations sur l'infrastructure
                return Ok(new
                {
                    message = "Image imported successfully",
                    fileName = fileName,
                    size = imageBytes.Length,
                    serverInfo = new
                    {
                        machineName = Environment.MachineName,
                        osVersion = Environment.OSVersion.ToString(),
                        processorCount = Environment.ProcessorCount
                    }
                });
            }
            catch (Exception ex)
            {
                // VULNÉRABLE: Message d'erreur détaillé révélant la structure interne
                return BadRequest(new
                {
                    error = "Failed to import image",
                    details = ex.Message,
                    stackTrace = ex.StackTrace,
                    innerException = ex.InnerException?.Message
                });
            }
        }

        #endregion

        #region Webhook et callbacks

        /// <summary>
        /// VULNÉRABLE: Configuration de webhook sans validation
        /// </summary>
        [HttpPost("webhook/configure")]
        public async Task<IActionResult> ConfigureWebhook([FromBody] WebhookConfigRequest request)
        {
            // VULNÉRABLE: URL de webhook non validée
            var testPayload = new
            {
                eventType = "webhook.test",
                timestamp = DateTime.UtcNow,
                data = new
                {
                    message = "Webhook configuration test",
                    userId = request.UserId
                }
            };

            try
            {
                // VULNÉRABLE: Requête vers URL arbitraire
                var content = new StringContent(
                    JsonSerializer.Serialize(testPayload),
                    Encoding.UTF8,
                    "application/json"
                );

                var response = await _httpClient.PostAsync(request.WebhookUrl, content);
                var responseBody = await response.Content.ReadAsStringAsync();

                // VULNÉRABLE: Retour du contenu de la réponse (peut contenir des données internes)
                return Ok(new
                {
                    message = "Webhook configured and tested",
                    webhookUrl = request.WebhookUrl,
                    testResult = new
                    {
                        statusCode = (int)response.StatusCode,
                        headers = response.Headers.ToString(),
                        body = responseBody,
                        responseTime = response.Headers.Date
                    }
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        /// <summary>
        /// VULNÉRABLE: Callback URL pour OAuth/SSO
        /// </summary>
        [HttpPost("oauth/callback-test")]
        public async Task<IActionResult> TestOAuthCallback([FromBody] OAuthCallbackTestRequest request)
        {
            // VULNÉRABLE: Redirection vers URL arbitraire avec token
            var callbackUrl = $"{request.CallbackUrl}?code={Guid.NewGuid()}&state={request.State}";

            var response = await _httpClient.GetAsync(callbackUrl);
            var content = await response.Content.ReadAsStringAsync();

            return Ok(new
            {
                message = "Callback tested",
                callbackResponse = content,
                headers = response.Headers.ToDictionary(h => h.Key, h => string.Join(", ", h.Value))
            });
        }

        #endregion

        #region Proxy et fetch de contenu

        /// <summary>
        /// VULNÉRABLE: Proxy ouvert vers n'importe quelle URL
        /// </summary>
        [HttpGet("proxy")]
        public async Task<IActionResult> ProxyRequest([FromQuery] string url)
        {
            try
            {
                // VULNÉRABLE: Aucune validation de l'URL
                // Permet d'accéder à des ressources internes comme:
                // - http://localhost/admin
                // - http://192.168.1.1/
                // - file:///etc/passwd
                // - gopher://internal-server

                var response = await _httpClient.GetAsync(url);
                var content = await response.Content.ReadAsStringAsync();

                // VULNÉRABLE: Retourne le contenu complet
                return Content(content, response.Content.Headers.ContentType?.ToString() ?? "text/plain");
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        /// <summary>
        /// VULNÉRABLE: Récupération de métadonnées d'URL
        /// </summary>
        [HttpPost("metadata/fetch")]
        public async Task<IActionResult> FetchUrlMetadata([FromBody] MetadataFetchRequest request)
        {
            var results = new List<object>();

            foreach (var url in request.Urls)
            {
                try
                {
                    // VULNÉRABLE: Requêtes multiples vers URLs arbitraires
                    var response = await _httpClient.GetAsync(url);
                    var content = await response.Content.ReadAsStringAsync();

                    // VULNÉRABLE: Parse HTML/XML sans validation
                    var title = ExtractTitle(content);
                    var metadata = ExtractMetaTags(content);

                    results.Add(new
                    {
                        url = url,
                        title = title,
                        metadata = metadata,
                        contentLength = content.Length,
                        serverHeaders = response.Headers.Server?.ToString(),
                        // VULNÉRABLE: Peut révéler des informations sensibles
                        rawHeaders = response.Headers.ToDictionary(h => h.Key, h => string.Join(", ", h.Value))
                    });
                }
                catch (Exception ex)
                {
                    results.Add(new
                    {
                        url = url,
                        error = ex.Message
                    });
                }
            }

            return Ok(results);
        }

        #endregion

        #region Intégrations PDF et documents

        /// <summary>
        /// VULNÉRABLE: Génération de PDF avec contenu externe
        /// </summary>
        [HttpPost("pdf/generate")]
        public async Task<IActionResult> GeneratePdfFromUrl([FromBody] PdfGenerationRequest request)
        {
            try
            {
                // VULNÉRABLE: Inclusion de ressources externes dans le PDF
                var htmlContent = await _httpClient.GetStringAsync(request.SourceUrl);

                // VULNÉRABLE: Injection possible via le contenu HTML
                var pdfHtml = $@"
                    <html>
                    <head>
                        <title>{request.Title}</title>
                    </head>
                    <body>
                        <h1>{request.Title}</h1>
                        <div>{htmlContent}</div>
                        <img src='{request.LogoUrl}' />
                        <iframe src='{request.EmbedUrl}'></iframe>
                    </body>
                    </html>";

                // Simulation de génération PDF (vulnérable)
                var pdfBytes = Encoding.UTF8.GetBytes(pdfHtml); // Simulé

                return File(pdfBytes, "application/pdf", "generated.pdf");
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        #endregion

        #region Validation d'URL et DNS

        /// <summary>
        /// VULNÉRABLE: Résolution DNS et validation d'URL
        /// </summary>
        [HttpPost("url/validate")]
        public async Task<IActionResult> ValidateUrl([FromBody] UrlValidationRequest request)
        {
            try
            {
                // VULNÉRABLE: Résolution DNS pouvant être utilisée pour scanner le réseau interne
                var uri = new Uri(request.Url);
                var hostEntry = await Dns.GetHostEntryAsync(uri.Host);

                // VULNÉRABLE: Révèle des informations sur le réseau interne
                var ipAddresses = hostEntry.AddressList.Select(ip => ip.ToString()).ToList();

                // VULNÉRABLE: Tentative de connexion pour vérifier l'accessibilité
                var tcpClient = new System.Net.Sockets.TcpClient();
                var isReachable = false;

                try
                {
                    await tcpClient.ConnectAsync(uri.Host, uri.Port == -1 ? 80 : uri.Port);
                    isReachable = tcpClient.Connected;
                    tcpClient.Close();
                }
                catch
                {
                    // Ignore
                }

                return Ok(new
                {
                    url = request.Url,
                    host = uri.Host,
                    ipAddresses = ipAddresses,
                    isReachable = isReachable,
                    port = uri.Port,
                    // VULNÉRABLE: renvoi des
                    aliases = hostEntry.Aliases,
                    hostName = hostEntry.HostName
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new
                {
                    error = "URL validation failed",
                    details = ex.Message
                });
            }
        }

        #endregion

        #region Import/Export de données

        /// <summary>
        /// VULNÉRABLE: Import de données depuis URL externe
        /// </summary>
        [HttpPost("data/import")]
        public async Task<IActionResult> ImportDataFromUrl([FromBody] DataImportRequest request)
        {
            try
            {
                // VULNÉRABLE: Téléchargement de fichier depuis URL arbitraire
                var response = await _httpClient.GetAsync(request.DataUrl);
                var data = await response.Content.ReadAsStringAsync();

                // VULNÉRABLE: Désérialisation sans validation
                dynamic jsonData = JsonSerializer.Deserialize<dynamic>(data);

                // VULNÉRABLE: Exécution de requêtes basées sur les données importées
                if (request.AutoProcess)
                {
                    // Simule le traitement automatique des données
                    var processedCount = 0;

                    // Traitement vulnérable des données...
                    processedCount = new Random().Next(10, 100);

                    return Ok(new
                    {
                        message = "Data imported and processed",
                        source = request.DataUrl,
                        recordsProcessed = processedCount,
                        serverTime = DateTime.Now,
                        serverName = Environment.MachineName
                    });
                }

                return Ok(new
                {
                    message = "Data imported",
                    dataSize = data.Length,
                    preview = data.Substring(0, Math.Min(1000, data.Length))
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message, stackTrace = ex.StackTrace });
            }
        }

        /// <summary>
        /// VULNÉRABLE: Export vers URL externe
        /// </summary>
        [HttpPost("data/export")]
        public async Task<IActionResult> ExportDataToUrl([FromBody] DataExportRequest request)
        {
            try
            {
                // VULNÉRABLE: Récupération de données sensibles
                var users = await _context.Users.ToListAsync();
                var exportData = JsonSerializer.Serialize(users);

                // VULNÉRABLE: Envoi de données vers URL arbitraire
                var content = new StringContent(exportData, Encoding.UTF8, "application/json");
                var response = await _httpClient.PostAsync(request.DestinationUrl, content);

                return Ok(new
                {
                    message = "Data exported",
                    destination = request.DestinationUrl,
                    recordCount = users.Count,
                    responseStatus = response.StatusCode,
                    responseBody = await response.Content.ReadAsStringAsync()
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        #endregion

        #region Services internes et API Gateway

        /// <summary>
        /// VULNÉRABLE: Appel de services internes via paramètres utilisateur
        /// </summary>
        [HttpPost("internal/service-call")]
        public async Task<IActionResult> CallInternalService([FromBody] InternalServiceRequest request)
        {
            // VULNÉRABLE: Construction d'URL interne basée sur l'entrée utilisateur
            var internalUrl = $"http://{request.ServiceName}.internal.local:{request.Port}/{request.Endpoint}";

            try
            {
                var response = await _httpClient.GetAsync(internalUrl);
                var content = await response.Content.ReadAsStringAsync();

                // VULNÉRABLE: Expose la structure interne du réseau
                return Ok(new
                {
                    service = request.ServiceName,
                    endpoint = request.Endpoint,
                    response = content,
                    internalUrl = internalUrl,
                    networkInfo = new
                    {
                        dnsServers = string.Join(", ", GetDnsServers()),
                        internalIps = GetInternalIpAddresses()
                    }
                });
            }
            catch (Exception ex)
            {
                // VULNÉRABLE: Révèle des détails sur l'infrastructure interne
                return BadRequest(new
                {
                    error = $"Failed to reach internal service: {request.ServiceName}",
                    details = ex.Message,
                    attemptedUrl = internalUrl
                });
            }
        }

        #endregion

        #region Helpers vulnérables

        private string ExtractTitle(string html)
        {
            var match = Regex.Match(html, @"<title>(.*?)</title>", RegexOptions.IgnoreCase);
            return match.Success ? match.Groups[1].Value : "No title";
        }

        private Dictionary<string, string> ExtractMetaTags(string html)
        {
            var metaTags = new Dictionary<string, string>();
            var matches = Regex.Matches(html, @"<meta\s+name=[""']([^""']+)[""']\s+content=[""']([^""']+)[""']", RegexOptions.IgnoreCase);

            foreach (Match match in matches)
            {
                metaTags[match.Groups[1].Value] = match.Groups[2].Value;
            }

            return metaTags;
        }

        private List<string> GetDnsServers()
        {
            // Simule la récupération des serveurs DNS (vulnérable)
            return new List<string> { "10.0.0.1", "10.0.0.2", "8.8.8.8" };
        }

        private List<string> GetInternalIpAddresses()
        {
            // Simule la récupération des IPs internes (vulnérable)
            return new List<string> { "192.168.1.100", "172.16.0.50", "10.0.0.100" };
        }

        #endregion
    }

    // ===== MODÈLES DE REQUÊTE =====

    public class ImageImportRequest
    {
        public string ImageUrl { get; set; } = string.Empty;
        public string? Description { get; set; }
    }

    public class WebhookConfigRequest
    {
        public int UserId { get; set; }
        public string WebhookUrl { get; set; } = string.Empty;
        public List<string> Events { get; set; } = new();
    }

    public class OAuthCallbackTestRequest
    {
        public string CallbackUrl { get; set; } = string.Empty;
        public string State { get; set; } = string.Empty;
    }

    public class MetadataFetchRequest
    {
        public List<string> Urls { get; set; } = new();
    }

    public class PdfGenerationRequest
    {
        public string SourceUrl { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string LogoUrl { get; set; } = string.Empty;
        public string EmbedUrl { get; set; } = string.Empty;
    }

    public class UrlValidationRequest
    {
        public string Url { get; set; } = string.Empty;
    }

    public class DataImportRequest
    {
        public string DataUrl { get; set; } = string.Empty;
        public bool AutoProcess { get; set; }
    }

    public class DataExportRequest
    {
        public string DestinationUrl { get; set; } = string.Empty;
        public string DataType { get; set; } = string.Empty;
    }

    public class InternalServiceRequest
    {
        public string ServiceName { get; set; } = string.Empty;
        public int Port { get; set; } = 80;
        public string Endpoint { get; set; } = string.Empty;
    }
}