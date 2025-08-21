using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Net8_WebApi_InsecureApp.Data;
using Net8_WebApi_InsecureApp.Models;
using System.Net.Http.Headers;
using System.ServiceModel.Syndication;
using System.Text;
using System.Text.Json;
using System.Xml;

namespace Net8_WebApi_InsecureApp.Controllers
{
    /// <summary>
    /// Contrôleur démontrant la vulnérabilité API10:2023 - Unsafe Consumption of APIs
    /// Ce contrôleur contient intentionnellement des vulnérabilités pour des fins éducatives
    /// NE PAS UTILISER EN PRODUCTION
    /// </summary>
    [ApiController]
    [Route("api/external")]
    public class Api10UnsafeConsumptionController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<Api10UnsafeConsumptionController> _logger;
        private readonly IConfiguration _configuration;
        private readonly IWebHostEnvironment _environment;
        private static readonly HttpClient _unsafeClient = new HttpClient(new HttpClientHandler
        {
            // VULNÉRABLE: Désactive la validation SSL
            ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true,
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 10
        });

        public Api10UnsafeConsumptionController(
            AppDbContext context,
            IHttpClientFactory httpClientFactory,
            IConfiguration configuration,
            IWebHostEnvironment environment,
            ILogger<Api10UnsafeConsumptionController> logger)
        {
            _context = context;
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
            _environment = environment;
            _logger = logger;
        }


        #region Weather API - Injection de contenu non validé

        /// <summary>
        /// VULNÉRABLE: Consomme une API météo sans validation
        /// </summary>
        [HttpGet("weather/{location}")]
        public async Task<IActionResult> GetWeather(string location)
        {
            try
            {
                // VULNÉRABLE: Injection possible dans l'URL
                var url = $"http://api.weather-provider.com/v1/current?location={location}&apikey=demo";

                // VULNÉRABLE: Pas de timeout défini
                var response = await _unsafeClient.GetAsync(url);
                var content = await response.Content.ReadAsStringAsync();

                // VULNÉRABLE: Désérialisation directe sans validation
                dynamic weatherData = JsonSerializer.Deserialize<dynamic>(content)!;

                // VULNÉRABLE: Retourne les données brutes de l'API externe
                return Ok(new WeatherData
                {
                    Location = location,
                    Temperature = weatherData.GetProperty("temperature").GetDecimal(),
                    Description = weatherData.GetProperty("description").GetString(),
                    RawData = JsonSerializer.Deserialize<Dictionary<string, object>>(content)!,
                    ProviderResponse = content // VULNÉRABLE: Expose la réponse complète
                });
            }
            catch (Exception ex)
            {
                // VULNÉRABLE: Expose les détails de l'erreur
                return BadRequest(new { error = ex.Message, stackTrace = ex.StackTrace });
            }
        }

        #endregion

        #region Payment Processing - Trust sans validation

        /// <summary>
        /// VULNÉRABLE: Traite des paiements via une API tierce non sécurisée
        /// </summary>
        [HttpPost("payment/process")]
        public async Task<IActionResult> ProcessPayment([FromBody] PaymentRequest request)
        {
            // VULNÉRABLE: Log les données sensibles
            _logger.LogInformation($"Processing payment for card: {request.CardNumber}");

            var paymentData = new
            {
                card = request.CardNumber,
                holder = request.CardHolder,
                amount = request.Amount,
                currency = request.Currency,
                // VULNÉRABLE: Inclut toutes les métadonnées sans validation
                metadata = request.Metadata
            };

            // VULNÉRABLE: Utilise HTTP au lieu de HTTPS
            var paymentUrl = "http://payment-processor.external/api/charge";
            var content = new StringContent(JsonSerializer.Serialize(paymentData), Encoding.UTF8, "application/json");

            var response = await _unsafeClient.PostAsync(paymentUrl, content);
            var responseContent = await response.Content.ReadAsStringAsync();

            // VULNÉRABLE: Trust aveugle de la réponse
            if (response.IsSuccessStatusCode)
            {
                var result = JsonSerializer.Deserialize<Dictionary<string, object>>(responseContent);

                // VULNÉRABLE: Stocke les données sensibles
                await _context.Set<PaymentResponse>().AddAsync(new PaymentResponse
                {
                    TransactionId = result?["transactionId"]?.ToString() ?? "unknown",
                    Status = "success",
                    ProcessorResponse = result!,
                    RawResponse = responseContent
                });
                await _context.SaveChangesAsync();

                return Ok(result);
            }

            // VULNÉRABLE: Retourne l'erreur brute du processeur
            return BadRequest(new { error = responseContent });
        }

        #endregion

        #region User Verification - Données sensibles exposées

        /// <summary>
        /// VULNÉRABLE: Vérifie les utilisateurs via une API tierce
        /// </summary>
        [HttpPost("verify/user")]
        public async Task<IActionResult> VerifyUser([FromBody] UserVerification request)
        {
            // VULNÉRABLE: Envoie des données sensibles à un service externe
            var verificationData = new
            {
                email = request.Email,
                ssn = request.SocialSecurityNumber, // VULNÉRABLE: SSN en clair
                phone = request.Phone,
                additionalData = request.AdditionalData
            };

            var apiConfig = await _context.Set<ExternalApiConfig>()
                .FirstOrDefaultAsync(c => c.Name == "UserVerification");

            if (apiConfig == null)
            {
                // VULNÉRABLE: Utilise une URL par défaut non sécurisée
                apiConfig = new ExternalApiConfig
                {
                    BaseUrl = "http://verification.untrusted-api.com",
                    ValidateSsl = false
                };
            }

            var url = $"{apiConfig.BaseUrl}/verify";
            var content = new StringContent(JsonSerializer.Serialize(verificationData), Encoding.UTF8, "application/json");

            // VULNÉRABLE: Pas de validation du certificat SSL
            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
            };

            using var client = new HttpClient(handler);
            var response = await client.PostAsync(url, content);
            var responseContent = await response.Content.ReadAsStringAsync();
            //Problème: Lit toute la réponse en mémoire Risques:
            //OutOfMemoryException avec grandes réponses
            //DoS par épuisement mémoire


            # region version corrigée
            // Configuration sécurisée du HttpClient
            var handler2 = new HttpClientHandler
            {
                // CORRECTION 1: Validation SSL activée (comportement par défaut)
                // ServerCertificateCustomValidationCallback reste null
            };

            using var client2 = new HttpClient(handler)
            {
                // CORRECTION 3: Timeout approprié
                Timeout = TimeSpan.FromSeconds(30)
            };

            // CORRECTION 2: Validation de l'URL
            if (!IsUrlAllowed(url))
            {
                throw new InvalidOperationException("URL non autorisée");
            }

            // CORRECTION 4: Limite de taille pour la réponse
            client.MaxResponseContentBufferSize = 10 * 1024 * 1024; // 10 MB max

            var response2 = await client.PostAsync(url, content);

            // Vérifier la taille avant de lire
            if (response.Content.Headers.ContentLength > 10 * 1024 * 1024)
            {
                throw new InvalidOperationException("Réponse trop grande");
            }

            var responseContent2 = await response.Content.ReadAsStringAsync();

            /// Points clés de la correction :
            // Validation SSL/ TLS active
            // Liste blanche des URLs
            // HTTPS uniquement
            // Timeout configuré
            // Limite de taille des réponses
            // Blocage des IPs internes

            #endregion


            // VULNÉRABLE: Parse et retourne directement la réponse
            var verificationResult = JsonSerializer.Deserialize<VerificationResponse>(responseContent);
            verificationResult!.RawProviderData = responseContent;

            return Ok(verificationResult);
        }

        // Méthode de validation d'URL
        private bool IsUrlAllowed(string url)
        {
            // Liste blanche des domaines autorisés
            var allowedHosts = new[] { "api.trusted.com", "storage.mycompany.com" };

            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
                return false;

            // Seulement HTTPS
            if (uri.Scheme != "https")
                return false;

            // Vérifier la liste blanche
            if (!allowedHosts.Contains(uri.Host))
                return false;

            // Bloquer les IPs privées
            if (IsPrivateIP(uri.Host))
                return false;

            return true;
        }

        private bool IsPrivateIP(string host)
        {
            throw new NotImplementedException();
        }

        #endregion

        #region Proxy - Redirection non contrôlée

        /// <summary>
        /// VULNÉRABLE: Proxy vers n'importe quelle URL
        /// </summary>
        [HttpPost("proxy")]
        public async Task<IActionResult> ProxyRequest([FromBody] ProxyRequest request)
        {
            try
            {
                // VULNÉRABLE: Permet de proxy vers n'importe quelle URL
                var httpRequest = new HttpRequestMessage(
                    new HttpMethod(request.Method),
                    request.TargetUrl);

                // VULNÉRABLE: Copie tous les headers sans validation
                foreach (var header in request.Headers)
                {
                    httpRequest.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }

                if (!string.IsNullOrEmpty(request.Body))
                {
                    httpRequest.Content = new StringContent(request.Body, Encoding.UTF8, "application/json");
                }

                // VULNÉRABLE: Suit les redirections automatiquement
                var response = await _unsafeClient.SendAsync(httpRequest);
                var responseContent = await response.Content.ReadAsStringAsync();

                // VULNÉRABLE: Retourne la réponse brute
                return Ok(new
                {
                    statusCode = (int)response.StatusCode,
                    headers = response.Headers.ToDictionary(h => h.Key, h => string.Join(", ", h.Value)),
                    body = responseContent,
                    finalUrl = response.RequestMessage?.RequestUri?.ToString()
                });
            }
            catch (Exception ex)
            {
                // VULNÉRABLE: Expose les détails de l'exception
                return StatusCode(500, new { error = ex.ToString() });
            }
        }

        #endregion

        #region RSS/XML - Parsing non sécurisé

        /// <summary>
        /// VULNÉRABLE: Agrège des flux RSS sans validation
        /// </summary>
        [HttpPost("rss/aggregate")]
        public async Task<IActionResult> AggregateRssFeeds([FromBody] RssAggregation request)
        {
            var results = new List<object>();

            foreach (var feedUrl in request.FeedUrls)
            {
                try
                {
                    // VULNÉRABLE: Télécharge et parse du XML sans validation
                    var response = await _unsafeClient.GetAsync(feedUrl);
                    var xml = await response.Content.ReadAsStringAsync();

                    // VULNÉRABLE: Parse XML avec des paramètres non sécurisés
                    var settings = new XmlReaderSettings
                    {
                        DtdProcessing = DtdProcessing.Parse, // VULNÉRABLE: XXE possible
                        XmlResolver = new XmlUrlResolver(), // VULNÉRABLE: Résolution d'URL externe
                        MaxCharactersFromEntities = long.MaxValue
                    };

                    using var stringReader = new StringReader(xml);
                    using var xmlReader = XmlReader.Create(stringReader, settings);

                    var feed = SyndicationFeed.Load(xmlReader);

                    // VULNÉRABLE: Execute du contenu HTML si demandé
                    if (request.ParseHtml)
                    {
                        foreach (var item in feed.Items)
                        {
                            results.Add(new
                            {
                                title = item.Title?.Text,
                                content = item.Content?.ToString(), // VULNÉRABLE: Contenu HTML non sanitisé
                                htmlContent = item.Summary?.Text,
                                links = item.Links?.Select(l => l.Uri?.ToString()),
                                rawXml = item.ToString()
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    // VULNÉRABLE: Continue malgré les erreurs
                    results.Add(new { error = ex.Message, feed = feedUrl });
                }
            }

            return Ok(new { feeds = results, totalProcessed = request.FeedUrls.Count });
        }

        #endregion

        #region Webhooks - Exécution non validée

        /// <summary>
        /// VULNÉRABLE: Reçoit et traite des webhooks sans validation
        /// </summary>
        [HttpPost("webhook/receive")]
        public async Task<IActionResult> ReceiveWebhook([FromBody] WebhookPayload payload)
        {
            // VULNÉRABLE: Pas de validation de signature
            _logger.LogInformation($"Received webhook: {payload.Event} from {payload.SourceIp}");

            // VULNÉRABLE: Exécute des actions basées sur le payload non validé
            switch (payload.Event)
            {
                case "user.created":
                    // VULNÉRABLE: Crée un utilisateur avec les données du webhook
                    var userData = JsonSerializer.Deserialize<Dictionary<string, object>>(
                        JsonSerializer.Serialize(payload.Data));

                    // Simule la création d'utilisateur
                    await Task.Delay(100);

                    return Ok(new { message = "User created", data = userData });

                case "payment.completed":
                    // VULNÉRABLE: Met à jour le statut de paiement sans vérification
                    var paymentData = payload.Data;

                    return Ok(new { message = "Payment processed", amount = paymentData["amount"] });

                case "command.execute":
                    // VULNÉRABLE: Exécute des commandes arbitraires
                    var command = payload.Data["command"]?.ToString();

                    return Ok(new { message = $"Command executed: {command}" });

                default:
                    // VULNÉRABLE: Retourne toutes les données reçues
                    return Ok(new { message = "Unknown event", payload });
            }
        }

        #endregion

        #region API Aggregation - Parallélisation non sécurisée

        /// <summary>
        /// VULNÉRABLE: Agrège plusieurs APIs sans contrôle
        /// </summary>
        [HttpPost("aggregate")]
        public async Task<IActionResult> AggregateApis([FromBody] ApiAggregationRequest request)
        {
            var results = new AggregatedResponse
            {
                TotalRequests = request.ApiEndpoints.Count
            };

            // VULNÉRABLE: Exécution parallèle sans limite
            var tasks = request.ApiEndpoints.Select(async endpoint =>
            {
                var startTime = DateTime.UtcNow;
                try
                {
                    var httpRequest = new HttpRequestMessage(HttpMethod.Get, endpoint);

                    // VULNÉRABLE: Ajoute tous les headers fournis
                    foreach (var header in request.GlobalHeaders)
                    {
                        httpRequest.Headers.TryAddWithoutValidation(header.Key, header.Value);
                    }

                    var response = await _unsafeClient.SendAsync(httpRequest);
                    var content = await response.Content.ReadAsStringAsync();
                    var responseTime = (DateTime.UtcNow - startTime).TotalMilliseconds;

                    results.ResponseTimes[endpoint] = (long)responseTime;

                    // VULNÉRABLE: Parse et retourne n'importe quel contenu
                    try
                    {
                        var jsonData = JsonSerializer.Deserialize<object>(content);
                        results.Results.Add(jsonData!);
                        results.SuccessfulRequests++;
                    }
                    catch
                    {
                        // VULNÉRABLE: Si ce n'est pas du JSON, retourne le contenu brut
                        results.Results.Add(content);
                    }
                }
                catch (Exception ex)
                {
                    if (!request.ContinueOnError)
                        throw;

                    results.Errors.Add($"{endpoint}: {ex.Message}");
                }
            });

            // VULNÉRABLE: Pas de timeout global
            if (request.ParallelExecution)
            {
                await Task.WhenAll(tasks);
            }
            else
            {
                foreach (var task in tasks)
                {
                    await task;
                }
            }

            return Ok(results);
        }

        #endregion

        #region Social Media - Intégration non sécurisée

        /// <summary>
        /// VULNÉRABLE: Poste sur les réseaux sociaux sans validation
        /// </summary>
        [HttpPost("social/post")]
        public async Task<IActionResult> PostToSocialMedia([FromBody] SocialMediaPost post)
        {
            // VULNÉRABLE: Utilise des endpoints non vérifiés
            var endpoints = new Dictionary<string, string>
            {
                ["twitter"] = "http://fake-twitter-api.com/post",
                ["facebook"] = "http://fake-facebook-api.com/share",
                ["instagram"] = "http://fake-instagram-api.com/upload"
            };

            if (!endpoints.ContainsKey(post.Platform.ToLower()))
            {
                return BadRequest(new { error = "Unknown platform" });
            }

            var postData = new
            {
                content = post.Content,
                tags = post.Tags,
                media = post.MediaUrls,
                // VULNÉRABLE: Inclut des données sensibles
                apiKey = "hardcoded-api-key-12345",
                secret = "platform-secret-key"
            };

            var response = await _unsafeClient.PostAsJsonAsync(
                endpoints[post.Platform.ToLower()],
                postData);

            var responseContent = await response.Content.ReadAsStringAsync();

            // VULNÉRABLE: Retourne la réponse brute
            return Ok(new
            {
                platform = post.Platform,
                response = responseContent,
                statusCode = response.StatusCode
            });
        }

        #endregion

        #region File Upload - Transfert non sécurisé

        /// <summary>
        /// VULNÉRABLE: File Upload sans validation
        /// </summary>
        [HttpPost("file/upload")]
        public async Task<IActionResult> UploadFile([FromForm] IFormFile file,
                string url = "https://external-storage.com/api/upload")
        {
            // VULNÉRABLE: API externe non validée
            var externalApiUrl = _configuration["FileStorage:ApiEndpoint"] ?? url;

            // VULNÉRABLE: Pas de validation de la taille
            // Pas de limite : file.Length peut être énorme
            // VULNÉRABLE: Pas de validation du type de fichier
            var uploadPath = Path.Combine(_environment.WebRootPath, "uploads");
            // VULNÉRABLE: Utilisation directe du nom de fichier client
            var fileName = file.FileName; // Peut contenir ../../../ 
            var filePath = Path.Combine(uploadPath, fileName);
            // VULNÉRABLE: Pas de vérification d'extension
            // Accepte .exe, .dll, .aspx, .config, etc.
            // VULNÉRABLE: Sauvegarde directe sans validation
            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await file.CopyToAsync(stream);
            }

            // VULNÉRABLE: Envoi du fichier à une API externe non fiable
            using var client = new HttpClient();
            using var content = new MultipartFormDataContent();

            // VULNÉRABLE: Relecture du fichier sans validation
            var fileBytes = await System.IO.File.ReadAllBytesAsync(filePath);
            var fileContent = new ByteArrayContent(fileBytes);

            // VULNÉRABLE: Trust du Content-Type original
            fileContent.Headers.ContentType = MediaTypeHeaderValue.Parse(file.ContentType);
            content.Add(fileContent, "file", fileName);

            // VULNÉRABLE: Envoi à l'API externe sans vérification
            var response = await client.PostAsync(externalApiUrl, content);
            var externalResponse = await response.Content.ReadAsStringAsync();

            // VULNÉRABLE: Le fichier est accessible publiquement
            var publicUrl = $"/uploads/{fileName}";

            return Ok(new
            {
                url = publicUrl,
                fileName = fileName,
                // VULNÉRABLE: Expose le chemin réel
                path = filePath,
                // VULNÉRABLE: Expose la réponse de l'API externe
                externalApiResponse = externalResponse
            });
        }

        #endregion
    }

    public class ExternalApiResponse
    {
        public string? FileUrl { get; set; }
        public string? FileId { get; set; }
    }
}