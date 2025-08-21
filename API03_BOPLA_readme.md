# API3:2023 - Broken Object Property Level Authorization (BOPLA)

## 📋 Description de la vulnérabilité

La vulnérabilité **Broken Object Property Level Authorization (BOPLA)** se produit lorsqu'une API expose ou permet la modification de propriétés d'objets qui devraient être restreintes. Cette vulnérabilité combine deux aspects :

1. **Exposition excessive de données** : L'API retourne des propriétés sensibles qui ne devraient pas être visibles
2. **Assignation de masse** : L'API permet de modifier des propriétés qui devraient être protégées

### Impact potentiel
- Exposition d'informations sensibles (salaires, SSN, données financières)
- Modification non autorisée de propriétés critiques (rôles, permissions, soldes)
- Contournement des contrôles métier
- Violation de la vie privée et de la confidentialité
- Élévation de privilèges

## 🎯 Endpoints vulnérables

Le contrôleur `Api03BoplaController` expose de nombreux endpoints vulnérables :

### 1. **Profils utilisateurs**
- `GET /api/bopla/users/{userId}` - Retourne toutes les propriétés
- `PATCH /api/bopla/users/{userId}` - Permet de modifier n'importe quelle propriété
- `POST /api/bopla/users/query` - Requête sur n'importe quel champ
- `POST /api/bopla/users/export` - Export en masse avec propriétés sensibles

### 2. **Produits**
- `GET /api/bopla/products?showInternal=true` - Expose les propriétés internes
- `PATCH /api/bopla/products/bulk-update` - Mise à jour en masse
- `GET /api/bopla/products/search?fields=...` - Projection dynamique

### 3. **Données d'entreprise**
- `POST /api/bopla/graphql` - Endpoint GraphQL exposant tout
- `GET /api/bopla/company/{companyId}?include=all` - Données financières exposées

### 4. **Enregistrements employés**
- `GET /api/bopla/employees?includeSalary=true` - Expose les salaires
- `PUT /api/bopla/employees/{employeeId}` - Modification sans restriction

### 5. **Manipulation générique**
- `POST /api/bopla/objects/{entityType}` - Accès à n'importe quelle entité

## 🔍 Code vulnérable expliqué

### Exemple 1 : Exposition de toutes les propriétés

```csharp
[HttpGet("users/{userId}")]
public async Task<IActionResult> GetUserProfile(int userId)
{
    var user = await _context.Set<UserProfile>().FindAsync(userId);
    if (user == null) return NotFound();

    // VULNÉRABLE: Retourne toutes les propriétés, y compris les sensibles
    return Ok(user);
}
```

**Problème** : L'API retourne l'objet complet incluant des propriétés sensibles comme :
- `SocialSecurityNumber`
- `Salary`
- `CreditLimit`
- `SecurityAnswer`

### Exemple 2 : Assignation de masse

```csharp
[HttpPatch("users/{userId}")]
public async Task<IActionResult> UpdateUserProfile(int userId, [FromBody] UserProfileUpdateRequest request)
{
    var user = await _context.Set<UserProfile>().FindAsync(userId);
    if (user == null) return NotFound();

    foreach (var update in request.Updates)
    {
        var property = user.GetType().GetProperty(update.Key, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
        if (property != null && property.CanWrite)
        {
            // VULNÉRABLE: Permet de modifier n'importe quelle propriété
            property.SetValue(user, update.Value);
        }
    }

    await _context.SaveChangesAsync();
    return Ok(user);
}
```

**Problème** : Permet de modifier des propriétés critiques comme :
- `Role` → Élévation de privilèges
- `Salary` → Augmentation non autorisée
- `IsVerified` → Contournement de vérification

### Exemple 3 : Requête dynamique sur tous les champs

```csharp
[HttpPost("users/query")]
public async Task<IActionResult> QueryUsers([FromBody] QueryRequest request)
{
    var query = _context.Set<UserProfile>().AsQueryable();

    // VULNÉRABLE: Permet de filtrer sur n'importe quel champ
    if (request.Filters != null)
    {
        foreach (var filter in request.Filters)
        {
            query = query.Where($"{filter.Key} == @0", filter.Value);
        }
    }

    // VULNÉRABLE: Retourne les champs demandés sans validation
    if (request.Fields != null && request.Fields.Any())
    {
        // Projection dynamique des champs sensibles
    }

    return Ok(users);
}
```

### Exemple 4 : Endpoint GraphQL non sécurisé

```csharp
[HttpPost("graphql")]
public async Task<IActionResult> GraphQLQuery([FromBody] JsonElement query)
{
    if (queryString?.Contains("employees") == true)
    {
        var employees = await _context.Set<EmployeeRecord>().ToListAsync();
        // VULNÉRABLE: Retourne toutes les données des employés
        return Ok(new { data = new { employees } });
    }
}
```

## 💥 Scénarios d'exploitation

### Scénario 1 : Vol de données sensibles
```bash
# Récupération de toutes les propriétés d'un utilisateur
GET /api/bopla/users/1
Response: {
    "id": 1,
    "username": "john.doe",
    "email": "john@example.com",
    "socialSecurityNumber": "123-45-6789",  # Sensible!
    "salary": 95000,                        # Sensible!
    "creditLimit": 50000,                   # Sensible!
    "securityAnswer": "Fluffy",             # Sensible!
    "bankAccountNumber": "1234567890"       # Sensible!
}
```

### Scénario 2 : Élévation de privilèges
```bash
# Modification du rôle utilisateur
PATCH /api/bopla/users/123
Content-Type: application/json

{
    "updates": {
        "role": "Admin",
        "isVerified": true,
        "isPremium": true,
        "creditLimit": 1000000
    }
}
```

### Scénario 3 : Export en masse de données sensibles
```bash
# Export avec mot de passe faible
POST /api/bopla/users/export
Content-Type: application/json

{
    "includeSensitive": true,
    "exportPassword": "admin123",
    "format": "csv"
}

Response: CSV avec SSN, salaires, etc.
```

### Scénario 4 : Requête sur des champs sensibles
```python
# Recherche d'utilisateurs avec salaire élevé
import requests

response = requests.post('http://localhost:5000/api/bopla/users/query',
    json={
        "filters": {"salary": {"$gt": 100000}},
        "fields": ["email", "salary", "creditLimit"]
    })

# Résultat : Liste des utilisateurs riches avec leurs emails
```

### Scénario 5 : Manipulation de prix de produits
```bash
# Modification en masse des prix
PATCH /api/bopla/products/bulk-update
Content-Type: application/json

{
    "ids": [1, 2, 3, 4, 5],
    "updates": {
        "price": 0.01,
        "cost": 1000,
        "isInternal": false,
        "isDiscontinued": false
    }
}
```

## 🛡️ Solutions de remédiation

### 1. **Implémenter des DTO (Data Transfer Objects)**

```csharp
// DTO pour les réponses publiques
public class UserProfilePublicDto
{
    public int Id { get; set; }
    public string Username { get; set; }
    public string Email { get; set; }
    // Uniquement les propriétés publiques
}

// DTO pour les propriétaires
public class UserProfileOwnerDto : UserProfilePublicDto
{
    public string Phone { get; set; }
    public DateTime LastLogin { get; set; }
    // Propriétés supplémentaires pour le propriétaire
}

[HttpGet("users/{userId}")]
public async Task<IActionResult> GetUserProfile(int userId)
{
    var currentUserId = GetCurrentUserId();
    var user = await _context.UserProfiles.FindAsync(userId);
    
    if (user == null) return NotFound();
    
    // Retourner des données différentes selon l'autorisation
    if (currentUserId == userId)
    {
        return Ok(_mapper.Map<UserProfileOwnerDto>(user));
    }
    else
    {
        return Ok(_mapper.Map<UserProfilePublicDto>(user));
    }
}
```

### 2. **Listes blanches pour les propriétés modifiables**

```csharp
public class UserUpdateDto
{
    private static readonly HashSet<string> AllowedProperties = new()
    {
        "Username", "Email", "Phone", "Bio"
    };

    public Dictionary<string, object> Updates { get; set; }

    public Dictionary<string, object> GetAllowedUpdates()
    {
        return Updates.Where(kvp => AllowedProperties.Contains(kvp.Key))
                     .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
    }
}

[HttpPatch("users/{userId}")]
public async Task<IActionResult> UpdateUserProfile(int userId, [FromBody] UserUpdateDto request)
{
    var currentUserId = GetCurrentUserId();
    if (currentUserId != userId)
        return Forbid();

    var user = await _context.UserProfiles.FindAsync(userId);
    if (user == null) return NotFound();

    // Appliquer uniquement les mises à jour autorisées
    var allowedUpdates = request.GetAllowedUpdates();
    foreach (var update in allowedUpdates)
    {
        var property = user.GetType().GetProperty(update.Key);
        if (property != null)
        {
            property.SetValue(user, update.Value);
        }
    }

    await _context.SaveChangesAsync();
    
    // Retourner un DTO sécurisé
    return Ok(_mapper.Map<UserProfileOwnerDto>(user));
}
```

### 3. **Validation des requêtes dynamiques**

```csharp
[HttpPost("users/query")]
public async Task<IActionResult> QueryUsers([FromBody] SecureQueryRequest request)
{
    // Définir les champs autorisés pour les requêtes
    var allowedQueryFields = new HashSet<string> { "Username", "Email", "CreatedAt" };
    var allowedReturnFields = new HashSet<string> { "Id", "Username", "Email", "Bio" };

    // Valider les filtres
    var validFilters = request.Filters?
        .Where(f => allowedQueryFields.Contains(f.Key))
        .ToDictionary(f => f.Key, f => f.Value);

    // Valider les champs de retour
    var validFields = request.Fields?
        .Where(f => allowedReturnFields.Contains(f))
        .ToList();

    var query = _context.UserProfiles.AsQueryable();

    // Appliquer les filtres validés
    foreach (var filter in validFilters ?? new Dictionary<string, object>())
    {
        query = query.Where($"{filter.Key} == @0", filter.Value);
    }

    var users = await query.Select(u => new UserProfilePublicDto
    {
        Id = u.Id,
        Username = u.Username,
        Email = u.Email
    }).ToListAsync();

    return Ok(users);
}
```

### 4. **Autorisation basée sur les rôles pour les propriétés**

```csharp
public interface IPropertyAuthorization
{
    bool CanRead(string propertyName, string userRole);
    bool CanWrite(string propertyName, string userRole);
}

public class PropertyAuthorizationService : IPropertyAuthorization
{
    private readonly Dictionary<string, HashSet<string>> _readPermissions = new()
    {
        ["Salary"] = new() { "Admin", "HR" },
        ["SocialSecurityNumber"] = new() { "Admin", "HR" },
        ["CreditLimit"] = new() { "Admin", "Finance" }
    };

    private readonly Dictionary<string, HashSet<string>> _writePermissions = new()
    {
        ["Role"] = new() { "Admin" },
        ["Salary"] = new() { "HR" },
        ["IsVerified"] = new() { "Admin" }
    };

    public bool CanRead(string propertyName, string userRole)
    {
        return !_readPermissions.ContainsKey(propertyName) || 
               _readPermissions[propertyName].Contains(userRole);
    }

    public bool CanWrite(string propertyName, string userRole)
    {
        return !_writePermissions.ContainsKey(propertyName) || 
               _writePermissions[propertyName].Contains(userRole);
    }
}
```

### 5. **API versioning avec schémas stricts**

```csharp
[ApiVersion("2.0")]
[Route("api/v{version:apiVersion}/users")]
public class SecureUsersController : ControllerBase
{
    [HttpGet("{id}")]
    [ProducesResponseType(typeof(UserProfilePublicDto), 200)]
    public async Task<IActionResult> GetUser(int id)
    {
        // Implementation avec DTO sécurisé
    }

    [HttpPatch("{id}")]
    [ProducesResponseType(typeof(UserProfileOwnerDto), 200)]
    public async Task<IActionResult> UpdateUser(
        int id, 
        [FromBody] UserUpdateDto updates)
    {
        // Implementation avec validation stricte
    }
}
```

## 🔧 Bonnes pratiques

1. **Principe du moindre privilège** : Ne retourner que les données nécessaires
2. **Utiliser des DTO** : Séparer les modèles de domaine des modèles d'API
3. **Listes blanches** : Toujours utiliser des listes blanches pour les propriétés
4. **Validation stricte** : Valider toutes les entrées utilisateur
5. **Documentation** : Documenter clairement les propriétés exposées
6. **Tests** : Tester l'accès aux propriétés pour chaque rôle
7. **Audit** : Journaliser les modifications de propriétés sensibles

## 📊 Tests de détection

### Test d'exposition de propriétés
```python
import requests
import json

def test_property_exposure(base_url, token):
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test 1: Vérifier les propriétés exposées
    response = requests.get(f"{base_url}/api/bopla/users/1", headers=headers)
    user_data = response.json()
    
    sensitive_fields = [
        "socialSecurityNumber", "salary", "creditLimit", 
        "securityAnswer", "bankAccountNumber"
    ]
    
    exposed_fields = [field for field in sensitive_fields if field in user_data]
    
    if exposed_fields:
        print(f"❌ Propriétés sensibles exposées: {exposed_fields}")
    else:
        print("✅ Pas de propriétés sensibles exposées")
```

### Test d'assignation de masse
```bash
# Tentative de modification de propriétés sensibles
curl -X PATCH http://localhost:5000/api/bopla/users/123 \
    -H "Authorization: Bearer [TOKEN]" \
    -H "Content-Type: application/json" \
    -d '{
        "updates": {
            "role": "Admin",
            "salary": 200000,
            "isVerified": true,
            "creditLimit": 100000
        }
    }'
```

### Test avec Burp Suite

1. Intercepter une requête de mise à jour légitime
2. Ajouter des propriétés sensibles dans le payload
3. Observer si les propriétés sont modifiées
4. Utiliser l'extension "Param Miner" pour découvrir des propriétés cachées

## ⚠️ Attention

Ce code est **intentionnellement vulnérable** et ne doit **JAMAIS** être utilisé en production. Il sert uniquement à des fins éducatives pour comprendre et apprendre à détecter les vulnérabilités BOPLA.

## 📚 Références

- [OWASP API Security Top 10 2023 - BOPLA](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
- [Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- [API Security Best Practices](https://owasp.org/www-project-api-security/)