# API9:2023 - Improper Inventory Management

## 📋 Description de la vulnérabilité

La vulnérabilité **Improper Inventory Management** se produit lorsqu'une organisation n'a pas une visibilité et un contrôle adéquats sur ses APIs. Cela inclut les APIs non documentées, les versions obsolètes, les endpoints de test exposés en production, et l'absence de gestion centralisée des APIs.

### Impact potentiel
- Accès à des APIs non documentées ou oubliées
- Exploitation de versions obsolètes avec des vulnérabilités connues
- Découverte d'endpoints de développement/test en production
- Contournement des contrôles de sécurité via des versions alternatives
- Exposition d'informations sensibles via des APIs shadow IT

## 🎯 Endpoints vulnérables

Le contrôleur `Api09InventoryController` expose de nombreux problèmes de gestion d'inventaire :

### 1. **Versions multiples non documentées**
- `GET /api/v1/users` - Ancienne version toujours active
- `GET /api/v2-beta/users` - Version beta exposée
- `GET /api/internal/debug/users` - Endpoint interne exposé
- `GET /api/legacy/api/userData.php` - Endpoint legacy non sécurisé

### 2. **Discovery et énumération**
- `GET /api/inventory/endpoints` - Découverte de tous les endpoints
- `GET /api/inventory/swagger-config` - Configuration Swagger exposée
- `POST /api/inventory/scan` - Scanner d'endpoints

### 3. **Informations système**
- `GET /api/inventory/system-info` - Informations système détaillées
- `GET /api/inventory/environment` - Variables d'environnement
- `GET /api/inventory/assemblies` - Assemblies chargées

### 4. **Service Discovery**
- `GET /api/inventory/services` - Registre des services
- `GET /api/inventory/internal-services` - Services internes

### 5. **Documentation et inventaire**
- `GET /api/inventory/documentation` - Documentation interne
- `GET /api/inventory/complete` - Inventaire complet
- `GET /api/versions` - Toutes les versions d'API

## 🔍 Code vulnérable expliqué

### Exemple 1 : Versions multiples non contrôlées

```csharp
[HttpGet("v1/users")]
public async Task<IActionResult> GetUsersV1()
{
    // VULNÉRABLE: Ancienne version sans pagination ni filtrage
    var users = await _context.Users.ToListAsync();
    return Ok(new
    {
        data = users,
        version = "1.0",
        deprecated = true,
        message = "This endpoint is deprecated,