using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Net8_WebApi_InsecureApp.Data;
using Net8_WebApi_InsecureApp.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Net8_WebApi_InsecureApp.Controllers
{
    /// <summary>
    /// Contrôleur démontrant la vulnérabilité API2:2023 - Broken Authentication
    /// Ce contrôleur contient intentionnellement des vulnérabilités pour des fins éducatives
    /// NE PAS UTILISER EN PRODUCTION
    /// </summary>
    [ApiController]
    [Route("api/auth")]
    public class Api02AuthController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly ILogger<Api02AuthController> _logger;

        // VULNÉRABLE: Stockage en dur de secrets
        private const string HardcodedSecret = "VeryWeakSecretKeyForDemonstrationPurposes123!";
        private const string DefaultAdminPassword = "admin123";
        private static readonly Dictionary<string, DateTime> _tokenBlacklist = new();
        private static readonly Dictionary<string, int> _loginAttempts = new();
        private static readonly Dictionary<string, string> _passwordResetTokens = new();
        private static readonly Dictionary<string, string> _sessionTokens = new();

        public Api02AuthController(AppDbContext context, IConfiguration configuration, ILogger<Api02AuthController> logger)
        {
            _context = context;
            _configuration = configuration;
            _logger = logger;
        }

        #region Login Endpoints - Multiple Vulnerabilities

        /// <summary>
        /// VULNÉRABLE: Login sans limitation de tentatives
        /// </summary>
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            // VULNÉRABLE: Pas de limite sur les tentatives de connexion (Brute Force possible)
            // VULNÉRABLE: Pas de CAPTCHA
            // VULNÉRABLE: Messages d'erreur informatifs

            var user = await _context.Set<AuthUser>()
                .FirstOrDefaultAsync(u => u.Email == request.Email);

            if (user == null)
            {
                // VULNÉRABLE: Message révélant l'existence ou non de l'utilisateur
                return Unauthorized(new { error = "User not found with this email" });
            }

            // VULNÉRABLE: Comparaison de mot de passe en clair
            if (user.Password != request.Password)
            {
                // VULNÉRABLE: Timing attack possible (comparaison directe)
                return Unauthorized(new { error = "Invalid password for this user" });
            }

            // VULNÉRABLE: Token JWT avec secret faible
            var token = GenerateWeakJwtToken(user);

            // VULNÉRABLE: Pas de rotation de token
            // VULNÉRABLE: Token avec durée de vie très longue
            return Ok(new
            {
                token,
                expiresIn = "30 days", // VULNÉRABLE: Token de longue durée
                userId = user.Id, // VULNÉRABLE: Exposition d'informations sensibles
                role = user.Role
            });
        }

        /// <summary>
        /// VULNÉRABLE: Login avec authentification basique HTTP
        /// </summary>
        [HttpPost("login-basic")]
        public async Task<IActionResult> LoginBasic()
        {
            // VULNÉRABLE: Utilisation de l'authentification basique (credentials en clair dans les headers)
            var authHeader = Request.Headers["Authorization"].FirstOrDefault();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Basic "))
            {
                return Unauthorized();
            }

            try
            {
                var encodedCredentials = authHeader.Substring("Basic ".Length).Trim();
                var decodedCredentials = Encoding.UTF8.GetString(Convert.FromBase64String(encodedCredentials));
                var parts = decodedCredentials.Split(':', 2);

                if (parts.Length != 2)
                {
                    return Unauthorized();
                }

                var email = parts[0];
                var password = parts[1];

                // VULNÉRABLE: Réutilisation du même code vulnérable
                var user = await _context.Set<AuthUser>()
                    .FirstOrDefaultAsync(u => u.Email == email && u.Password == password);

                if (user == null)
                {
                    return Unauthorized();
                }

                return Ok(new { token = GenerateWeakJwtToken(user) });
            }
            catch
            {
                return Unauthorized();
            }
        }

        /// <summary>
        /// VULNÉRABLE: Login avec token prédictible
        /// </summary>
        [HttpPost("login-simple")]
        public async Task<IActionResult> LoginSimple([FromBody] SimpleLoginRequest request)
        {
            var user = await _context.Set<AuthUser>()
                .FirstOrDefaultAsync(u => u.Email == request.Email);

            if (user == null) return Unauthorized();

            // VULNÉRABLE: Token prédictible basé sur l'email
            var simpleToken = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{user.Email}:{user.Id}:{DateTime.Now.Ticks}"));

            _sessionTokens[simpleToken] = user.Id.ToString();

            return Ok(new { token = simpleToken });
        }

        #endregion

        #region Registration - Weak Password Policy

        /// <summary>
        /// VULNÉRABLE: Enregistrement sans politique de mot de passe
        /// </summary>
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            // VULNÉRABLE: Pas de vérification de la force du mot de passe
            // VULNÉRABLE: Pas de vérification d'email
            // VULNÉRABLE: Stockage du mot de passe en clair

            var existingUser = await _context.Set<AuthUser>()
                .FirstOrDefaultAsync(u => u.Email == request.Email);

            if (existingUser != null)
            {
                // VULNÉRABLE: Confirmation que l'email existe déjà
                return BadRequest(new { error = "Email already registered" });
            }

            var user = new AuthUser
            {
                Email = request.Email,
                Password = request.Password, // VULNÉRABLE: Mot de passe en clair
                Role = "User",
                CreatedAt = DateTime.UtcNow,
                IsActive = true // VULNÉRABLE: Activation automatique sans vérification email
            };

            _context.Set<AuthUser>().Add(user);
            await _context.SaveChangesAsync();

            // VULNÉRABLE: Connexion automatique après inscription
            var token = GenerateWeakJwtToken(user);

            return Ok(new
            {
                message = "Registration successful",
                token, // VULNÉRABLE: Token fourni immédiatement
                userId = user.Id
            });
        }

        /// <summary>
        /// VULNÉRABLE: Enregistrement en masse sans limitation
        /// </summary>
        [HttpPost("register-bulk")]
        public async Task<IActionResult> RegisterBulk([FromBody] List<RegisterRequest> requests)
        {
            // VULNÉRABLE: Pas de limite sur le nombre d'enregistrements
            // VULNÉRABLE: Pas de CAPTCHA ou rate limiting

            var results = new List<object>();

            foreach (var request in requests)
            {
                var user = new AuthUser
                {
                    Email = request.Email,
                    Password = request.Password,
                    Role = request.Role ?? "User", // VULNÉRABLE: Permet de spécifier le rôle
                    CreatedAt = DateTime.UtcNow,
                    IsActive = true
                };

                _context.Set<AuthUser>().Add(user);
                results.Add(new { email = request.Email, status = "created" });
            }

            await _context.SaveChangesAsync();
            return Ok(results);
        }

        #endregion

        #region Password Reset - Multiple Vulnerabilities

        /// <summary>
        /// VULNÉRABLE: Reset de mot de passe avec token prédictible
        /// </summary>
        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
        {
            var user = await _context.Set<AuthUser>()
                .FirstOrDefaultAsync(u => u.Email == request.Email);

            if (user == null)
            {
                // VULNÉRABLE: Confirmation que l'email n'existe pas
                return NotFound(new { error = "Email not found" });
            }

            // VULNÉRABLE: Token de reset prédictible
            var resetToken = GeneratePredictableResetToken(user.Email);
            _passwordResetTokens[resetToken] = user.Email;

            // VULNÉRABLE: Token retourné dans la réponse
            return Ok(new
            {
                message = "Password reset token generated",
                resetToken, // VULNÉRABLE: Ne devrait pas être dans la réponse
                expiresIn = "1 hour"
            });
        }

        /// <summary>
        /// VULNÉRABLE: Reset sans vérification de l'ancien mot de passe
        /// </summary>
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            // VULNÉRABLE: Pas de vérification du token
            if (!_passwordResetTokens.ContainsKey(request.Token))
            {
                return BadRequest(new { error = "Invalid reset token" });
            }

            var email = _passwordResetTokens[request.Token];
            var user = await _context.Set<AuthUser>()
                .FirstOrDefaultAsync(u => u.Email == email);

            if (user == null) return NotFound();

            // VULNÉRABLE: Pas de vérification de la force du nouveau mot de passe
            user.Password = request.NewPassword;
            user.PasswordChangedAt = DateTime.UtcNow;

            await _context.SaveChangesAsync();

            // VULNÉRABLE: Pas d'invalidation des sessions existantes
            // VULNÉRABLE: Token de reset non supprimé (réutilisable)

            return Ok(new { message = "Password reset successful" });
        }

        /// <summary>
        /// VULNÉRABLE: Changement de mot de passe sans authentification
        /// </summary>
        [HttpPost("change-password-insecure")]
        public async Task<IActionResult> ChangePasswordInsecure([FromBody] ChangePasswordRequest request)
        {
            // VULNÉRABLE: Pas de vérification d'authentification
            // VULNÉRABLE: userId passé dans la requête

            var user = await _context.Set<AuthUser>().FindAsync(request.UserId);
            if (user == null) return NotFound();

            // VULNÉRABLE: Pas de vérification de l'ancien mot de passe
            user.Password = request.NewPassword;
            await _context.SaveChangesAsync();

            return Ok(new { message = "Password changed successfully" });
        }

        #endregion

        #region Session Management Vulnerabilities

        /// <summary>
        /// VULNÉRABLE: Logout qui ne révoque pas vraiment le token
        /// </summary>
        [HttpPost("logout")]
        public IActionResult Logout()
        {
            // VULNÉRABLE: Le token JWT reste valide après logout
            // Pas de blacklist ou de révocation côté serveur

            var token = Request.Headers["Authorization"].FirstOrDefault()?.Replace("Bearer ", "");

            if (!string.IsNullOrEmpty(token))
            {
                // VULNÉRABLE: Blacklist en mémoire seulement (perdue au redémarrage)
                _tokenBlacklist[token] = DateTime.UtcNow;
            }

            return Ok(new { message = "Logged out successfully" });
        }

        /// <summary>
        /// VULNÉRABLE: Refresh token sans validation
        /// </summary>
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            // VULNÉRABLE: Pas de vérification du refresh token
            // VULNÉRABLE: Génération d'un nouveau token sans authentification

            try
            {
                // Décodage basique du token sans validation
                var handler = new JwtSecurityTokenHandler();
                var jsonToken = handler.ReadJwtToken(request.Token);

                var userIdClaim = jsonToken.Claims.FirstOrDefault(x => x.Type == "userId")?.Value;
                if (string.IsNullOrEmpty(userIdClaim)) return Unauthorized();

                var userId = int.Parse(userIdClaim);
                var user = await _context.Set<AuthUser>().FindAsync(userId);

                if (user == null) return Unauthorized();

                // VULNÉRABLE: Nouveau token sans vérifier l'expiration de l'ancien
                var newToken = GenerateWeakJwtToken(user);

                return Ok(new { token = newToken, expiresIn = "30 days" });
            }
            catch
            {
                return Unauthorized();
            }
        }

        /// <summary>
        /// VULNÉRABLE: Validation de session faible
        /// </summary>
        [HttpGet("validate-session")]
        public IActionResult ValidateSession([FromQuery] string token)
        {
            // VULNÉRABLE: Token passé en query string (visible dans les logs)

            if (_sessionTokens.ContainsKey(token))
            {
                var userId = _sessionTokens[token];
                // VULNÉRABLE: Retourne des informations sensibles
                return Ok(new
                {
                    valid = true,
                    userId = userId,
                    sessionInfo = "Active session found"
                });
            }

            return Ok(new { valid = false });
        }

        #endregion

        #region OAuth/SSO Vulnerabilities

        /// <summary>
        /// VULNÉRABLE: OAuth avec state prédictible
        /// </summary>
        [HttpGet("oauth/authorize")]
        public IActionResult OAuthAuthorize([FromQuery] string clientId, [FromQuery] string redirectUri)
        {
            // VULNÉRABLE: State parameter prédictible
            var state = DateTime.Now.Ticks.ToString();

            // VULNÉRABLE: Pas de validation du redirect_uri
            var authUrl = $"https://oauth.provider.com/auth?client_id={clientId}&redirect_uri={redirectUri}&state={state}";

            return Ok(new { authUrl, state });
        }

        /// <summary>
        /// VULNÉRABLE: Callback OAuth sans validation
        /// </summary>
        [HttpPost("oauth/callback")]
        public async Task<IActionResult> OAuthCallback([FromBody] OAuthCallbackRequest request)
        {
            // VULNÉRABLE: Pas de validation du state parameter
            // VULNÉRABLE: Trust aveugle du code d'autorisation

            // Simulation d'échange de code (vulnérable)
            var email = DecodeAuthCode(request.Code);

            var user = await _context.Set<AuthUser>()
                .FirstOrDefaultAsync(u => u.Email == email);

            if (user == null)
            {
                // VULNÉRABLE: Création automatique de compte
                user = new AuthUser
                {
                    Email = email,
                    Password = Guid.NewGuid().ToString(), // VULNÉRABLE: Mot de passe prédictible
                    Role = "User",
                    CreatedAt = DateTime.UtcNow,
                    IsActive = true
                };

                _context.Set<AuthUser>().Add(user);
                await _context.SaveChangesAsync();
            }

            var token = GenerateWeakJwtToken(user);
            return Ok(new { token, userId = user.Id });
        }

        #endregion

        #region API Key Authentication Vulnerabilities

        /// <summary>
        /// VULNÉRABLE: Génération de clé API faible
        /// </summary>
        [HttpPost("generate-api-key")]
        public async Task<IActionResult> GenerateApiKey([FromBody] ApiKeyRequest request)
        {
            // VULNÉRABLE: Pas d'authentification requise
            var user = await _context.Set<AuthUser>()
                .FirstOrDefaultAsync(u => u.Email == request.Email);

            if (user == null) return NotFound();

            // VULNÉRABLE: Clé API prédictible
            var apiKey = $"sk_{user.Id}_{DateTime.Now.Ticks}";

            var key = new UserApiKey
            {
                UserId = user.Id,
                Key = apiKey,
                Name = request.KeyName ?? "Default Key",
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = null // VULNÉRABLE: Pas d'expiration
            };

            _context.Set<UserApiKey>().Add(key);
            await _context.SaveChangesAsync();

            // VULNÉRABLE: Retourne la clé en clair
            return Ok(new { apiKey, userId = user.Id });
        }

        /// <summary>
        /// VULNÉRABLE: Validation de clé API
        /// </summary>
        [HttpGet("validate-api-key")]
        public async Task<IActionResult> ValidateApiKey([FromHeader(Name = "X-API-Key")] string apiKey)
        {
            // VULNÉRABLE: Clé API dans les headers custom (peut être loggée)

            var key = await _context.Set<UserApiKey>()
                .Include(k => k.User)
                .FirstOrDefaultAsync(k => k.Key == apiKey);

            if (key == null)
            {
                return Unauthorized(new { error = "Invalid API key" });
            }

            // VULNÉRABLE: Pas de vérification d'expiration
            // VULNÉRABLE: Retourne trop d'informations
            return Ok(new
            {
                valid = true,
                userId = key.UserId,
                userEmail = key.User.Email,
                keyName = key.Name,
                createdAt = key.CreatedAt
            });
        }

        #endregion

        #region Helper Methods

        private string GenerateWeakJwtToken(AuthUser user)
        {
            // VULNÉRABLE: Utilisation d'un secret faible et codé en dur
            var key = Encoding.ASCII.GetBytes(HardcodedSecret);
            var tokenHandler = new JwtSecurityTokenHandler();

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

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private string GeneratePredictableResetToken(string email)
        {
            // VULNÉRABLE: Token prédictible basé sur l'email et le timestamp
            var timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmm");
            var data = $"{email}:{timestamp}";
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(data));
        }

        private string DecodeAuthCode(string code)
        {
            // VULNÉRABLE: Décodage simple sans validation cryptographique
            try
            {
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(code));
                return decoded.Split(':')[0];
            }
            catch
            {
                return "default@example.com";
            }
        }

        #endregion

        #region Admin Backdoor

        /// <summary>
        /// VULNÉRABLE: Backdoor administrateur
        /// </summary>
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
                var defaultAdmin = new AuthUser
                {
                    Id = 999,
                    Email = "admin@system.local",
                    Role = "Admin"
                };

                var token = GenerateWeakJwtToken(defaultAdmin);
                return Ok(new { token, message = "Default admin access" });
            }

            return Unauthorized();
        }

        #endregion
    }

    // ===== MODÈLES DE REQUÊTE =====
    public class LoginRequest
    {
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }

    public class SimpleLoginRequest
    {
        public string Email { get; set; } = string.Empty;
    }

    public class RegisterRequest
    {
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string? Role { get; set; }
    }

    public class ForgotPasswordRequest
    {
        public string Email { get; set; } = string.Empty;
    }

    public class ResetPasswordRequest
    {
        public string Token { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
    }

    public class ChangePasswordRequest
    {
        public int UserId { get; set; }
        public string NewPassword { get; set; } = string.Empty;
    }

    public class RefreshTokenRequest
    {
        public string Token { get; set; } = string.Empty;
    }

    public class OAuthCallbackRequest
    {
        public string Code { get; set; } = string.Empty;
        public string State { get; set; } = string.Empty;
    }

    public class ApiKeyRequest
    {
        public string Email { get; set; } = string.Empty;
        public string? KeyName { get; set; }
    }

    public class AdminLoginRequest
    {
        public string? Email { get; set; }
        public string? Password { get; set; }
        public string? MasterPassword { get; set; }
    }

}