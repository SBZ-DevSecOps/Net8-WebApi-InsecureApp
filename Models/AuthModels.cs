namespace Net8_WebApi_InsecureApp.Models
{
    // ===== MODÈLES DE DONNÉES AUTHENTICATION =====

    public class AuthUser
    {
        public int Id { get; set; }
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty; // VULNÉRABLE: Stocké en clair
        public string Role { get; set; } = "User";
        public DateTime CreatedAt { get; set; }
        public DateTime? LastLoginAt { get; set; }
        public DateTime? PasswordChangedAt { get; set; }
        public bool IsActive { get; set; }
        public string? TwoFactorSecret { get; set; } // Non utilisé (vulnérable)
        public ICollection<UserApiKey> ApiKeys { get; set; } = new List<UserApiKey>();
    }

    public class UserApiKey
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public string Key { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public DateTime? LastUsedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }
        public AuthUser User { get; set; } = null!;
    }

    // ===== MODÈLES DE REQUÊTE AUTHENTICATION =====

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

    // ===== MODÈLES DE RÉPONSE AUTHENTICATION =====

    public class LoginResponse
    {
        public string Token { get; set; } = string.Empty;
        public string ExpiresIn { get; set; } = string.Empty;
        public int UserId { get; set; }
        public string Role { get; set; } = string.Empty;
    }

    public class ApiKeyResponse
    {
        public string ApiKey { get; set; } = string.Empty;
        public int UserId { get; set; }
    }

    public class ValidationResponse
    {
        public bool Valid { get; set; }
        public int? UserId { get; set; }
        public string? UserEmail { get; set; }
        public string? KeyName { get; set; }
        public DateTime? CreatedAt { get; set; }
        public string? SessionInfo { get; set; }
    }
}