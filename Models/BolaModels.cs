namespace Net8_WebApi_InsecureApp.Models
{
    // ===== MODÈLES DE DONNÉES BOLA =====

    public class User
    {
        public int Id { get; set; }
        public string Email { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;
        public ICollection<Order> Orders { get; set; } = new List<Order>();
        public ICollection<BankAccount> BankAccounts { get; set; } = new List<BankAccount>();
        public ICollection<MedicalRecord> MedicalRecords { get; set; } = new List<MedicalRecord>();
        public ICollection<Document> Documents { get; set; } = new List<Document>();
        public ICollection<ApiKey> ApiKeys { get; set; } = new List<ApiKey>();
    }

    public class Order
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public decimal Amount { get; set; }
        public string Status { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public User? User { get; set; }
    }

    public class BankAccount
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public string AccountNumber { get; set; } = string.Empty;
        public decimal Balance { get; set; }
        public string IBAN { get; set; } = string.Empty;
        public User User { get; set; } = null!;
    }

    public class MedicalRecord
    {
        public int Id { get; set; }
        public int PatientId { get; set; }
        public string Diagnosis { get; set; } = string.Empty;
        public string Medications { get; set; } = string.Empty;
        public string SensitiveNotes { get; set; } = string.Empty;
        public User Patient { get; set; } = null!;
    }

    public class Document
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public string FileName { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public bool IsConfidential { get; set; }
        public User User { get; set; } = null!;
    }

    public class Message
    {
        public int Id { get; set; }
        public int SenderId { get; set; }
        public int RecipientId { get; set; }
        public string Content { get; set; } = string.Empty;
        public DateTime SentAt { get; set; }
        public bool IsRead { get; set; }
        public User Sender { get; set; } = null!;
        public User Recipient { get; set; } = null!;
    }

    public class ApiKey
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public string Key { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public DateTime? LastUsedAt { get; set; }
        public bool IsRevoked { get; set; }
        public DateTime? RevokedAt { get; set; }
        public User User { get; set; } = null!;
    }

    // ===== MODÈLES DE REQUÊTE BOLA =====

    public class TransferRequest
    {
        public int TargetAccountId { get; set; }
        public decimal Amount { get; set; }
    }

    public class ShareRequest
    {
        public string[] RecipientEmails { get; set; } = Array.Empty<string>();
        public DateTime? ExpirationDate { get; set; }
    }

    public class UpdateRoleRequest
    {
        public string NewRole { get; set; } = string.Empty;
    }
}