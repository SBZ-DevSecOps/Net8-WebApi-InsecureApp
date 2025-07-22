
namespace Net8_WebApi_InsecureApp.Models
{
    // ===== MODÈLES DE DONNÉES BOPLA =====

    public class UserProfile
    {
        public int Id { get; set; }
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? Phone { get; set; }
        public string? Address { get; set; }
        public DateTime DateOfBirth { get; set; }

        // Propriétés sensibles qui ne devraient pas être exposées
        public string? SocialSecurityNumber { get; set; }
        public decimal Salary { get; set; }
        public string? InternalNotes { get; set; }
        public bool IsVip { get; set; }
        public decimal CreditLimit { get; set; }
        public string? SecurityQuestion { get; set; }
        public string? SecurityAnswer { get; set; }

        // Propriétés administratives
        public DateTime CreatedAt { get; set; }
        public DateTime? LastModified { get; set; }
        public string? CreatedBy { get; set; }
        public int AccessLevel { get; set; }
        public bool IsActive { get; set; }
        public string? AccountStatus { get; set; }
        public DateTime? LastLoginAt { get; set; }
        public string? LastLoginIp { get; set; }
        public int FailedLoginAttempts { get; set; }
    }

    public class Product
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public decimal Price { get; set; }
        public int Stock { get; set; }
        public string Category { get; set; } = string.Empty;

        // Propriétés internes
        public decimal Cost { get; set; } // Ne devrait pas être visible
        public decimal Markup { get; set; } // Ne devrait pas être visible
        public string? SupplierName { get; set; } // Ne devrait pas être visible
        public string? SupplierContact { get; set; } // Ne devrait pas être visible
        public string? InternalSku { get; set; }
        public int WarehouseLocation { get; set; }
        public decimal ProfitMargin { get; set; }

        // Propriétés modifiables par admin seulement
        public bool IsFeatured { get; set; }
        public bool IsActive { get; set; }
        public int DisplayOrder { get; set; }
        public DateTime? PromotionEndDate { get; set; }
        public decimal? SpecialPrice { get; set; }
    }

    public class CompanyData
    {
        public int Id { get; set; }
        public string CompanyName { get; set; } = string.Empty;
        public string Industry { get; set; } = string.Empty;
        public string Website { get; set; } = string.Empty;

        // Données sensibles business
        public decimal AnnualRevenue { get; set; }
        public decimal MonthlyBurn { get; set; }
        public int EmployeeCount { get; set; }
        public string? TaxId { get; set; }
        public string? BankAccount { get; set; }
        public decimal CreditLine { get; set; }
        public string? InvestorNotes { get; set; }
        public List<string> ClientList { get; set; } = new();
        public Dictionary<string, decimal> RevenueByClient { get; set; } = new();

        // Propriétés stratégiques
        public string? BusinessPlan { get; set; }
        public string? CompetitiveAdvantage { get; set; }
        public List<string> TradeSecrets { get; set; } = new();
        public Dictionary<string, object> FinancialMetrics { get; set; } = new();
    }

    public class EmployeeRecord
    {
        public int Id { get; set; }
        public string EmployeeId { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string Department { get; set; } = string.Empty;
        public string Position { get; set; } = string.Empty;

        // Données RH sensibles
        public decimal BaseSalary { get; set; }
        public decimal Bonus { get; set; }
        public string? PerformanceRating { get; set; }
        public string? ManagerNotes { get; set; }
        public List<string> Complaints { get; set; } = new();
        public bool IsOnPip { get; set; } // Performance Improvement Plan
        public DateTime? TerminationDate { get; set; }
        public string? TerminationReason { get; set; }

        // Données personnelles
        public string? HomeAddress { get; set; }
        public string? PersonalEmail { get; set; }
        public string? EmergencyContact { get; set; }
        public string? MedicalConditions { get; set; }
        public Dictionary<string, string> PersonalInfo { get; set; } = new();
    }

    // ===== MODÈLES DE REQUÊTE BOPLA =====

    public class UserProfileUpdateRequest
    {
        // L'utilisateur peut envoyer n'importe quelle propriété
        public Dictionary<string, object> Updates { get; set; } = new();
    }

    public class ProductUpdateRequest
    {
        // Permet la mise à jour de n'importe quelle propriété
        public Dictionary<string, object> Properties { get; set; } = new();
    }

    public class BulkUpdateRequest
    {
        public List<int> Ids { get; set; } = new();
        public Dictionary<string, object> Updates { get; set; } = new();
    }

    public class QueryRequest
    {
        public List<string>? Fields { get; set; } // Permet de demander n'importe quel champ
        public Dictionary<string, object>? Filters { get; set; }
        public bool IncludeInternal { get; set; } // VULNÉRABLE: Permet d'inclure les champs internes
        public bool IncludeAll { get; set; } // VULNÉRABLE: Retourne toutes les propriétés
    }

    public class ExportRequest
    {
        public string Format { get; set; } = "json";
        public List<string>? Fields { get; set; } // VULNÉRABLE: Permet d'exporter n'importe quel champ
        public bool IncludeSensitive { get; set; }
        public string? ExportPassword { get; set; } // VULNÉRABLE: Mot de passe faible ou prévisible
    }
}
