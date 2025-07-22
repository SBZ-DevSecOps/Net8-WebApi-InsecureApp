using Net8_WebApi_InsecureApp.Models;

namespace Net8_WebApi_InsecureApp.Data
{
    public static class DatabaseSeeder
    {
        public static void SeedDatabase(AppDbContext context)
        {
            if (context.Users.Any())
                return; // Déjà initialisé

            // === Seed BOLA Data ===
            SeedBolaData(context);

            // === Seed Authentication Data ===
            SeedAuthenticationData(context);

            // === Seed BOPLA Data ===
            SeedBoplaData(context);

            SeedFunctionLevelAuthTestData(context);

            SeedInventoryData(context);

            SeedUnsafeConsumptionData(context);

            context.SaveChanges();
        }

        private static void SeedBolaData(AppDbContext context)
        {
            // Utilisateurs
            var users = new[]
            {
                new User { Id = 1, Email = "alice@example.com", Role = "User" },
                new User { Id = 2, Email = "bob@example.com", Role = "User" },
                new User { Id = 3, Email = "charlie@example.com", Role = "User" },
                new User { Id = 4, Email = "admin@example.com", Role = "Admin" },
                new User { Id = 5, Email = "eve@example.com", Role = "User" }
            };
            context.Users.AddRange(users);

            // Commandes
            var orders = new[]
            {
                new Order { Id = 1001, UserId = 1, Amount = 150.00m, Status = "Pending", CreatedAt = DateTime.UtcNow.AddDays(-2) },
                new Order { Id = 1002, UserId = 2, Amount = 299.99m, Status = "Shipped", CreatedAt = DateTime.UtcNow.AddDays(-5) },
                new Order { Id = 1003, UserId = 3, Amount = 75.50m, Status = "Delivered", CreatedAt = DateTime.UtcNow.AddDays(-10) },
                new Order { Id = 1004, UserId = 1, Amount = 525.00m, Status = "Processing", CreatedAt = DateTime.UtcNow.AddDays(-1) },
                new Order { Id = 1005, UserId = 5, Amount = 1250.00m, Status = "Pending", CreatedAt = DateTime.UtcNow }
            };
            context.Orders.AddRange(orders);

            // Comptes bancaires
            var bankAccounts = new[]
            {
                new BankAccount { Id = 2001, UserId = 1, AccountNumber = "1234567890", Balance = 5000.00m, IBAN = "FR7630001007941234567890185" },
                new BankAccount { Id = 2002, UserId = 2, AccountNumber = "0987654321", Balance = 15000.00m, IBAN = "FR7630001007940987654321186" },
                new BankAccount { Id = 2003, UserId = 3, AccountNumber = "1111222233", Balance = 250.00m, IBAN = "FR7630001007941111222233187" },
                new BankAccount { Id = 2004, UserId = 4, AccountNumber = "9999888877", Balance = 100000.00m, IBAN = "FR7630001007949999888877188" },
                new BankAccount { Id = 2005, UserId = 5, AccountNumber = "5555666677", Balance = 7500.00m, IBAN = "FR7630001007945555666677189" }
            };
            context.BankAccounts.AddRange(bankAccounts);

            // Dossiers médicaux
            var medicalRecords = new[]
            {
                new MedicalRecord { Id = 3001, PatientId = 1, Diagnosis = "Hypertension", Medications = "Lisinopril 10mg", SensitiveNotes = "Anxiété liée au travail" },
                new MedicalRecord { Id = 3002, PatientId = 2, Diagnosis = "Diabète Type 2", Medications = "Metformine 500mg", SensitiveNotes = "Antécédents familiaux importants" },
                new MedicalRecord { Id = 3003, PatientId = 3, Diagnosis = "Asthme sévère", Medications = "Ventoline, Seretide", SensitiveNotes = "Allergies multiples" },
                new MedicalRecord { Id = 3004, PatientId = 4, Diagnosis = "Migraine chronique", Medications = "Sumatriptan", SensitiveNotes = "Stress professionnel élevé" },
                new MedicalRecord { Id = 3005, PatientId = 5, Diagnosis = "Dépression", Medications = "Sertraline 50mg", SensitiveNotes = "En thérapie hebdomadaire" }
            };
            context.MedicalRecords.AddRange(medicalRecords);

            // Documents
            var documents = new[]
            {
                new Document { Id = 4001, UserId = 1, FileName = "contrat_travail.pdf", FilePath = "/files/doc_4001.pdf", IsConfidential = true },
                new Document { Id = 4002, UserId = 2, FileName = "bilan_medical_2024.pdf", FilePath = "/files/doc_4002.pdf", IsConfidential = true },
                new Document { Id = 4003, UserId = 3, FileName = "declaration_impots.pdf", FilePath = "/files/doc_4003.pdf", IsConfidential = true },
                new Document { Id = 4004, UserId = 4, FileName = "plans_strategiques.xlsx", FilePath = "/files/doc_4004.xlsx", IsConfidential = true },
                new Document { Id = 4005, UserId = 5, FileName = "photos_famille.zip", FilePath = "/files/doc_4005.zip", IsConfidential = false }
            };
            context.Documents.AddRange(documents);

            // Messages
            var messages = new[]
            {
                new Message { Id = 6001, SenderId = 1, RecipientId = 2, Content = "Mot de passe WiFi: SecretPass123", SentAt = DateTime.UtcNow.AddHours(-2), IsRead = true },
                new Message { Id = 6002, SenderId = 2, RecipientId = 3, Content = "Le code de la salle serveur est 4521", SentAt = DateTime.UtcNow.AddHours(-5), IsRead = false },
                new Message { Id = 6003, SenderId = 3, RecipientId = 1, Content = "Numéro de CB: 4532-XXXX-XXXX-1234", SentAt = DateTime.UtcNow.AddDays(-1), IsRead = true },
                new Message { Id = 6004, SenderId = 4, RecipientId = 5, Content = "Accès admin: admin/P@ssw0rd2024", SentAt = DateTime.UtcNow.AddDays(-2), IsRead = false },
                new Message { Id = 6005, SenderId = 5, RecipientId = 4, Content = "Clé API production: sk-prod-abc123xyz789", SentAt = DateTime.UtcNow.AddDays(-3), IsRead = true }
            };
            context.Messages.AddRange(messages);

            // Clés API
            var apiKeys = new[]
            {
                new ApiKey { Id = 5001, UserId = 1, Key = "sk-dev-aaa111bbb222ccc333", Name = "Development Key", CreatedAt = DateTime.UtcNow.AddDays(-30) },
                new ApiKey { Id = 5002, UserId = 2, Key = "sk-prod-xxx999yyy888zzz777", Name = "Production Key", CreatedAt = DateTime.UtcNow.AddDays(-60) },
                new ApiKey { Id = 5003, UserId = 3, Key = "sk-test-123abc456def789ghi", Name = "Test Key", CreatedAt = DateTime.UtcNow.AddDays(-15) },
                new ApiKey { Id = 5004, UserId = 4, Key = "sk-admin-master-key-2024", Name = "Master Admin Key", CreatedAt = DateTime.UtcNow.AddDays(-90) },
                new ApiKey { Id = 5005, UserId = 5, Key = "sk-api-public-readonly-key", Name = "Public API Key", CreatedAt = DateTime.UtcNow.AddDays(-7) }
            };
            context.ApiKeys.AddRange(apiKeys);


        }

        private static void SeedAuthenticationData(AppDbContext context)
        {
            // Utilisateurs d'authentification
            var authUsers = new[]
            {
                new AuthUser
                {
                    Id = 101,
                    Email = "admin@vulnerable.com",
                    Password = "admin123", // VULNÉRABLE: Mot de passe en clair
                    Role = "Admin",
                    CreatedAt = DateTime.UtcNow.AddDays(-90),
                    IsActive = true,
                    LastLoginAt = DateTime.UtcNow.AddHours(-2)
                },
                new AuthUser
                {
                    Id = 102,
                    Email = "user@vulnerable.com",
                    Password = "user123",
                    Role = "User",
                    CreatedAt = DateTime.UtcNow.AddDays(-60),
                    IsActive = true,
                    LastLoginAt = DateTime.UtcNow.AddDays(-1)
                },
                new AuthUser
                {
                    Id = 103,
                    Email = "test@vulnerable.com",
                    Password = "test123",
                    Role = "User",
                    CreatedAt = DateTime.UtcNow.AddDays(-30),
                    IsActive = true
                },
                new AuthUser
                {
                    Id = 104,
                    Email = "demo@vulnerable.com",
                    Password = "demo", // VULNÉRABLE: Mot de passe très faible
                    Role = "User",
                    CreatedAt = DateTime.UtcNow.AddDays(-15),
                    IsActive = true
                },
                new AuthUser
                {
                    Id = 105,
                    Email = "guest@vulnerable.com",
                    Password = "guest",
                    Role = "Guest",
                    CreatedAt = DateTime.UtcNow.AddDays(-7),
                    IsActive = true
                },
                new AuthUser
                {
                    Id = 106,
                    Email = "inactive@vulnerable.com",
                    Password = "inactive123",
                    Role = "User",
                    CreatedAt = DateTime.UtcNow.AddDays(-120),
                    IsActive = false // Compte inactif mais peut se connecter (vulnérable)
                }
            };
            context.AuthUsers.AddRange(authUsers);

            // Clés API pour les utilisateurs d'authentification
            var authApiKeys = new[]
            {
                new UserApiKey
                {
                    Id = 101,
                    UserId = 101,
                    Key = "sk_101_1234567890123", // VULNÉRABLE: Format prévisible
                    Name = "Admin Master Key",
                    CreatedAt = DateTime.UtcNow.AddDays(-30),
                    LastUsedAt = DateTime.UtcNow.AddHours(-1)
                },
                new UserApiKey
                {
                    Id = 102,
                    UserId = 102,
                    Key = "sk_102_9876543210987",
                    Name = "User Default Key",
                    CreatedAt = DateTime.UtcNow.AddDays(-20)
                },
                new UserApiKey
                {
                    Id = 103,
                    UserId = 101,
                    Key = "sk_101_backup_key_2024",
                    Name = "Admin Backup Key",
                    CreatedAt = DateTime.UtcNow.AddDays(-10),
                    ExpiresAt = DateTime.UtcNow.AddDays(-5) // VULNÉRABLE: Clé expirée mais non vérifiée
                }
            };
            context.UserApiKeys.AddRange(authApiKeys);
        }

        private static void SeedBoplaData(AppDbContext context)
        {

            // CLEANUP avant d'insérer
            context.UserProfiles.RemoveRange(context.UserProfiles);
            context.Products.RemoveRange(context.Products);
            context.CompanyData.RemoveRange(context.CompanyData);
            context.EmployeeRecords.RemoveRange(context.EmployeeRecords);
            context.SaveChanges();


            // User Profiles avec données sensibles
            var userProfiles = new[]
            {
                new UserProfile
                {
                    Id = 1,
                    Username = "john.doe",
                    Email = "john.doe@company.com",
                    Phone = "+1-555-0123",
                    Address = "123 Main St, Anytown, USA",
                    DateOfBirth = new DateTime(1985, 5, 15),
                    SocialSecurityNumber = "123-45-6789",
                    Salary = 75000,
                    InternalNotes = "Good performer, eligible for promotion",
                    IsVip = false,
                    CreditLimit = 10000,
                    SecurityQuestion = "Mother's maiden name",
                    SecurityAnswer = "Smith",
                    CreatedAt = DateTime.UtcNow.AddYears(-2),
                    AccessLevel = 1,
                    IsActive = true,
                    AccountStatus = "Active",
                    LastLoginAt = DateTime.UtcNow.AddHours(-2),
                    LastLoginIp = "192.168.1.100",
                    FailedLoginAttempts = 0
                },
                new UserProfile
                {
                    Id = 2,
                    Username = "jane.smith",
                    Email = "jane.smith@company.com",
                    Phone = "+1-555-0124",
                    Address = "456 Oak Ave, Another City, USA",
                    DateOfBirth = new DateTime(1990, 8, 22),
                    SocialSecurityNumber = "987-65-4321",
                    Salary = 95000,
                    InternalNotes = "VIP customer, handle with care",
                    IsVip = true,
                    CreditLimit = 50000,
                    SecurityQuestion = "First pet's name",
                    SecurityAnswer = "Fluffy",
                    CreatedAt = DateTime.UtcNow.AddYears(-1),
                    AccessLevel = 2,
                    IsActive = true,
                    AccountStatus = "Premium",
                    LastLoginAt = DateTime.UtcNow.AddDays(-1),
                    LastLoginIp = "192.168.1.101",
                    FailedLoginAttempts = 0
                },
                new UserProfile
                {
                    Id = 3,
                    Username = "admin.user",
                    Email = "admin@company.com",
                    Phone = "+1-555-0125",
                    Address = "789 Admin Blvd, Tech City, USA",
                    DateOfBirth = new DateTime(1980, 1, 1),
                    SocialSecurityNumber = "111-22-3333",
                    Salary = 150000,
                    InternalNotes = "System administrator - full access",
                    IsVip = true,
                    CreditLimit = 100000,
                    SecurityQuestion = "Favorite color",
                    SecurityAnswer = "Blue",
                    CreatedAt = DateTime.UtcNow.AddYears(-5),
                    AccessLevel = 99,
                    IsActive = true,
                    AccountStatus = "Admin",
                    LastLoginAt = DateTime.UtcNow,
                    LastLoginIp = "10.0.0.1",
                    FailedLoginAttempts = 0
                }
            };
            context.UserProfiles.AddRange(userProfiles);

            // Products avec données internes
            var products = new[]
            {
                new Product
                {
                    Id = 1,
                    Name = "Premium Widget",
                    Description = "Our flagship product",
                    Price = 99.99m,
                    Stock = 1000,
                    Category = "Electronics",
                    Cost = 25.00m,
                    Markup = 299.96m,
                    SupplierName = "TechCorp Shanghai",
                    SupplierContact = "supplier@techcorp.cn",
                    InternalSku = "WDG-001-PREM",
                    WarehouseLocation = 5,
                    ProfitMargin = 74.99m,
                    IsFeatured = true,
                    IsActive = true,
                    DisplayOrder = 1,
                    PromotionEndDate = DateTime.UtcNow.AddDays(30),
                    SpecialPrice = 79.99m
                },
                new Product
                {
                    Id = 2,
                    Name = "Basic Gadget",
                    Description = "Entry level product",
                    Price = 29.99m,
                    Stock = 5000,
                    Category = "Electronics",
                    Cost = 5.00m,
                    Markup = 499.80m,
                    SupplierName = "BudgetSupplies Inc",
                    SupplierContact = "orders@budgetsupplies.com",
                    InternalSku = "GDG-002-BASIC",
                    WarehouseLocation = 3,
                    ProfitMargin = 24.99m,
                    IsFeatured = false,
                    IsActive = true,
                    DisplayOrder = 5
                },
                new Product
                {
                    Id = 3,
                    Name = "Enterprise Solution",
                    Description = "Complete business package",
                    Price = 4999.99m,
                    Stock = 50,
                    Category = "Software",
                    Cost = 500.00m,
                    Markup = 899.80m,
                    SupplierName = "Internal Development",
                    SupplierContact = "dev@company.com",
                    InternalSku = "ENT-003-FULL",
                    WarehouseLocation = 1,
                    ProfitMargin = 4499.99m,
                    IsFeatured = true,
                    IsActive = true,
                    DisplayOrder = 2
                }
            };
            context.Products.AddRange(products);

            // Company Data avec informations sensibles
            var companies = new[]
            {
                new CompanyData
                {
                    Id = 1,
                    CompanyName = "TechStartup Inc",
                    Industry = "Technology",
                    Website = "www.techstartup.com",
                    AnnualRevenue = 5000000,
                    MonthlyBurn = 250000,
                    EmployeeCount = 50,
                    TaxId = "12-3456789",
                    BankAccount = "1234567890",
                    CreditLine = 1000000,
                    InvestorNotes = "Series A completed, preparing for Series B",
                    ClientList = new List<string> { "Microsoft", "Google", "Amazon" },
                    RevenueByClient = new Dictionary<string, decimal>
                    {
                        ["Microsoft"] = 2000000,
                        ["Google"] = 1500000,
                        ["Amazon"] = 1500000
                    },
                    BusinessPlan = "Expand to European market in Q3",
                    CompetitiveAdvantage = "Proprietary AI algorithm",
                    TradeSecrets = new List<string> { "Algorithm details", "Client acquisition strategy" },
                    FinancialMetrics = new Dictionary<string, object>
                    {
                        ["GrossMargin"] = 0.75,
                        ["NetMargin"] = 0.15,
                        ["RunwayMonths"] = 18
                    }
                }
            };
            context.CompanyData.AddRange(companies);

            // Employee Records avec données RH sensibles
            var employees = new[]
            {
                new EmployeeRecord
                {
                    Id = 1,
                    EmployeeId = "EMP001",
                    FirstName = "Alice",
                    LastName = "Johnson",
                    Department = "Engineering",
                    Position = "Senior Developer",
                    BaseSalary = 120000,
                    Bonus = 24000,
                    PerformanceRating = "Exceeds Expectations",
                    ManagerNotes = "Strong technical skills, good team player",
                    Complaints = new List<string>(),
                    IsOnPip = false,
                    HomeAddress = "123 Developer Lane",
                    PersonalEmail = "alice.j@personal.com",
                    EmergencyContact = "Bob Johnson - 555-0199",
                    PersonalInfo = new Dictionary<string, string>
                    {
                        ["SpouseName"] = "Bob Johnson",
                        ["Children"] = "2"
                    }
                },
                new EmployeeRecord
                {
                    Id = 2,
                    EmployeeId = "EMP002",
                    FirstName = "Bob",
                    LastName = "Williams",
                    Department = "Sales",
                    Position = "Account Manager",
                    BaseSalary = 80000,
                    Bonus = 40000,
                    PerformanceRating = "Meets Expectations",
                    ManagerNotes = "Struggling with new CRM system",
                    Complaints = new List<string> { "Late to meetings", "Missed quota Q2" },
                    IsOnPip = true,
                    TerminationDate = DateTime.UtcNow.AddMonths(3),
                    TerminationReason = "Performance issues",
                    HomeAddress = "456 Sales Street",
                    PersonalEmail = "bwilliams@email.com",
                    EmergencyContact = "Carol Williams - 555-0200",
                    MedicalConditions = "Diabetes Type 2",
                    PersonalInfo = new Dictionary<string, string>
                    {
                        ["SpouseName"] = "Carol Williams",
                        ["PreviousEmployer"] = "CompetitorCorp"
                    }
                }
            };
            context.EmployeeRecords.AddRange(employees);
        }

        private static void SeedFunctionLevelAuthTestData(AppDbContext context)
        {
            context.Users.RemoveRange(context.Users);
            context.UserProfiles.RemoveRange(context.UserProfiles);
            context.SaveChanges();

            // Users avec rôles variés
            var users = new List<User>
            {
                new User { Id = 1, Email = "admin@test.local", Role = "Admin" },
                new User { Id = 2, Email = "manager@test.local", Role = "Manager" },
                new User { Id = 3, Email = "user1@test.local", Role = "User" },
                new User { Id = 4, Email = "user2@test.local", Role = "User" }
            };
            context.Users.AddRange(users);

            // UserProfiles pour correspondre aux Users
            var profiles = new List<UserProfile>
            {
                new UserProfile { Id = 1, Username = "admin", Email = "admin@test.local" },
                new UserProfile { Id = 2, Username = "manager", Email = "manager@test.local" },
                new UserProfile { Id = 3, Username = "user1", Email = "user1@test.local" },
                new UserProfile { Id = 4, Username = "user2", Email = "user2@test.local" }
            };

            context.UserProfiles.AddRange(profiles);

            context.SaveChanges();
        }

        private static void SeedInventoryData(AppDbContext context)
        {
            // API Endpoints
            var endpoints = new[]
            {
                new ApiEndpoint
                {
                    Id = 1,
                    Path = "/api/v1/users",
                    Method = "GET",
                    Version = "1.0",
                    IsDeprecated = true,
                    IsInternal = false,
                    RequiresAuth = false,
                    Description = "Legacy user endpoint - DEPRECATED",
                    CreatedAt = DateTime.UtcNow.AddYears(-3),
                    DeprecatedAt = DateTime.UtcNow.AddYears(-1),
                    Permissions = new List<string> { "read:users" }
                },
                new ApiEndpoint
                {
                    Id = 2,
                    Path = "/api/v2/users",
                    Method = "GET",
                    Version = "2.0",
                    IsDeprecated = false,
                    IsInternal = false,
                    RequiresAuth = true,
                    Description = "Current user endpoint",
                    CreatedAt = DateTime.UtcNow.AddYears(-1),
                    Permissions = new List<string> { "read:users", "read:profiles" }
                },
                new ApiEndpoint
                {
                    Id = 3,
                    Path = "/api/internal/debug/users",
                    Method = "GET",
                    Version = "internal",
                    IsDeprecated = false,
                    IsInternal = true,
                    RequiresAuth = false,
                    Description = "Internal debugging endpoint - DO NOT EXPOSE",
                    CreatedAt = DateTime.UtcNow.AddMonths(-6),
                    Permissions = new List<string> { "admin:debug" }
                },
                new ApiEndpoint
                {
                    Id = 4,
                    Path = "/api/v2-beta/users",
                    Method = "GET",
                    Version = "2.0-beta",
                    IsDeprecated = false,
                    IsInternal = false,
                    RequiresAuth = false,
                    Description = "Beta endpoint with experimental features",
                    CreatedAt = DateTime.UtcNow.AddMonths(-2),
                    Permissions = new List<string> { "beta:access" }
                },
                new ApiEndpoint
                {
                    Id = 5,
                    Path = "/api/admin/users/delete-all",
                    Method = "DELETE",
                    Version = "admin",
                    IsDeprecated = false,
                    IsInternal = true,
                    RequiresAuth = true,
                    Description = "Dangerous admin endpoint",
                    CreatedAt = DateTime.UtcNow.AddYears(-2),
                    Permissions = new List<string> { "admin:delete-all" }
                }
            };
            context.ApiEndpoints.AddRange(endpoints);

            // API Versions
            var versions = new[]
            {
                new ApiVersion
                {
                    Id = 1,
                    Version = "1.0",
                    IsActive = true,
                    IsPublic = true,
                    ReleaseDate = DateTime.UtcNow.AddYears(-3),
                    EndOfLifeDate = DateTime.UtcNow.AddMonths(-6),
                    ReleaseNotes = "Initial release - deprecated",
                    Features = new List<string> { "Basic CRUD", "No authentication" },
                    Configuration = new Dictionary<string, object>
                    {
                        ["MaxRequestSize"] = "1MB",
                        ["RateLimitPerMinute"] = 60
                    }
                },
                new ApiVersion
                {
                    Id = 2,
                    Version = "2.0",
                    IsActive = true,
                    IsPublic = true,
                    ReleaseDate = DateTime.UtcNow.AddYears(-1),
                    ReleaseNotes = "Current stable version",
                    Features = new List<string> { "Authentication", "Rate limiting", "Pagination" },
                    Configuration = new Dictionary<string, object>
                    {
                        ["MaxRequestSize"] = "10MB",
                        ["RateLimitPerMinute"] = 100,
                        ["RequiresApiKey"] = true
                    }
                },
                new ApiVersion
                {
                    Id = 3,
                    Version = "2.0-beta",
                    IsActive = true,
                    IsPublic = false,
                    ReleaseDate = DateTime.UtcNow.AddMonths(-2),
                    ReleaseNotes = "Beta version - testing new features",
                    Features = new List<string> { "GraphQL support", "WebSockets", "Bulk operations" },
                    Configuration = new Dictionary<string, object>
                    {
                        ["EnableDebugMode"] = true,
                        ["ExposeInternalErrors"] = true
                    }
                },
                new ApiVersion
                {
                    Id = 4,
                    Version = "3.0-alpha",
                    IsActive = true,
                    IsPublic = false,
                    ReleaseDate = DateTime.UtcNow,
                    ReleaseNotes = "Alpha version - internal testing only",
                    Features = new List<string> { "AI integration", "Blockchain support" },
                    Configuration = new Dictionary<string, object>
                    {
                        ["ExperimentalFeatures"] = true,
                        ["BypassSecurity"] = true
                    }
                }
            };
            context.ApiVersions.AddRange(versions);

            // Service Registry
            var services = new[]
            {
                new ServiceRegistry
                {
                    Id = 1,
                    ServiceName = "UserService",
                    ServiceUrl = "http://internal-users.local:8080",
                    Environment = "Production",
                    IsActive = true,
                    ApiKey = "sk-prod-user-service-key-123456",
                    ConnectionString = "Server=prod-db;Database=Users;User=sa;Password=P@ssw0rd123",
                    Headers = new Dictionary<string, string>
                    {
                        ["X-Internal-Auth"] = "Bearer internal-token-123",
                        ["X-Service-Secret"] = "super-secret-value"
                    },
                    AllowedIPs = new List<string> { "10.0.0.0/8", "172.16.0.0/12" }
                },
                new ServiceRegistry
                {
                    Id = 2,
                    ServiceName = "PaymentService",
                    ServiceUrl = "https://payments.internal:443",
                    Environment = "Production",
                    IsActive = true,
                    ApiKey = "sk-prod-payment-key-789",
                    ConnectionString = "Server=payment-db;Database=Payments;User=payment_user;Password=PaymentPass123!",
                    Headers = new Dictionary<string, string>
                    {
                        ["X-Payment-Token"] = "payment-secret-token"
                    }
                },
                new ServiceRegistry
                {
                    Id = 3,
                    ServiceName = "DebugService",
                    ServiceUrl = "http://debug.local:9999",
                    Environment = "Development",
                    IsActive = true,
                    ApiKey = "debug-key-insecure",
                    Headers = new Dictionary<string, string>
                    {
                        ["X-Debug-Mode"] = "true",
                        ["X-Bypass-Auth"] = "true"
                    }
                }
            };
            context.ServiceRegistries.AddRange(services);

            // Swagger Config
            var swaggerConfig = new SwaggerConfig
            {
                Id = 1,
                Version = "1.0",
                ExposeInternalEndpoints = true,
                ShowDetailedErrors = true,
                IncludeDebugInfo = true,
                HiddenEndpoints = new List<string>
                {
                    "/api/internal/*",
                    "/api/admin/*",
                    "/api/debug/*",
                    "/api/v1/*"
                },
                CustomHeaders = new Dictionary<string, string>
                {
                    ["X-Swagger-Internal"] = "true",
                    ["X-Show-Hidden"] = "true"
                }
            };
            context.SwaggerConfigs.Add(swaggerConfig);

            // Legacy Endpoints
            var legacyEndpoints = new[]
            {
                new LegacyEndpoint
                {
                    Id = 1,
                    OriginalPath = "/api/users",
                    LegacyPath = "/legacy/api/userData.php",
                    Method = "GET",
                    IsStillActive = true,
                    CreatedAt = DateTime.UtcNow.AddYears(-5),
                    SecurityIssues = "No authentication, SQL injection vulnerable"
                },
                new LegacyEndpoint
                {
                    Id = 2,
                    OriginalPath = "/api/login",
                    LegacyPath = "/admin/login.aspx",
                    Method = "POST",
                    IsStillActive = true,
                    RedirectTo = "/api/auth/login",
                    CreatedAt = DateTime.UtcNow.AddYears(-4),
                    SecurityIssues = "Weak session management, plaintext passwords"
                }
            };
            context.LegacyEndpoints.AddRange(legacyEndpoints);

            // Internal Services
            var internalServices = new[]
            {
                new InternalService
                {
                    Id = 1,
                    ServiceName = "AdminPanel",
                    InternalUrl = "http://admin.internal:8888",
                    DatabaseConnection = "Server=admin-db;Database=AdminDB;User=admin;Password=Admin123!",
                    AdminCredentials = "admin:administrator123",
                    IsExposedExternally = true,
                    Port = 8888,
                    Secrets = new Dictionary<string, string>
                    {
                        ["JWT_SECRET"] = "super-secret-jwt-key-do-not-share",
                        ["ENCRYPTION_KEY"] = "AES256-encryption-key-12345",
                        ["MASTER_PASSWORD"] = "MasterPassword123!"
                    }
                },
                new InternalService
                {
                    Id = 2,
                    ServiceName = "MonitoringService",
                    InternalUrl = "http://monitoring.local:9090",
                    AdminCredentials = "monitor:Monitor@2024",
                    IsExposedExternally = false,
                    Port = 9090,
                    Secrets = new Dictionary<string, string>
                    {
                        ["GRAFANA_API_KEY"] = "grafana-key-123",
                        ["PROMETHEUS_TOKEN"] = "prometheus-bearer-token"
                    }
                }
            };
            context.InternalServices.AddRange(internalServices);

            // API Documentation
            var documentation = new[]
            {
                new ApiDocumentation
                {
                    Id = 1,
                    EndpointPath = "/api/v2/users",
                    Method = "GET",
                    RequestSchema = "{ page: number, limit: number }",
                    ResponseSchema = "{ data: User[], total: number }",
                    RequiredHeaders = new List<string> { "Authorization", "X-API-Key" },
                    Examples = new Dictionary<string, string>
                    {
                        ["GetAllUsers"] = "GET /api/v2/users?page=1&limit=10",
                        ["GetUserById"] = "GET /api/v2/users/123"
                    },
                    IsPubliclyDocumented = true
                },
                new ApiDocumentation
                {
                    Id = 2,
                    EndpointPath = "/api/internal/debug/users",
                    Method = "GET",
                    RequestSchema = "{}",
                    ResponseSchema = "{ users: User[], debug: DebugInfo }",
                    RequiredHeaders = new List<string> { "X-Debug-Token" },
                    Examples = new Dictionary<string, string>
                    {
                        ["DebugAllUsers"] = "GET /api/internal/debug/users",
                        ["DebugWithSQL"] = "GET /api/internal/debug/users?showSql=true"
                    },
                    IsPubliclyDocumented = false,
                    InternalNotes = "NEVER expose this endpoint publicly - contains sensitive debug information"
                }
            };
            context.ApiDocumentations.AddRange(documentation);
        }

        private static void SeedUnsafeConsumptionData(AppDbContext context)
        {
            // External API Configurations
            var apiConfigs = new[]
            {
                new ExternalApiConfig
                {
                    Id = 1,
                    Name = "WeatherAPI",
                    BaseUrl = "http://api.weather-provider.com", // VULNÉRABLE: HTTP au lieu de HTTPS
                    ApiKey = "demo-key-12345",
                    ValidateSsl = false, // VULNÉRABLE: SSL désactivé
                    TimeoutSeconds = 300, // VULNÉRABLE: Timeout très long
                    LogResponses = true, // VULNÉRABLE: Log les réponses
                    Headers = new Dictionary<string, string>
                    {
                        ["X-Api-Version"] = "1.0",
                        ["X-Client-Id"] = "internal-system"
                    }
                },
                new ExternalApiConfig
                {
                    Id = 2,
                    Name = "PaymentProcessor",
                    BaseUrl = "http://payment-processor.external", // VULNÉRABLE: HTTP
                    ApiKey = "sk_live_payment_key_123456",
                    ValidateSsl = false,
                    TimeoutSeconds = 0, // VULNÉRABLE: Pas de timeout
                    LogResponses = true,
                    Headers = new Dictionary<string, string>
                    {
                        ["Authorization"] = "Bearer hardcoded-token",
                        ["X-Merchant-Id"] = "MERCHANT-001"
                    }
                },
                new ExternalApiConfig
                {
                    Id = 3,
                    Name = "UserVerification",
                    BaseUrl = "http://verification.untrusted-api.com",
                    ApiKey = "verification-api-key-789",
                    ValidateSsl = false,
                    TimeoutSeconds = 60,
                    LogResponses = true,
                    Headers = new Dictionary<string, string>
                    {
                        ["X-Verification-Level"] = "full",
                        ["X-Include-Sensitive"] = "true"
                    }
                },
                new ExternalApiConfig
                {
                    Id = 4,
                    Name = "GeoLocation",
                    BaseUrl = "http://geo.tracking-service.net",
                    ApiKey = null, // VULNÉRABLE: Pas d'API key
                    ValidateSsl = false,
                    TimeoutSeconds = 30,
                    LogResponses = true,
                    Headers = new Dictionary<string, string>()
                },
                new ExternalApiConfig
                {
                    Id = 5,
                    Name = "TranslationService",
                    BaseUrl = "http://translate.untrusted.api",
                    ApiKey = "translate-key-456",
                    ValidateSsl = false,
                    TimeoutSeconds = 120,
                    LogResponses = true,
                    Headers = new Dictionary<string, string>
                    {
                        ["X-Auto-Detect"] = "true",
                        ["X-Execute-Scripts"] = "true" // VULNÉRABLE
                    }
                },
                new ExternalApiConfig
                {
                    Id = 6,
                    Name = "FileStorage",
                    BaseUrl = "http://file-storage.untrusted.com",
                    ApiKey = "storage-key-999",
                    ValidateSsl = false,
                    TimeoutSeconds = 600, // VULNÉRABLE: 10 minutes timeout
                    LogResponses = false,
                    Headers = new Dictionary<string, string>
                    {
                        ["X-Public-Access"] = "true",
                        ["X-Skip-Validation"] = "true"
                    }
                }
            };
            context.ExternalApiConfigs.AddRange(apiConfigs);

            // Sample Payment Responses (showing stored sensitive data)
            var paymentResponses = new[]
            {
                new PaymentResponse
                {
                    TransactionId = "TXN-001-VULN",
                    Status = "success",
                    ProcessorResponse = new Dictionary<string, object>
                    {
                        ["cardLast4"] = "1234",
                        ["authCode"] = "AUTH123",
                        ["processorId"] = "PROC-001",
                        ["rawCardNumber"] = "4111111111111111" // VULNÉRABLE: Numéro de carte stocké
                    },
                    RawResponse = "{\"status\":\"success\",\"card\":\"4111111111111111\",\"cvv\":\"123\"}" // VULNÉRABLE
                },
                new PaymentResponse
                {
                    TransactionId = "TXN-002-FAIL",
                    Status = "failed",
                    ErrorMessage = "Insufficient funds",
                    ProcessorResponse = new Dictionary<string, object>
                    {
                        ["errorCode"] = "INSUFFICIENT_FUNDS",
                        ["attemptedAmount"] = 5000,
                        ["availableBalance"] = 1000, // VULNÉRABLE: Expose le solde
                        ["accountNumber"] = "ACC-12345"
                    },
                    RawResponse = "{\"error\":\"Insufficient funds\",\"balance\":1000}"
                }
            };
            context.PaymentResponses.AddRange(paymentResponses);
        }

        // Méthode utilitaire pour créer des fichiers de documents (si nécessaire)
        public static void CreateDocumentFiles(IWebHostEnvironment env, IEnumerable<Document> documents)
        {
            foreach (var doc in documents)
            {
                var relativePath = doc.FilePath.TrimStart('/').Replace('/', Path.DirectorySeparatorChar);
                var fullPath = Path.Combine(env.ContentRootPath, relativePath);

                var directory = Path.GetDirectoryName(fullPath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                if (!File.Exists(fullPath))
                {
                    var content = doc.IsConfidential
                        ? $"CONFIDENTIEL - Document #{doc.Id}\nUtilisateur: {doc.UserId}\nFichier: {doc.FileName}"
                        : $"Document #{doc.Id}\nUtilisateur: {doc.UserId}\nFichier: {doc.FileName}";

                    File.WriteAllText(fullPath, content);
                }
            }
        }
    }
}