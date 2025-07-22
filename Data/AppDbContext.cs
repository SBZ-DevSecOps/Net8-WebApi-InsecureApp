using Microsoft.EntityFrameworkCore;
using Net8_WebApi_InsecureApp.Controllers;
using Net8_WebApi_InsecureApp.Models;
using System.Text.Json;

namespace Net8_WebApi_InsecureApp.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        // Entités BOLA
        public DbSet<User> Users { get; set; }
        public DbSet<Order> Orders { get; set; }
        public DbSet<BankAccount> BankAccounts { get; set; }
        public DbSet<MedicalRecord> MedicalRecords { get; set; }
        public DbSet<Document> Documents { get; set; }
        public DbSet<Message> Messages { get; set; }
        public DbSet<ApiKey> ApiKeys { get; set; }

        // Entités Authentication
        public DbSet<AuthUser> AuthUsers { get; set; }
        public DbSet<UserApiKey> UserApiKeys { get; set; }

        // Entités BOPLA
        public DbSet<UserProfile> UserProfiles { get; set; }
        public DbSet<Product> Products { get; set; }
        public DbSet<CompanyData> CompanyData { get; set; }
        public DbSet<EmployeeRecord> EmployeeRecords { get; set; }


        public DbSet<ApiEndpoint> ApiEndpoints { get; set; }
        public DbSet<ApiVersion> ApiVersions { get; set; }
        public DbSet<ServiceRegistry> ServiceRegistries { get; set; }
        public DbSet<SwaggerConfig> SwaggerConfigs { get; set; }
        public DbSet<LegacyEndpoint> LegacyEndpoints { get; set; }
        public DbSet<InternalService> InternalServices { get; set; }
        public DbSet<ApiDocumentation> ApiDocumentations { get; set; }


        public DbSet<ExternalApiConfig> ExternalApiConfigs { get; set; }
        public DbSet<PaymentResponse> PaymentResponses { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // === Configuration BOLA ===

            // Configuration des relations
            modelBuilder.Entity<Order>()
                .HasOne(o => o.User)
                .WithMany(u => u.Orders)
                .HasForeignKey(o => o.UserId);

            modelBuilder.Entity<BankAccount>()
                .HasOne(b => b.User)
                .WithMany(u => u.BankAccounts)
                .HasForeignKey(b => b.UserId);

            modelBuilder.Entity<MedicalRecord>()
                .HasOne(m => m.Patient)
                .WithMany(u => u.MedicalRecords)
                .HasForeignKey(m => m.PatientId);

            modelBuilder.Entity<Document>()
                .HasOne(d => d.User)
                .WithMany(u => u.Documents)
                .HasForeignKey(d => d.UserId);

            modelBuilder.Entity<Message>()
                .HasOne(m => m.Sender)
                .WithMany()
                .HasForeignKey(m => m.SenderId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<Message>()
                .HasOne(m => m.Recipient)
                .WithMany()
                .HasForeignKey(m => m.RecipientId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<ApiKey>()
                .HasOne(a => a.User)
                .WithMany(u => u.ApiKeys)
                .HasForeignKey(a => a.UserId);

            // Index unique sur les clés API
            modelBuilder.Entity<ApiKey>()
                .HasIndex(a => a.Key)
                .IsUnique();

            // === Configuration Authentication ===

            // Configuration pour les tables d'authentification
            modelBuilder.Entity<AuthUser>()
                .HasIndex(u => u.Email)
                .IsUnique();

            modelBuilder.Entity<UserApiKey>()
                .HasOne(k => k.User)
                .WithMany(u => u.ApiKeys)
                .HasForeignKey(k => k.UserId);

            modelBuilder.Entity<UserApiKey>()
                .HasIndex(k => k.Key)
                .IsUnique();

            // === Configuration BOPLA ===

            modelBuilder.Entity<UserProfile>()
                .HasIndex(u => u.Email)
                .IsUnique();

            modelBuilder.Entity<Product>()
                .HasIndex(p => p.InternalSku)
                .IsUnique();

            modelBuilder.Entity<CompanyData>()
                .Property(c => c.ClientList)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                    v => JsonSerializer.Deserialize<List<string>>(v, (JsonSerializerOptions?)null) ?? new List<string>());

            modelBuilder.Entity<CompanyData>()
                .Property(c => c.RevenueByClient)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                    v => JsonSerializer.Deserialize<Dictionary<string, decimal>>(v, (JsonSerializerOptions?)null) ?? new Dictionary<string, decimal>());

            modelBuilder.Entity<CompanyData>()
                .Property(c => c.TradeSecrets)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                    v => JsonSerializer.Deserialize<List<string>>(v, (JsonSerializerOptions?)null) ?? new List<string>());

            modelBuilder.Entity<CompanyData>()
                .Property(c => c.FinancialMetrics)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                    v => JsonSerializer.Deserialize<Dictionary<string, object>>(v, (JsonSerializerOptions?)null) ?? new Dictionary<string, object>());

            modelBuilder.Entity<EmployeeRecord>()
                .Property(e => e.Complaints)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                    v => JsonSerializer.Deserialize<List<string>>(v, (JsonSerializerOptions?)null) ?? new List<string>());

            modelBuilder.Entity<EmployeeRecord>()
                .Property(e => e.PersonalInfo)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                    v => JsonSerializer.Deserialize<Dictionary<string, string>>(v, (JsonSerializerOptions?)null) ?? new Dictionary<string, string>());

            // === Configuration Inventory Management ===

            modelBuilder.Entity<ApiEndpoint>()
                .Property(e => e.Permissions)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                    v => JsonSerializer.Deserialize<List<string>>(v, (JsonSerializerOptions?)null) ?? new List<string>());

            modelBuilder.Entity<ApiVersion>()
                .Property(v => v.Features)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                    v => JsonSerializer.Deserialize<List<string>>(v, (JsonSerializerOptions?)null) ?? new List<string>());

            modelBuilder.Entity<ApiVersion>()
                .Property(v => v.Configuration)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                    v => JsonSerializer.Deserialize<Dictionary<string, object>>(v, (JsonSerializerOptions?)null) ?? new Dictionary<string, object>());

            modelBuilder.Entity<ServiceRegistry>()
                .Property(s => s.Headers)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                    v => JsonSerializer.Deserialize<Dictionary<string, string>>(v, (JsonSerializerOptions?)null) ?? new Dictionary<string, string>());

            modelBuilder.Entity<ServiceRegistry>()
                .Property(s => s.AllowedIPs)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                    v => JsonSerializer.Deserialize<List<string>>(v, (JsonSerializerOptions?)null) ?? new List<string>());

            modelBuilder.Entity<SwaggerConfig>()
                .Property(s => s.HiddenEndpoints)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                    v => JsonSerializer.Deserialize<List<string>>(v, (JsonSerializerOptions?)null) ?? new List<string>());

            modelBuilder.Entity<SwaggerConfig>()
                .Property(s => s.CustomHeaders)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                    v => JsonSerializer.Deserialize<Dictionary<string, string>>(v, (JsonSerializerOptions?)null) ?? new Dictionary<string, string>());

            modelBuilder.Entity<InternalService>()
                .Property(i => i.Secrets)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                    v => JsonSerializer.Deserialize<Dictionary<string, string>>(v, (JsonSerializerOptions?)null) ?? new Dictionary<string, string>());

            modelBuilder.Entity<ApiDocumentation>()
                .Property(d => d.RequiredHeaders)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                    v => JsonSerializer.Deserialize<List<string>>(v, (JsonSerializerOptions?)null) ?? new List<string>());

            modelBuilder.Entity<ApiDocumentation>()
                .Property(d => d.Examples)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                    v => JsonSerializer.Deserialize<Dictionary<string, string>>(v, (JsonSerializerOptions?)null) ?? new Dictionary<string, string>());

            // === Configuration Unsafe Consumption ===

            modelBuilder.Entity<ExternalApiConfig>()
                .Property(e => e.Headers)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                    v => JsonSerializer.Deserialize<Dictionary<string, string>>(v, (JsonSerializerOptions?)null) ?? new Dictionary<string, string>());

            modelBuilder.Entity<PaymentResponse>()
                .Property(p => p.ProcessorResponse)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
                    v => JsonSerializer.Deserialize<Dictionary<string, object>>(v, (JsonSerializerOptions?)null) ?? new Dictionary<string, object>());        

        }
        
    }
}