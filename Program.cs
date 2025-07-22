using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Net8_WebApi_InsecureApp.Data;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Configuration des services
builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.ReferenceHandler =
            System.Text.Json.Serialization.ReferenceHandler.IgnoreCycles;
        options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
    });

builder.Services.AddEndpointsApiExplorer();

// Configuration de Swagger avec support JWT
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "API Vulnérable - OWASP API Security Top 10",
        Version = "v1",
        Description = "⚠️ ATTENTION: Cette API contient intentionnellement des vulnérabilités BOLA (API1:2023) et Broken Authentication (API2:2023) à des fins éducatives. NE PAS UTILISER EN PRODUCTION!",
        Contact = new OpenApiContact
        {
            Name = "Security Team",
            Email = "security@example.com"
        }
    });

    // Configuration pour l'authentification JWT dans Swagger
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// Configuration d'Entity Framework
builder.Services.AddDbContext<AppDbContext>(options =>
{
    if (builder.Environment.IsDevelopment() || builder.Environment.IsEnvironment("Testing"))
    {
        // Utiliser une base de données en mémoire pour le développement/tests
        options.UseInMemoryDatabase($"TestDb_{Guid.NewGuid()}");
        options.EnableServiceProviderCaching(false); // Désactive le cache qui cause le problème
    }
    else
    {
        // Utiliser SQL Server en production (même si on ne devrait jamais déployer cette API!)
        options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
    }
}, ServiceLifetime.Singleton);


// Configuration de l'authentification JWT (intentionnellement faible pour la démo)
var key = Encoding.ASCII.GetBytes("VeryWeakSecretKeyForDemonstrationPurposes123!");
builder.Services.AddAuthentication(x =>
{
    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(x =>
{
    x.RequireHttpsMetadata = false; // ⚠️ Vulnérable: Pas de HTTPS requis
    x.SaveToken = true;
    x.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false, // ⚠️ Vulnérable: Pas de validation de l'émetteur
        ValidateAudience = false, // ⚠️ Vulnérable: Pas de validation de l'audience
        ValidateLifetime = false, // ⚠️ Vulnérable: Pas de validation de l'expiration
        ClockSkew = TimeSpan.Zero
    };
});

// CORS permissif (pour la démo)
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll",
        builder =>
        {
            builder.AllowAnyOrigin()
                   .AllowAnyMethod()
                   .AllowAnyHeader();
        });
});

// Ajouter HttpClient factory
builder.Services.AddHttpClient();

var app = builder.Build();

// Seed de la base de données
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    var env = scope.ServiceProvider.GetRequiredService<IWebHostEnvironment>();

    context.Database.EnsureCreated();

    // Utiliser la classe DatabaseSeeder
    DatabaseSeeder.SeedDatabase(context);

    // Créer les fichiers de documents si nécessaire
    if (env.IsDevelopment() || env.IsEnvironment("Testing"))
    {
        var documents = context.Documents.ToList();
        if (documents.Any())
        {
            DatabaseSeeder.CreateDocumentFiles(env, documents);
        }
    }
}

// Configuration du pipeline HTTP
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "API Vulnérable v1");
        c.RoutePrefix = string.Empty; // Swagger à la racine
    });
}

app.UseCors("AllowAll");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

// Endpoint de santé
app.MapGet("/health", () => Results.Ok(new
{
    status = "unhealthy",
    message = "This API contains BOLA and Broken Authentication vulnerabilities!",
    timestamp = DateTime.UtcNow
}));

// Endpoint pour générer un token de test
app.MapPost("/api/auth/token", (TokenRequest request) =>
{
    // ⚠️ VULNÉRABLE: Génération de token sans vérification appropriée
    var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new System.Security.Claims.ClaimsIdentity(new[]
        {
            new System.Security.Claims.Claim("userId", request.UserId.ToString()),
            new System.Security.Claims.Claim("role", request.Role ?? "User")
        }),
        Expires = DateTime.UtcNow.AddDays(7),
        SigningCredentials = new SigningCredentials(
            new SymmetricSecurityKey(key),
            SecurityAlgorithms.HmacSha256Signature)
    };
    var token = tokenHandler.CreateToken(tokenDescriptor);
    return Results.Ok(new
    {
        token = tokenHandler.WriteToken(token),
        expiresIn = "7 days"
    });
});

app.Run();

// Classe pour la requête de token
public record TokenRequest(int UserId, string? Role);

// Rendre le Program accessible pour les tests
public partial class Program { }