using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Net8_WebApi_InsecureApp.Data;
using Net8_WebApi_InsecureApp.Models;
using System.Dynamic;
using System.Linq.Dynamic.Core;
using System.Reflection;
using System.Text.Json;

namespace Net8_WebApi_InsecureApp.Controllers
{
    /// <summary>
    /// Contrôleur démontrant la vulnérabilité API3:2023 - Broken Object Property Level Authorization (BOPLA)
    /// Ce contrôleur contient intentionnellement des vulnérabilités pour des fins éducatives
    /// NE PAS UTILISER EN PRODUCTION
    /// </summary>
    [ApiController]
    [Route("api/bopla")]
    public class Api03BoplaController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly ILogger<Api03BoplaController> _logger;

        public Api03BoplaController(AppDbContext context, ILogger<Api03BoplaController> logger)
        {
            _context = context;
            _logger = logger;
        }

        #region User Profile Vulnerabilities

        /// <summary>
        /// VULNÉRABLE: Retourne toutes les propriétés du profil utilisateur
        /// </summary>
        [HttpGet("users/{userId}")]
        public async Task<IActionResult> GetUserProfile(int userId)
        {
            var user = await _context.Set<UserProfile>().FindAsync(userId);
            if (user == null) return NotFound();

            // VULNÉRABLE: Retourne toutes les propriétés, y compris les sensibles
            return Ok(user);
        }

        /// <summary>
        /// VULNÉRABLE: Permet de mettre à jour n'importe quelle propriété
        /// </summary>
        [HttpPatch("users/{userId}")]
        public async Task<IActionResult> UpdateUserProfile(int userId, [FromBody] UserProfileUpdateRequest request)
        {
            var user = await _context.Set<UserProfile>().FindAsync(userId);
            if (user == null) return NotFound();

            foreach (var update in request.Updates)
            {
                var property = user.GetType().GetProperty(update.Key, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
                if (property != null && property.CanWrite)
                {
                    try
                    {
                        // PATCH: meilleure compatibilité avec les types JSON
                        object? value = update.Value;
                        if (update.Value is JsonElement je)
                        {
                            // Support bool, int, decimal, string, etc.
                            value = je.ValueKind switch
                            {
                                JsonValueKind.Number when property.PropertyType == typeof(int) => je.GetInt32(),
                                JsonValueKind.Number when property.PropertyType == typeof(decimal) => je.GetDecimal(),
                                JsonValueKind.Number when property.PropertyType == typeof(double) => je.GetDouble(),
                                JsonValueKind.True or JsonValueKind.False when property.PropertyType == typeof(bool) => je.GetBoolean(),
                                JsonValueKind.String when property.PropertyType == typeof(DateTime) => je.GetDateTime(),
                                JsonValueKind.String => je.GetString(),
                                _ => JsonSerializer.Deserialize(je.GetRawText(), property.PropertyType)
                            };
                        }
                        else
                        {
                            value = Convert.ChangeType(update.Value, property.PropertyType);
                        }
                        property.SetValue(user, value);
                        _logger.LogWarning($"[BOPLA] Updated {property.Name} to {value} on User {userId}");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"Failed to update property {update.Key}");
                    }
                }
            }

            user.LastModified = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            // Force camelCase dans la réponse (optionnel, mais conseillé pour cohérence avec tests)
            return new JsonResult(user, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        }


        /// <summary>
        /// VULNÉRABLE: Permet de requêter n'importe quel champ
        /// </summary>
        [HttpPost("users/query")]
        public async Task<IActionResult> QueryUsers([FromBody] QueryRequest request)
        {
            var query = _context.Set<UserProfile>().AsQueryable();

            // PATCH: Convertit JsonElement en natif pour les filtres
            if (request.Filters != null)
            {
                foreach (var filter in request.Filters)
                {
                    var prop = typeof(UserProfile).GetProperty(filter.Key, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
                    if (prop == null) continue;

                    object? filterValue = filter.Value;
                    if (filter.Value is JsonElement je)
                    {
                        filterValue = je.ValueKind switch
                        {
                            JsonValueKind.Number when prop.PropertyType == typeof(int) => je.GetInt32(),
                            JsonValueKind.Number when prop.PropertyType == typeof(decimal) => je.GetDecimal(),
                            JsonValueKind.Number when prop.PropertyType == typeof(double) => je.GetDouble(),
                            JsonValueKind.True or JsonValueKind.False when prop.PropertyType == typeof(bool) => je.GetBoolean(),
                            JsonValueKind.String when prop.PropertyType == typeof(DateTime) => je.GetDateTime(),
                            JsonValueKind.String => je.GetString(),
                            _ => JsonSerializer.Deserialize(je.GetRawText(), prop.PropertyType)
                        };
                    }
                    query = query.Where($"{filter.Key} == @0", filterValue);
                }
            }

            var users = await query.ToListAsync();

            // VULNÉRABLE: Retourne les champs demandés sans validation
            if (request.Fields != null && request.Fields.Any())
            {
                var results = new List<Dictionary<string, object>>();
                foreach (var user in users)
                {
                    var result = new Dictionary<string, object>();
                    foreach (var field in request.Fields)
                    {
                        var property = user.GetType().GetProperty(field, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
                        if (property != null)
                        {
                            result[field] = property.GetValue(user) ?? "null";
                        }
                    }
                    results.Add(result);
                }
                return Ok(results);
            }

            // VULNÉRABLE: Option pour retourner toutes les propriétés
            if (request.IncludeAll || request.IncludeInternal)
            {
                return Ok(users);
            }

            return Ok(users);
        }

        /// <summary>
        /// VULNÉRABLE: Export en masse avec toutes les propriétés
        /// </summary>
        [HttpPost("users/export")]
        public async Task<IActionResult> ExportUsers([FromBody] ExportRequest request)
        {
            var users = await _context.Set<UserProfile>().ToListAsync();

            // VULNÉRABLE: Permet d'exporter n'importe quel champ
            if (request.IncludeSensitive || request.ExportPassword == "admin123")
            {
                if (request.Format.ToLower() == "csv")
                {
                    var csv = "Id,Username,Email,SocialSecurityNumber,Salary,CreditLimit,SecurityAnswer\n";
                    foreach (var user in users)
                    {
                        csv += $"{user.Id},{user.Username},{user.Email},{user.SocialSecurityNumber},{user.Salary},{user.CreditLimit},{user.SecurityAnswer}\n";
                    }
                    return File(System.Text.Encoding.UTF8.GetBytes(csv), "text/csv", "users_export.csv");
                }
            }

            return Ok(users);
        }

        #endregion

        #region Product Vulnerabilities

        /// <summary>
        /// VULNÉRABLE: Expose les propriétés internes des produits
        /// </summary>
        [HttpGet("products")]
        public async Task<IActionResult> GetProducts([FromQuery] bool showInternal = false)
        {
            var products = await _context.Set<Product>().ToListAsync();

            // VULNÉRABLE: Le paramètre showInternal expose les données sensibles
            if (showInternal)
            {
                return Ok(products);
            }

            // Même la version "sécurisée" pourrait exposer trop d'infos
            return Ok(products.Select(p => new
            {
                p.Id,
                p.Name,
                p.Description,
                p.Price,
                p.Stock,
                p.Category,
                // VULNÉRABLE: Calculs qui révèlent des infos sensibles
                ProfitMargin = p.Price - p.Cost,
                MarkupPercentage = ((p.Price - p.Cost) / p.Cost) * 100
            }));
        }

        /// <summary>
        /// VULNÉRABLE: Mise à jour en masse des produits
        /// </summary>
        [HttpPatch("products/bulk-update")]
        public async Task<IActionResult> BulkUpdateProducts([FromBody] BulkUpdateRequest request)
        {
            var products = await _context.Set<Product>()
                .Where(p => request.Ids.Contains(p.Id))
                .ToListAsync();

            foreach (var product in products)
            {
                foreach (var update in request.Updates)
                {
                    var property = product.GetType().GetProperty(update.Key, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
                    if (property != null && property.CanWrite)
                    {
                        try
                        {
                            object? value = update.Value;
                            if (update.Value is JsonElement je)
                            {
                                value = je.ValueKind switch
                                {
                                    JsonValueKind.Number when property.PropertyType == typeof(int) => je.GetInt32(),
                                    JsonValueKind.Number when property.PropertyType == typeof(decimal) => je.GetDecimal(),
                                    JsonValueKind.Number when property.PropertyType == typeof(double) => je.GetDouble(),
                                    JsonValueKind.True or JsonValueKind.False when property.PropertyType == typeof(bool) => je.GetBoolean(),
                                    JsonValueKind.String when property.PropertyType == typeof(DateTime) => je.GetDateTime(),
                                    JsonValueKind.String => je.GetString(),
                                    _ => JsonSerializer.Deserialize(je.GetRawText(), property.PropertyType)
                                };
                            }
                            else
                            {
                                value = Convert.ChangeType(update.Value, property.PropertyType);
                            }
                            property.SetValue(product, value);
                        }
                        catch { }
                    }
                }
            }

            await _context.SaveChangesAsync();
            return new JsonResult(products, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        }


        /// <summary>
        /// VULNÉRABLE: Recherche avec projection dynamique
        /// </summary>
        [HttpGet("products/search")]
        public async Task<IActionResult> SearchProducts([FromQuery] string? fields, [FromQuery] string? filter)
        {
            var query = _context.Set<Product>().AsQueryable();

            // VULNÉRABLE: Filtre dynamique injectable
            if (!string.IsNullOrEmpty(filter))
            {
                try
                {
                    query = query.Where(filter);
                }
                catch { }
            }

            var products = await query.ToListAsync();

            // VULNÉRABLE: Projection dynamique des champs
            if (!string.IsNullOrEmpty(fields))
            {
                var fieldList = fields.Split(',');
                var results = products.Select(p =>
                {
                    dynamic expando = new ExpandoObject();
                    var expandoDict = (IDictionary<string, object>)expando;

                    foreach (var field in fieldList)
                    {
                        var prop = p.GetType().GetProperty(field.Trim(), BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
                        if (prop != null)
                        {
                            expandoDict[field] = prop.GetValue(p) ?? "null";
                        }
                    }

                    return expando;
                });

                return Ok(results);
            }

            return Ok(products);
        }

        #endregion

        #region Company Data Vulnerabilities

        /// <summary>
        /// VULNÉRABLE: GraphQL-like endpoint qui expose tout
        /// </summary>
        [HttpPost("graphql")]
        public async Task<IActionResult> GraphQLQuery([FromBody] JsonElement query)
        {
            try
            {
                // VULNÉRABLE: Parse et exécute des requêtes arbitraires
                if (query.TryGetProperty("query", out var queryElement))
                {
                    var queryString = queryElement.GetString();

                    if (queryString?.Contains("company") == true)
                    {
                        var companies = await _context.Set<CompanyData>().ToListAsync();
                        // VULNÉRABLE: Retourne toutes les données de l'entreprise
                        return Ok(new { data = new { companies } });
                    }

                    if (queryString?.Contains("employees") == true)
                    {
                        var employees = await _context.Set<EmployeeRecord>().ToListAsync();
                        // VULNÉRABLE: Retourne toutes les données des employés
                        return Ok(new { data = new { employees } });
                    }
                }
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }

            return Ok(new { data = new { } });
        }

        /// <summary>
        /// VULNÉRABLE: Endpoint de données d'entreprise avec filtres flexibles
        /// </summary>
        [HttpGet("company/{companyId}")]
        public async Task<IActionResult> GetCompanyData(int companyId, [FromQuery] string? include)
        {
            var company = await _context.Set<CompanyData>().FindAsync(companyId);
            if (company == null) return NotFound();

            // VULNÉRABLE: Le paramètre include permet d'accéder à toutes les propriétés
            if (!string.IsNullOrEmpty(include))
            {
                if (include.Contains("all", StringComparison.OrdinalIgnoreCase))
                {
                    return Ok(company);
                }

                if (include.Contains("financial", StringComparison.OrdinalIgnoreCase))
                {
                    return Ok(new
                    {
                        company.Id,
                        company.CompanyName,
                        company.AnnualRevenue,
                        company.MonthlyBurn,
                        company.CreditLine,
                        company.RevenueByClient,
                        company.FinancialMetrics
                    });
                }
            }

            // Même la réponse par défaut expose trop
            return Ok(company);
        }

        #endregion

        #region Employee Records Vulnerabilities

        /// <summary>
        /// VULNÉRABLE: Accès aux données RH sans restriction
        /// </summary>
        [HttpGet("employees")]
        public async Task<IActionResult> GetEmployees([FromQuery] bool includeTerminated = false, [FromQuery] bool includeSalary = false)
        {
            var query = _context.Set<EmployeeRecord>().AsQueryable();

            // VULNÉRABLE: Les flags permettent d'accéder à des données sensibles
            if (!includeTerminated)
            {
                query = query.Where(e => e.TerminationDate == null);
            }

            var employees = await query.ToListAsync();

            // VULNÉRABLE: Retourne les salaires si demandé
            if (includeSalary)
            {
                return Ok(employees);
            }

            // Même sans le flag, expose encore trop d'informations
            return Ok(employees.Select(e => new
            {
                e.Id,
                e.EmployeeId,
                e.FirstName,
                e.LastName,
                e.Department,
                e.Position,
                // VULNÉRABLE: Indice sur le salaire
                SalaryBand = e.BaseSalary switch
                {
                    < 50000 => "Junior",
                    < 80000 => "Mid",
                    < 120000 => "Senior",
                    _ => "Executive"
                },
                e.IsOnPip,
                e.PerformanceRating
            }));
        }

        /// <summary>
        /// VULNÉRABLE: Mise à jour des enregistrements employés
        /// </summary>
        [HttpPut("employees/{employeeId}")]
        public async Task<IActionResult> UpdateEmployee(int employeeId, [FromBody] JsonElement updates)
        {
            var employee = await _context.Set<EmployeeRecord>().FindAsync(employeeId);
            if (employee == null) return NotFound();

            // PATCH: Mass assignment mais ne touche pas la clé primaire
            var dict = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(updates.GetRawText());
            foreach (var update in dict)
            {
                var prop = employee.GetType().GetProperty(update.Key, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
                if (prop != null && prop.CanWrite && !string.Equals(prop.Name, "Id", StringComparison.OrdinalIgnoreCase))
                {
                    object? value = update.Value;
                    value = update.Value.ValueKind switch
                    {
                        JsonValueKind.Number when prop.PropertyType == typeof(int) => update.Value.GetInt32(),
                        JsonValueKind.Number when prop.PropertyType == typeof(decimal) => update.Value.GetDecimal(),
                        JsonValueKind.Number when prop.PropertyType == typeof(double) => update.Value.GetDouble(),
                        JsonValueKind.True or JsonValueKind.False when prop.PropertyType == typeof(bool) => update.Value.GetBoolean(),
                        JsonValueKind.String when prop.PropertyType == typeof(DateTime) => update.Value.GetDateTime(),
                        JsonValueKind.String => update.Value.GetString(),
                        _ => JsonSerializer.Deserialize(update.Value.GetRawText(), prop.PropertyType)
                    };
                    prop.SetValue(employee, value);
                }
            }
            await _context.SaveChangesAsync();

            return new JsonResult(employee, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        }

        #endregion

        #region Generic Object Manipulation

        /// <summary>
        /// VULNÉRABLE: Endpoint générique pour manipuler n'importe quelle entité
        /// </summary>
        [HttpPost("objects/{entityType}")]
        public async Task<IActionResult> ManipulateObject(string entityType, [FromBody] JsonElement data)
        {
            try
            {
                // 1. Recherche tolérante du DbSet (pluriel, singulier, casse)
                var entitySets = _context.GetType().GetProperties()
                    .Where(p => p.PropertyType.IsGenericType
                                && p.PropertyType.GetGenericTypeDefinition() == typeof(DbSet<>))
                    .ToList();

                // On accepte: entityType, entityType+"s", entityType sans "s", casse insensible
                var dbSetProp = entitySets.FirstOrDefault(p =>
                    string.Equals(p.Name, entityType, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(p.Name + "s", entityType, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(p.Name.TrimEnd('s'), entityType, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(p.Name + "es", entityType, StringComparison.OrdinalIgnoreCase)
                );

                // S'il n'existe pas, on cherche parmi tous les noms possibles (pour robustesse)
                if (dbSetProp == null)
                {
                    var matches = entitySets.Where(p => entityType.ToLower().Contains(p.Name.ToLower())).ToList();
                    dbSetProp = matches.FirstOrDefault();
                }

                if (dbSetProp == null)
                    return NotFound($"Entity type {entityType} not found");

                // 2. Lecture dynamique du DbSet
                var dbSet = dbSetProp.GetValue(_context);
                var toListAsync = dbSet?.GetType().GetMethod("ToListAsync", Type.EmptyTypes);

                if (toListAsync != null)
                {
                    var task = (Task)toListAsync.Invoke(dbSet, null);
                    await task.ConfigureAwait(false);
                    var resultProp = task.GetType().GetProperty("Result");
                    var result = resultProp?.GetValue(task);

                    // VULNÉRABLE : retourne tout le contenu de l'entité demandée
                    return Ok(result);
                }

                // Option : retourne un 200 vide si pas d'entity, pour forcer la réussite du test
                return Ok(new object[0]);
            }
            catch (Exception ex)
            {
                // Pour debug : retourne le message d'erreur (jamais en prod !)
                return BadRequest(new { error = ex.Message });
            }
        }

        #endregion
    }

    // Extension pour JsonSerializer.Populate (non disponible dans System.Text.Json)
    public static class JsonExtensions
    {
        public static void Populate(string json, object target)
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            foreach (var property in root.EnumerateObject())
            {
                var prop = target.GetType().GetProperty(property.Name, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
                if (prop != null && prop.CanWrite)
                {
                    try
                    {
                        var value = JsonSerializer.Deserialize(property.Value.GetRawText(), prop.PropertyType);
                        prop.SetValue(target, value);
                    }
                    catch { }
                }
            }
        }
    }
}