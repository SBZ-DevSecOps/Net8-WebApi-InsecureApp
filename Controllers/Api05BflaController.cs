using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Net8_WebApi_InsecureApp.Data;
using Net8_WebApi_InsecureApp.Models;

namespace Net8_WebApi_InsecureApp.Controllers
{
    [ApiController]
    [Route("api/bfla")]
    public class Api05BflaController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly ILogger<Api05BflaController> _logger;

        public Api05BflaController(AppDbContext context, ILogger<Api05BflaController> logger)
        {
            _context = context;
            _logger = logger;
        }

        // 1. Suppression utilisateur (admin only normalement)
        [HttpDelete("admin/delete-user/{id}")]
        public async Task<IActionResult> DeleteUser(int id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null) return NotFound();
            _context.Users.Remove(user);
            await _context.SaveChangesAsync();
            return Ok(new { deleted = id });
        }

        // 2. Élévation de privilège (admin only)
        [HttpPost("elevate/{id}")]
        public async Task<IActionResult> ElevateUserRole(int id, [FromBody] string newRole)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null) return NotFound();
            user.Role = newRole;
            await _context.SaveChangesAsync();
            return Ok(new { elevated = id, role = newRole });
        }

        // 3. Export complet des utilisateurs (admin only)
        [HttpGet("admin/export-users")]
        public async Task<IActionResult> ExportUsers()
        {
            var users = await _context.Users.ToListAsync();
            var csv = "Id,Email,Role\n" + string.Join("\n", users.Select(u => $"{u.Id},{u.Email},{u.Role}"));
            var bytes = System.Text.Encoding.UTF8.GetBytes(csv);
            return File(bytes, "text/csv", "users.csv");
        }

        // 4. Changement de config sensible (admin only)
        [HttpPost("admin/set-config")]
        public IActionResult SetConfig([FromBody] ConfigModel model)
        {
            // Modifie la config globale (ex : maintenance mode)
            // Vulnérabilité : tout le monde peut la changer
            return Ok(new { updated = true, config = model });
        }

        // 5. Création d'utilisateur avec n'importe quel rôle (admin only)
        [HttpPost("admin/create-user")]
        public async Task<IActionResult> CreateUser([FromBody] User newUser)
        {
            _context.Users.Add(newUser);
            await _context.SaveChangesAsync();
            return Ok(newUser);
        }

        // 6. Suppression de tous les logs (admin only)
        [HttpDelete("admin/clear-logs")]
        public IActionResult ClearLogs()
        {
            // Fictif pour la démo
            return Ok(new { cleared = true });
        }

        // 7. Accès à l'audit log (admin only)
        [HttpGet("admin/audit-log")]
        public IActionResult GetAuditLog()
        {
            // Fictif pour la démo
            return Ok(new[] {
                "2024-07-14 admin deleted user 2",
                "2024-07-14 user1 requested elevation"
            });
        }

        // 8. Reset password d'un autre utilisateur (admin only)
        [HttpPost("admin/reset-password/{id}")]
        public async Task<IActionResult> ResetPassword(int id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null) return NotFound();
            // Reset fictif (en vrai on enverrait un mail etc)
            return Ok(new { reset = id });
        }

        // 9. Set premium flag sur n'importe qui (admin only)
        [HttpPost("admin/set-premium/{id}")]
        public async Task<IActionResult> SetPremium(int id, [FromBody] bool isPremium)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null) return NotFound();
            // Ajoute un champ dynamique pour la démo
            user.Role = isPremium ? "PremiumUser" : user.Role;
            await _context.SaveChangesAsync();
            return Ok(new { premium = isPremium, userId = id });
        }

        // 10. Restauration de backup (admin only)
        [HttpPost("admin/restore-backup")]
        public IActionResult RestoreBackup([FromBody] string backupId)
        {
            // Fictif pour la démo
            return Ok(new { restored = backupId });
        }
    }

    // Petit modèle pour la config globale
    public class ConfigModel
    {
        public bool MaintenanceMode { get; set; }
        public string Motd { get; set; } = string.Empty;
    }
}
