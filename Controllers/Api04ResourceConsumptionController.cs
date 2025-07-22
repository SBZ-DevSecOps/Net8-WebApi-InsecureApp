using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Net8_WebApi_InsecureApp.Data;
using Net8_WebApi_InsecureApp.Models;
using System.Security.Cryptography;
using System.Text;

namespace Net8_WebApi_InsecureApp.Controllers
{
    /// <summary>
    /// API4:2023 - Unrestricted Resource Consumption (VULNÉRABLE)
    /// Route: /api/rc
    /// </summary>
    [ApiController]
    [Route("api/rc")]
    public class Api04ResourceConsumptionController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly ILogger<Api04ResourceConsumptionController> _logger;

        public Api04ResourceConsumptionController(AppDbContext context, ILogger<Api04ResourceConsumptionController> logger)
        {
            _context = context;
            _logger = logger;
        }

        // 1. Listing massif sans pagination
        [HttpGet("users/all")]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _context.UserProfiles.ToListAsync();
            return Ok(users);
        }

        // 2. Export CSV géant sans limite
        [HttpGet("export-csv")]
        public async Task<IActionResult> ExportCsv([FromQuery] int count = 100000)
        {
            var users = await _context.UserProfiles.Take(count).ToListAsync();
            var csv = new StringBuilder();
            csv.AppendLine("Id,Username,Email");
            foreach (var u in users)
            {
                csv.AppendLine($"{u.Id},{u.Username},{u.Email}");
            }
            var bytes = Encoding.UTF8.GetBytes(csv.ToString());
            return File(bytes, "text/csv", "users.csv");
        }

        // 3. Endpoint computation user-driven
        [HttpGet("hash-password")]
        public IActionResult HashPassword([FromQuery] string password, [FromQuery] int rounds = 1000000)
        {
            using var deriveBytes = new Rfc2898DeriveBytes(password, 16, rounds);
            var hash = Convert.ToBase64String(deriveBytes.GetBytes(32));
            return Ok(new { hash });
        }

        // 4. Bulk create sans plafond
        [HttpPost("bulk-create-orders")]
        public async Task<IActionResult> BulkCreateOrders([FromBody] List<Order> orders)
        {
            await _context.Orders.AddRangeAsync(orders);
            await _context.SaveChangesAsync();
            return Ok(new { created = orders.Count });
        }
    }
}
