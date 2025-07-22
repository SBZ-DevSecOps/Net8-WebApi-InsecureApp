// ===== CONTRÔLEUR UNIQUE POUR VULNÉRABILITÉ BOLA =====
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Net8_WebApi_InsecureApp.Data;
using Net8_WebApi_InsecureApp.Helpers;
using Net8_WebApi_InsecureApp.Models;

namespace Net8_WebApi_InsecureApp.Controllers
{
    /// <summary>
    /// Contrôleur démontrant la vulnérabilité API1:2023 - Broken Object Level Authorization (BOLA)
    /// Ce contrôleur contient intentionnellement des vulnérabilités pour des fins éducatives
    /// NE PAS UTILISER EN PRODUCTION
    /// </summary>
    [ApiController]
    [Route("api/bola")]
    public class Api01BolaController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IWebHostEnvironment _env;

        public Api01BolaController(AppDbContext context, IWebHostEnvironment env)
        {
            _context = context;
            _env = env;
        }

        #region ORDERS

        [HttpGet]
        public IEnumerable<Order> Get() => _context.Orders.AsEnumerable();

        [HttpGet("orders/{orderId}")]
        public async Task<IActionResult> GetOrder(int orderId)
        {
            var order = await _context.Orders.Include(o => o.User).FirstOrDefaultAsync(o => o.Id == orderId);
            if (order == null) return NotFound();
            return Ok(order);
        }

        [HttpPut("orders/{orderId}/status")]
        public async Task<IActionResult> UpdateOrderStatus(int orderId, [FromBody] string newStatus)
        {
            var order = await _context.Orders.FindAsync(orderId);
            if (order == null) return NotFound();
            order.Status = newStatus;
            await _context.SaveChangesAsync();
            return Ok(order);
        }

        [HttpDelete("orders/{orderId}")]
        public async Task<IActionResult> DeleteOrder(int orderId)
        {
            var order = await _context.Orders.FindAsync(orderId);
            if (order == null) return NotFound();
            _context.Orders.Remove(order);
            await _context.SaveChangesAsync();
            return NoContent();
        }

        #endregion

        #region BANK ACCOUNTS

        [HttpGet("bank-accounts/{accountId}")]
        public async Task<IActionResult> GetBankAccount(int accountId)
        {
            var account = await _context.BankAccounts.FirstOrDefaultAsync(a => a.Id == accountId);
            return Ok(account);
        }

        [HttpPut("bank-accounts/{accountId}/iban")]
        public async Task<IActionResult> UpdateIban(int accountId, [FromBody] string newIban)
        {
            var account = await _context.BankAccounts.FindAsync(accountId);
            if (account == null) return NotFound();
            account.IBAN = newIban;
            await _context.SaveChangesAsync();
            return Ok(account);
        }

        [HttpDelete("bank-accounts/{accountId}")]
        public async Task<IActionResult> DeleteBankAccount(int accountId)
        {
            var account = await _context.BankAccounts.FindAsync(accountId);
            if (account == null) return NotFound();
            _context.BankAccounts.Remove(account);
            await _context.SaveChangesAsync();
            return NoContent();
        }

        [HttpPost("bank-accounts/{accountId}/transfer")]
        public async Task<IActionResult> TransferMoney(int accountId, [FromBody] TransferRequest request)
        {
            var sourceAccount = await _context.BankAccounts.FindAsync(accountId);
            var targetAccount = await _context.BankAccounts.FindAsync(request.TargetAccountId);
            if (sourceAccount == null || targetAccount == null) return NotFound();
            sourceAccount.Balance -= request.Amount;
            targetAccount.Balance += request.Amount;
            await _context.SaveChangesAsync();
            return Ok(new { message = "Transfer completed" });
        }

        #endregion

        #region MEDICAL RECORDS

        [HttpGet("medical-records/{recordId}")]
        public async Task<IActionResult> GetMedicalRecord(int recordId)
        {
            var record = await _context.MedicalRecords.Include(r => r.Patient).FirstOrDefaultAsync(r => r.Id == recordId);
            return Ok(record);
        }

        [HttpPut("medical-records/{recordId}/notes")]
        public async Task<IActionResult> UpdateMedicalNotes(int recordId, [FromBody] string notes)
        {
            var record = await _context.MedicalRecords.FindAsync(recordId);
            if (record == null) return NotFound();
            record.SensitiveNotes = notes;
            await _context.SaveChangesAsync();
            return Ok(record);
        }

        [HttpDelete("medical-records/{recordId}")]
        public async Task<IActionResult> DeleteMedicalRecord(int recordId)
        {
            var record = await _context.MedicalRecords.FindAsync(recordId);
            if (record == null) return NotFound();
            _context.MedicalRecords.Remove(record);
            await _context.SaveChangesAsync();
            return NoContent();
        }

        // Batch export
        [HttpGet("medical-records/export")]
        public async Task<IActionResult> ExportMedicalRecords([FromQuery] int[] recordIds)
        {
            var records = await _context.MedicalRecords.Where(r => recordIds.Contains(r.Id)).ToListAsync();
            return Ok(records);
        }

        // Accès par GUID (pour piéger les SAST/DAST)
        [HttpGet("medical-records/guid/{guid}")]
        public async Task<IActionResult> GetMedicalRecordByGuid(Guid guid)
        {
            var intId = Math.Abs(guid.GetHashCode()) % 100 + 3000;
            var record = await _context.MedicalRecords.FindAsync(intId);
            if (record == null) return NotFound();
            return Ok(record);
        }

        #endregion

        #region DOCUMENTS

        [HttpGet("documents/{documentId}/download")]
        public async Task<IActionResult> DownloadDocument(int documentId)
        {
            Document? document = await _context.Documents.FindAsync(documentId);
            if (document == null) return NotFound();
            string relativePath = document.FilePath.TrimStart('/').Replace('/', Path.DirectorySeparatorChar);
            string filePath = Path.Combine(_env.ContentRootPath, relativePath);
            if (!System.IO.File.Exists(filePath)) return NotFound("File not found on server");
            byte[] fileBytes = await System.IO.File.ReadAllBytesAsync(filePath);
            return File(fileBytes, "application/octet-stream", document.FileName);
        }

        // Accès par slug
        [HttpGet("documents/by-slug/{slug}")]
        public async Task<IActionResult> DownloadDocumentBySlug(string slug)
        {
            Document? document = await _context.Documents.FirstOrDefaultAsync(d => d.FileName.ToLower().Contains(slug.ToLower()));
            if (document == null) return NotFound();
            string relativePath = document.FilePath.TrimStart('/').Replace('/', Path.DirectorySeparatorChar);
            string filePath = Path.Combine(_env.ContentRootPath, relativePath);
            if (!System.IO.File.Exists(filePath)) return NotFound("File not found on server");
            byte[] fileBytes = await System.IO.File.ReadAllBytesAsync(filePath);
            return File(fileBytes, "application/octet-stream", document.FileName);
        }

        [HttpPost("documents/{documentId}/share")]
        public async Task<IActionResult> ShareDocument(int documentId, [FromBody] ShareRequest request)
        {
            var document = await _context.Documents.FindAsync(documentId);
            if (document == null) return NotFound();
            var shareLink = $"/api/bola/documents/shared/{Guid.NewGuid()}";
            return Ok(new { shareLink, expiresIn = "7 days" });
        }

        [HttpDelete("documents/{documentId}")]
        public async Task<IActionResult> DeleteDocument(int documentId)
        {
            var document = await _context.Documents.FindAsync(documentId);
            if (document == null) return NotFound();
            _context.Documents.Remove(document);
            await _context.SaveChangesAsync();
            return NoContent();
        }

        #endregion

        #region USER PROFILES

        [HttpGet("users/{userId}/profile")]
        public async Task<IActionResult> GetUserProfile(int userId)
        {
            var user = await _context.Users
                .Select(u => new
                {
                    u.Id,
                    u.Email,
                    u.Role,
                    Orders = u.Orders.Select(o => new { o.Id, o.Amount, o.Status }),
                    BankAccounts = u.BankAccounts.Select(b => new { b.AccountNumber, b.Balance }),
                    DocumentCount = u.Documents.Count(),
                    LastActivity = DateTime.Now.AddDays(-new Random().Next(1, 30))
                })
                .FirstOrDefaultAsync(u => u.Id == userId);

            if (user == null)
                return NotFound();

            return Ok(user);
        }

        [HttpGet("users/me/profile")]
        public async Task<IActionResult> GetMyProfile()
        {
            if (!TokenHelper.TryGetClaimFromBearer<int>(HttpContext, "userId", out var userId) || userId == 0)
                return Unauthorized();

            // Optionnel : récupérer le rôle ou le tenantId
            TokenHelper.TryGetClaimFromBearer<string>(HttpContext, "role", out var role);

            var user = await _context.Users
                .Select(u => new
                {
                    u.Id,
                    u.Email,
                    u.Role,
                    Orders = u.Orders.Select(o => new { o.Id, o.Amount, o.Status }),
                    BankAccounts = u.BankAccounts.Select(b => new { b.AccountNumber, b.Balance }),
                    DocumentCount = u.Documents.Count(),
                    LastActivity = DateTime.Now.AddDays(-new Random().Next(1, 30))
                })
                .FirstOrDefaultAsync(u => u.Id == userId);

            if (user == null)
                return NotFound();

            return Ok(user);
        }

        [HttpPut("users/{userId}/role")]
        public async Task<IActionResult> UpdateUserRole(int userId, [FromBody] UpdateRoleRequest request)
        {
            var user = await _context.Users.FindAsync(userId);
            if (user == null) return NotFound();
            user.Role = request.NewRole;
            await _context.SaveChangesAsync();
            return Ok(new { message = "Role updated", userId, newRole = request.NewRole });
        }

        #endregion

        #region MESSAGES

        [HttpGet("messages/{messageId}")]
        public async Task<IActionResult> GetMessage(int messageId)
        {
            var message = await _context.Messages
                .Include(m => m.Sender)
                .Include(m => m.Recipient)
                .FirstOrDefaultAsync(m => m.Id == messageId);

            if (message == null)
                return NotFound();

            return Ok(message);
        }

        [HttpDelete("messages/{messageId}")]
        public async Task<IActionResult> DeleteMessage(int messageId)
        {
            var message = await _context.Messages.FindAsync(messageId);
            if (message == null)
                return NotFound();

            _context.Messages.Remove(message);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        #endregion

        #region API KEYS

        [HttpGet("api-keys/{keyId}")]
        public async Task<IActionResult> GetApiKey(int keyId)
        {
            var apiKey = await _context.ApiKeys.Include(k => k.User).FirstOrDefaultAsync(k => k.Id == keyId);
            if (apiKey == null) return NotFound();
            return Ok(apiKey);
        }

        [HttpPost("api-keys/{keyId}/revoke")]
        public async Task<IActionResult> RevokeApiKey(int keyId)
        {
            var apiKey = await _context.ApiKeys.FindAsync(keyId);
            if (apiKey == null) return NotFound();
            apiKey.IsRevoked = true;
            apiKey.RevokedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();
            return Ok(new { message = "API key revoked", keyId });
        }

        [HttpDelete("api-keys/{keyId}")]
        public async Task<IActionResult> DeleteApiKey(int keyId)
        {
            var apiKey = await _context.ApiKeys.FindAsync(keyId);
            if (apiKey == null) return NotFound();
            _context.ApiKeys.Remove(apiKey);
            await _context.SaveChangesAsync();
            return NoContent();
        }

        #endregion
    }
}