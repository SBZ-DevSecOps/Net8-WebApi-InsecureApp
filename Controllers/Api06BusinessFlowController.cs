using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Net8_WebApi_InsecureApp.Data;
using Net8_WebApi_InsecureApp.Models;
using System.Collections.Concurrent;

namespace Net8_WebApi_InsecureApp.Controllers
{
    /// <summary>
    /// API6:2023 - Unrestricted Access to Sensitive Business Flows (VULNÉRABLE)
    /// Ce contrôleur démontre les vulnérabilités liées à l'absence de protection
    /// des flux métiers sensibles contre l'automatisation et les abus
    /// </summary>
    [ApiController]
    [Route("api/business")]
    public class Api06BusinessFlowController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly ILogger<Api06BusinessFlowController> _logger;

        // VULNÉRABLE: Stockage en mémoire sans protection
        private static readonly ConcurrentDictionary<string, DateTime> _purchaseAttempts = new();
        private static readonly ConcurrentDictionary<string, int> _voucherUsage = new();
        private static readonly ConcurrentDictionary<int, DateTime> _lastPurchase = new();
        private static readonly ConcurrentDictionary<string, List<string>> _referralCodes = new();

        public Api06BusinessFlowController(AppDbContext context, ILogger<Api06BusinessFlowController> logger)
        {
            _context = context;
            _logger = logger;
        }

        #region Achat de produits en édition limitée

        /// <summary>
        /// VULNÉRABLE: Achat de produit limité sans protection contre les bots
        /// </summary>
        [HttpPost("purchase/limited-edition")]
        public async Task<IActionResult> PurchaseLimitedEdition([FromBody] LimitedEditionPurchaseRequest request)
        {
            // VULNÉRABLE: Pas de CAPTCHA
            // VULNÉRABLE: Pas de vérification du User-Agent
            // VULNÉRABLE: Pas de rate limiting
            // VULNÉRABLE: Pas de vérification d'identité forte

            var product = await _context.Products
                .FirstOrDefaultAsync(p => p.Id == request.ProductId && p.Category == "Limited Edition");

            if (product == null)
                return NotFound(new { error = "Product not found" });

            if (product.Stock <= 0)
                return BadRequest(new { error = "Out of stock" });

            // VULNÉRABLE: Simple décrémentation sans vérification transactionnelle
            product.Stock--;

            var order = new Order
            {
                UserId = request.UserId,
                Amount = product.Price,
                Status = "Confirmed",
                CreatedAt = DateTime.UtcNow
            };

            _context.Orders.Add(order);
            await _context.SaveChangesAsync();

            // VULNÉRABLE: Confirmation immédiate
            return Ok(new
            {
                orderId = order.Id,
                message = "Purchase successful",
                product = product.Name,
                remainingStock = product.Stock
            });
        }

        /// <summary>
        /// VULNÉRABLE: Vérification de stock en temps réel (facilite l'automatisation)
        /// </summary>
        [HttpGet("stock/limited-edition/{productId}")]
        public async Task<IActionResult> CheckLimitedStock(int productId)
        {
            // VULNÉRABLE: Pas de protection contre le scraping
            var product = await _context.Products.FindAsync(productId);

            if (product == null)
                return NotFound();

            // VULNÉRABLE: Information en temps réel facilitant les bots
            return Ok(new
            {
                productId = product.Id,
                name = product.Name,
                stock = product.Stock,
                price = product.Price,
                lastRestocked = DateTime.UtcNow.AddHours(-1),
                nextRestock = DateTime.UtcNow.AddHours(2)
            });
        }

        #endregion

        #region Système de codes promotionnels

        /// <summary>
        /// VULNÉRABLE: Génération de codes promo sans limite
        /// </summary>
        [HttpPost("promo/generate")]
        public IActionResult GeneratePromoCode([FromBody] PromoGenerationRequest request)
        {
            // VULNÉRABLE: Pas de limite sur le nombre de codes générés
            // VULNÉRABLE: Codes prévisibles
            var code = $"PROMO{DateTime.Now.Ticks % 100000}";

            _voucherUsage[code] = 0;

            return Ok(new
            {
                promoCode = code,
                discount = request.DiscountPercent,
                validUntil = DateTime.UtcNow.AddDays(30)
            });
        }

        /// <summary>
        /// VULNÉRABLE: Application de codes promo sans vérification
        /// </summary>
        [HttpPost("promo/apply")]
        public async Task<IActionResult> ApplyPromoCode([FromBody] PromoApplicationRequest request)
        {
            // VULNÉRABLE: Pas de vérification du nombre d'utilisations par utilisateur
            // VULNÉRABLE: Pas de vérification de l'éligibilité

            if (!_voucherUsage.ContainsKey(request.PromoCode))
                return BadRequest(new { error = "Invalid promo code" });

            // VULNÉRABLE: Incrémentation simple sans vérification
            _voucherUsage[request.PromoCode]++;

            var order = await _context.Orders.FindAsync(request.OrderId);
            if (order == null)
                return NotFound();

            // VULNÉRABLE: Application multiple possible
            order.Amount = order.Amount * 0.8m; // 20% de réduction
            await _context.SaveChangesAsync();

            return Ok(new
            {
                message = "Promo code applied",
                newAmount = order.Amount,
                usageCount = _voucherUsage[request.PromoCode]
            });
        }

        #endregion

        #region Système de parrainage

        /// <summary>
        /// VULNÉRABLE: Création de comptes en masse pour parrainage
        /// </summary>
        [HttpPost("referral/register")]
        public async Task<IActionResult> RegisterWithReferral([FromBody] ReferralRegistrationRequest request)
        {
            // VULNÉRABLE: Pas de vérification d'email
            // VULNÉRABLE: Pas de CAPTCHA
            // VULNÉRABLE: Création instantanée

            var referrer = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == request.ReferrerEmail);

            if (referrer == null)
                return BadRequest(new { error = "Referrer not found" });

            // VULNÉRABLE: Création de compte sans vérification
            var newUser = new User
            {
                Email = request.NewUserEmail,
                Role = "User"
            };

            _context.Users.Add(newUser);
            await _context.SaveChangesAsync();

            // VULNÉRABLE: Bonus immédiat sans vérification
            if (!_referralCodes.ContainsKey(request.ReferrerEmail))
                _referralCodes[request.ReferrerEmail] = new List<string>();

            _referralCodes[request.ReferrerEmail].Add(request.NewUserEmail);

            // VULNÉRABLE: Récompense automatique
            return Ok(new
            {
                message = "Referral successful",
                referrerBonus = 10, // $10 bonus
                newUserBonus = 5,  // $5 bonus
                totalReferrals = _referralCodes[request.ReferrerEmail].Count
            });
        }

        /// <summary>
        /// VULNÉRABLE: Réclamation de bonus de parrainage sans limite
        /// </summary>
        [HttpPost("referral/claim-bonus")]
        public async Task<IActionResult> ClaimReferralBonus([FromBody] ClaimBonusRequest request)
        {
            // VULNÉRABLE: Pas de vérification du nombre de réclamations
            // VULNÉRABLE: Pas de cooldown

            if (!_referralCodes.ContainsKey(request.UserEmail))
                return BadRequest(new { error = "No referrals found" });

            var referralCount = _referralCodes[request.UserEmail].Count;
            var bonus = referralCount * 10; // $10 par parrainage

            // VULNÉRABLE: Crédit immédiat sans vérification
            return Ok(new
            {
                message = "Bonus claimed",
                amount = bonus,
                referralCount = referralCount,
                nextClaimAvailable = DateTime.UtcNow // Pas de cooldown!
            });
        }

        #endregion

        #region Système de votes et reviews

        /// <summary>
        /// VULNÉRABLE: Vote multiple sans restriction
        /// </summary>
        [HttpPost("vote/product")]
        public async Task<IActionResult> VoteForProduct([FromBody] VoteRequest request)
        {
            // VULNÉRABLE: Pas de vérification d'unicité du vote
            // VULNÉRABLE: Pas d'authentification requise
            // VULNÉRABLE: Pas de rate limiting

            var product = await _context.Products.FindAsync(request.ProductId);
            if (product == null)
                return NotFound();

            // VULNÉRABLE: Incrémentation simple
            product.DisplayOrder += request.VoteValue; // Peut être positif ou négatif
            await _context.SaveChangesAsync();

            return Ok(new
            {
                message = "Vote recorded",
                newScore = product.DisplayOrder,
                totalVotes = new Random().Next(100, 10000) // Faux nombre
            });
        }

        /// <summary>
        /// VULNÉRABLE: Soumission de reviews en masse
        /// </summary>
        [HttpPost("review/submit")]
        public async Task<IActionResult> SubmitReview([FromBody] ReviewRequest request)
        {
            // VULNÉRABLE: Pas de vérification d'achat
            // VULNÉRABLE: Pas de modération
            // VULNÉRABLE: Publication instantanée

            var review = new ProductReview
            {
                ProductId = request.ProductId,
                UserEmail = request.UserEmail,
                Rating = request.Rating,
                Comment = request.Comment,
                CreatedAt = DateTime.UtcNow,
                IsVerifiedPurchase = false // Toujours faux!
            };

            _context.Set<ProductReview>().Add(review);
            await _context.SaveChangesAsync();

            // VULNÉRABLE: Récompense pour chaque review
            return Ok(new
            {
                message = "Review submitted",
                reviewId = review.Id,
                rewardPoints = 50,
                published = true
            });
        }

        #endregion

        #region Système de réservation

        /// <summary>
        /// VULNÉRABLE: Réservation en masse de créneaux
        /// </summary>
        [HttpPost("booking/reserve")]
        public async Task<IActionResult> ReserveSlot([FromBody] BookingRequest request)
        {
            // VULNÉRABLE: Pas de limite sur le nombre de réservations
            // VULNÉRABLE: Pas de vérification d'identité
            // VULNÉRABLE: Réservation instantanée sans confirmation

            var slot = new BookingSlot
            {
                UserId = request.UserId,
                SlotDateTime = request.SlotDateTime,
                ServiceType = request.ServiceType,
                Status = "Reserved",
                CreatedAt = DateTime.UtcNow
            };

            _context.Set<BookingSlot>().Add(slot);
            await _context.SaveChangesAsync();

            // VULNÉRABLE: Confirmation immédiate
            return Ok(new
            {
                bookingId = slot.Id,
                message = "Slot reserved",
                canCancelUntil = DateTime.UtcNow.AddYears(1) // Annulation tardive possible
            });
        }

        /// <summary>
        /// VULNÉRABLE: Annulation sans pénalité
        /// </summary>
        [HttpPost("booking/cancel/{bookingId}")]
        public async Task<IActionResult> CancelBooking(int bookingId)
        {
            // VULNÉRABLE: Pas de vérification du propriétaire
            // VULNÉRABLE: Pas de pénalité pour annulation tardive

            var booking = await _context.Set<BookingSlot>().FindAsync(bookingId);
            if (booking == null)
                return NotFound();

            booking.Status = "Cancelled";
            await _context.SaveChangesAsync();

            // VULNÉRABLE: Remboursement intégral toujours
            return Ok(new
            {
                message = "Booking cancelled",
                refundAmount = 100,
                refundPercentage = 100
            });
        }

        #endregion

        #region Transferts d'argent et transactions

        /// <summary>
        /// VULNÉRABLE: Transfert d'argent sans limite
        /// </summary>
        [HttpPost("transfer/money")]
        public async Task<IActionResult> TransferMoney([FromBody] MoneyTransferRequest request)
        {
            // VULNÉRABLE: Pas de limite journalière
            // VULNÉRABLE: Pas de vérification 2FA
            // VULNÉRABLE: Pas de délai de confirmation

            var sourceAccount = await _context.BankAccounts
                .FirstOrDefaultAsync(a => a.Id == request.SourceAccountId);

            var targetAccount = await _context.BankAccounts
                .FirstOrDefaultAsync(a => a.Id == request.TargetAccountId);

            if (sourceAccount == null || targetAccount == null)
                return NotFound();

            // VULNÉRABLE: Transfert immédiat
            sourceAccount.Balance -= request.Amount;
            targetAccount.Balance += request.Amount;
            await _context.SaveChangesAsync();

            return Ok(new
            {
                message = "Transfer completed",
                transactionId = Guid.NewGuid(),
                amount = request.Amount,
                newBalance = sourceAccount.Balance
            });
        }

        #endregion

        #region Système de loterie/tirage au sort

        /// <summary>
        /// VULNÉRABLE: Participation illimitée à la loterie
        /// </summary>
        [HttpPost("lottery/enter")]
        public IActionResult EnterLottery([FromBody] LotteryEntryRequest request)
        {
            // VULNÉRABLE: Pas de limite de participations
            // VULNÉRABLE: Pas de vérification d'éligibilité
            // VULNÉRABLE: Entrées multiples possibles

            var entryId = Guid.NewGuid();

            return Ok(new
            {
                message = "Entry successful",
                entryId = entryId,
                entryNumber = new Random().Next(1000000, 9999999),
                drawDate = DateTime.UtcNow.AddDays(7),
                currentEntries = new Random().Next(10000, 100000)
            });
        }

        #endregion

        #region API publique d'agrégation

        /// <summary>
        /// VULNÉRABLE: Endpoint d'agrégation sans limite
        /// </summary>
        [HttpGet("analytics/aggregate")]
        public async Task<IActionResult> GetAggregatedData([FromQuery] AggregationRequest request)
        {
            // VULNÉRABLE: Pas de pagination
            // VULNÉRABLE: Pas de cache
            // VULNÉRABLE: Calculs coûteux à la demande

            var orders = await _context.Orders
                .Where(o => o.CreatedAt >= request.StartDate && o.CreatedAt <= request.EndDate)
                .ToListAsync();

            var products = await _context.Products.ToListAsync();
            var users = await _context.Users.ToListAsync();

            // VULNÉRABLE: Agrégations complexes sans limite
            var result = new
            {
                totalOrders = orders.Count,
                totalRevenue = orders.Sum(o => o.Amount),
                averageOrderValue = orders.Average(o => o.Amount),
                topProducts = products.OrderByDescending(p => p.Price).Take(100),
                userStats = users.Select(u => new
                {
                    u.Id,
                    u.Email,
                    orderCount = orders.Count(o => o.UserId == u.Id),
                    totalSpent = orders.Where(o => o.UserId == u.Id).Sum(o => o.Amount)
                }),
                hourlyBreakdown = Enumerable.Range(0, 24).Select(hour => new
                {
                    hour,
                    orders = orders.Count(o => o.CreatedAt.Hour == hour),
                    revenue = orders.Where(o => o.CreatedAt.Hour == hour).Sum(o => o.Amount)
                })
            };

            return Ok(result);
        }

        #endregion
    }

    // ===== MODÈLES DE REQUÊTE =====

    public class LimitedEditionPurchaseRequest
    {
        public int UserId { get; set; }
        public int ProductId { get; set; }
        public int Quantity { get; set; } = 1;
    }

    public class PromoGenerationRequest
    {
        public int DiscountPercent { get; set; }
        public string? Category { get; set; }
    }

    public class PromoApplicationRequest
    {
        public int OrderId { get; set; }
        public string PromoCode { get; set; } = string.Empty;
    }

    public class ReferralRegistrationRequest
    {
        public string ReferrerEmail { get; set; } = string.Empty;
        public string NewUserEmail { get; set; } = string.Empty;
    }

    public class ClaimBonusRequest
    {
        public string UserEmail { get; set; } = string.Empty;
    }

    public class VoteRequest
    {
        public int ProductId { get; set; }
        public int VoteValue { get; set; } // +1 ou -1
    }

    public class ReviewRequest
    {
        public int ProductId { get; set; }
        public string UserEmail { get; set; } = string.Empty;
        public int Rating { get; set; }
        public string Comment { get; set; } = string.Empty;
    }

    public class BookingRequest
    {
        public int UserId { get; set; }
        public DateTime SlotDateTime { get; set; }
        public string ServiceType { get; set; } = string.Empty;
    }

    public class MoneyTransferRequest
    {
        public int SourceAccountId { get; set; }
        public int TargetAccountId { get; set; }
        public decimal Amount { get; set; }
    }

    public class LotteryEntryRequest
    {
        public string UserEmail { get; set; } = string.Empty;
        public string? ReferralCode { get; set; }
    }

    public class AggregationRequest
    {
        public DateTime StartDate { get; set; }
        public DateTime EndDate { get; set; }
        public string? GroupBy { get; set; }
    }

    // ===== MODÈLES DE DONNÉES SUPPLÉMENTAIRES =====

    public class ProductReview
    {
        public int Id { get; set; }
        public int ProductId { get; set; }
        public string UserEmail { get; set; } = string.Empty;
        public int Rating { get; set; }
        public string Comment { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public bool IsVerifiedPurchase { get; set; }
    }

    public class BookingSlot
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public DateTime SlotDateTime { get; set; }
        public string ServiceType { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
    }
}