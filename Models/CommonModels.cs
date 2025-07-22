namespace Net8_WebApi_InsecureApp.Models
{
    // ===== MODÈLES COMMUNS =====

    public class TokenRequest
    {
        public int UserId { get; set; }
        public string? Role { get; set; }
    }

    public class ErrorResponse
    {
        public string Error { get; set; } = string.Empty;
        public string? Details { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }

    public class SuccessResponse
    {
        public string Message { get; set; } = string.Empty;
        public object? Data { get; set; }
    }

    public class PaginationRequest
    {
        public int Page { get; set; } = 1;
        public int PageSize { get; set; } = 10;
        public string? SortBy { get; set; }
        public bool Descending { get; set; } = false;
    }

    public class PaginatedResponse<T>
    {
        public List<T> Items { get; set; } = new List<T>();
        public int TotalCount { get; set; }
        public int Page { get; set; }
        public int PageSize { get; set; }
        public int TotalPages => (int)Math.Ceiling(TotalCount / (double)PageSize);
    }
}