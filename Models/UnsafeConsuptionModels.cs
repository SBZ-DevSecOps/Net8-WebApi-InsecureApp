namespace Net8_WebApi_InsecureApp.Models
{
    // ===== MODÈLES POUR UNSAFE CONSUMPTION OF APIs =====

    public class ExternalApiConfig
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string BaseUrl { get; set; } = string.Empty;
        public string? ApiKey { get; set; }
        public bool ValidateSsl { get; set; }
        public int TimeoutSeconds { get; set; }
        public bool LogResponses { get; set; }
        public Dictionary<string, string> Headers { get; set; } = new();
    }

    public class WeatherData
    {
        public string Location { get; set; } = string.Empty;
        public decimal Temperature { get; set; }
        public string Description { get; set; } = string.Empty;
        public Dictionary<string, object> RawData { get; set; } = new();
        public string? ProviderResponse { get; set; }
    }

    public class PaymentRequest
    {
        public string CardNumber { get; set; } = string.Empty;
        public string CardHolder { get; set; } = string.Empty;
        public decimal Amount { get; set; }
        public string Currency { get; set; } = string.Empty;
        public Dictionary<string, string> Metadata { get; set; } = new();
    }

    public class PaymentResponse
    {
        public string TransactionId { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public string? ErrorMessage { get; set; }
        public Dictionary<string, object> ProcessorResponse { get; set; } = new();
        public string? RawResponse { get; set; }
    }

    public class UserVerification
    {
        public string Email { get; set; } = string.Empty;
        public string? Phone { get; set; }
        public string? SocialSecurityNumber { get; set; }
        public Dictionary<string, string> AdditionalData { get; set; } = new();
    }

    public class VerificationResponse
    {
        public bool IsValid { get; set; }
        public decimal Score { get; set; }
        public List<string> Flags { get; set; } = new();
        public Dictionary<string, object> Details { get; set; } = new();
        public string? RawProviderData { get; set; }
    }

    public class GeoLocationRequest
    {
        public string IpAddress { get; set; } = string.Empty;
        public bool IncludeDetails { get; set; }
    }

    public class GeoLocationResponse
    {
        public string Country { get; set; } = string.Empty;
        public string City { get; set; } = string.Empty;
        public decimal Latitude { get; set; }
        public decimal Longitude { get; set; }
        public string? Isp { get; set; }
        public Dictionary<string, object> ExtendedData { get; set; } = new();
    }

    public class TranslationRequest
    {
        public string Text { get; set; } = string.Empty;
        public string SourceLanguage { get; set; } = string.Empty;
        public string TargetLanguage { get; set; } = string.Empty;
        public bool PreserveFormatting { get; set; }
    }

    public class FileUploadRequest
    {
        public string FileName { get; set; } = string.Empty;
        public string ContentType { get; set; } = string.Empty;
        public byte[] Content { get; set; } = Array.Empty<byte>();
        public string? UploadUrl { get; set; }
    }

    public class SocialMediaPost
    {
        public string Platform { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;
        public List<string> Tags { get; set; } = new();
        public Dictionary<string, string> MediaUrls { get; set; } = new();
    }

    public class WebhookPayload
    {
        public string Event { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public Dictionary<string, object> Data { get; set; } = new();
        public string? Signature { get; set; }
        public string? SourceIp { get; set; }
    }

    public class ProxyRequest
    {
        public string TargetUrl { get; set; } = string.Empty;
        public string Method { get; set; } = "GET";
        public Dictionary<string, string> Headers { get; set; } = new();
        public string? Body { get; set; }
        public bool FollowRedirects { get; set; } = true;
    }

    public class RssAggregation
    {
        public List<string> FeedUrls { get; set; } = new();
        public bool ParseHtml { get; set; }
        public bool ExecuteScripts { get; set; }
        public int MaxItems { get; set; } = 100;
    }

    public class ApiAggregationRequest
    {
        public List<string> ApiEndpoints { get; set; } = new();
        public bool ParallelExecution { get; set; }
        public bool ContinueOnError { get; set; }
        public Dictionary<string, string> GlobalHeaders { get; set; } = new();
    }

    // ===== MODÈLES DE RÉPONSE =====

    public class ExternalApiResponse<T>
    {
        public T? Data { get; set; }
        public bool Success { get; set; }
        public string? Error { get; set; }
        public Dictionary<string, string> Headers { get; set; } = new();
        public int StatusCode { get; set; }
        public string? RawResponse { get; set; }
        public long ResponseTimeMs { get; set; }
    }

    public class AggregatedResponse
    {
        public List<object> Results { get; set; } = new();
        public List<string> Errors { get; set; } = new();
        public Dictionary<string, long> ResponseTimes { get; set; } = new();
        public int TotalRequests { get; set; }
        public int SuccessfulRequests { get; set; }
    }

    public class DynamicApiResponse
    {
        public dynamic? Result { get; set; }
        public string SourceApi { get; set; } = string.Empty;
        public bool FromCache { get; set; }
        public DateTime Timestamp { get; set; }
    }
}