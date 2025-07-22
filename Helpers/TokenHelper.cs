namespace Net8_WebApi_InsecureApp.Helpers
{
    using Microsoft.AspNetCore.Http;
    using System.Text;
    using System.Text.Json;

    public static class TokenHelper
    {
        public static bool TryGetClaimFromBearer<T>(HttpContext httpContext, string claimKey, out T value)
        {
            value = default!;
            var auth = httpContext.Request.Headers["Authorization"].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(auth) || !auth.StartsWith("Bearer ")) return false;

            try
            {
                var payload = auth.Substring("Bearer ".Length);
                var tokenPayload = Encoding.UTF8.GetString(Convert.FromBase64String(payload));
                var token = JsonSerializer.Deserialize<Dictionary<string, object>>(tokenPayload);

                if (token != null && token.TryGetValue(claimKey, out var raw))
                {
                    if (raw is JsonElement je)
                    {
                        object? resolved = null;
                        if (typeof(T) == typeof(int) && je.ValueKind == JsonValueKind.Number && je.TryGetInt32(out var intval))
                            resolved = intval;
                        else if (typeof(T) == typeof(string))
                            resolved = je.ValueKind == JsonValueKind.String ? je.GetString() : je.ToString();
                        else if (typeof(T) == typeof(bool) && (je.ValueKind == JsonValueKind.True || je.ValueKind == JsonValueKind.False))
                            resolved = je.GetBoolean();

                        if (resolved is T val)
                        {
                            value = val;
                            return true;
                        }
                    }
                    else if (raw is T directVal)
                    {
                        value = directVal;
                        return true;
                    }
                    else if (raw is string sRaw && typeof(T) == typeof(int) && int.TryParse(sRaw, out var iVal))
                    {
                        value = (T)(object)iVal;
                        return true;
                    }
                }
            }
            catch { }
            return false;
        }

        public static int GetUserIdFromHeader(string? auth)
        {
            if (string.IsNullOrWhiteSpace(auth) || !auth.StartsWith("Bearer ")) return 0;
            try
            {
                var payload = auth.Substring("Bearer ".Length);
                var tokenPayload = Encoding.UTF8.GetString(Convert.FromBase64String(payload));
                var token = JsonSerializer.Deserialize<Dictionary<string, object>>(tokenPayload);
                if (token != null && token.TryGetValue("userId", out var idObj))
                {
                    // Pour JsonElement
                    if (idObj is JsonElement je)
                    {
                        if (je.ValueKind == JsonValueKind.Number) return je.GetInt32();
                        if (je.ValueKind == JsonValueKind.String && int.TryParse(je.GetString(), out var val)) return val;
                    }
                    // Pour long/int/string natif
                    if (idObj is long l) return (int)l;
                    if (idObj is int i) return i;
                    if (idObj is string s && int.TryParse(s, out var val2)) return val2;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[TokenHelper] Exception: " + ex.Message);
            }
            return 0;
        }
    }

}
