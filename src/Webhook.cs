using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Authsignal
{
    public class Webhook(string apiSecretKey)
    {
        private const int DEFAULT_TOLERANCE = 5;
        private const string VERSION = "v2";

        private readonly string apiSecretKey = apiSecretKey;

        private readonly JsonSerializerOptions serializerOptions = new()
        {
            DictionaryKeyPolicy = JsonNamingPolicy.CamelCase,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        public WebhookEvent ConstructEvent(string payload, string signature, int tolerance = DEFAULT_TOLERANCE)
        {
            var parsedSignature = ParseSignature(signature);

            long secondsSinceEpoch = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            if (tolerance > 0 && parsedSignature.Timestamp < secondsSinceEpoch - tolerance * 60)
            {
                throw new InvalidSignatureException("Timestamp is outside the tolerance zone.");
            }

            string hmacContent = $"{parsedSignature.Timestamp}.{payload}";

            string computedSignature = ComputeHmac(hmacContent, apiSecretKey);

            bool match = parsedSignature.Signatures.Any(sig => sig.Equals(computedSignature));

            if (!match)
            {
                throw new InvalidSignatureException("Signature mismatch.");
            }

            WebhookEvent? webhookEvent = JsonSerializer.Deserialize<WebhookEvent>(payload, serializerOptions);

            if (webhookEvent == null)
            {
                throw new InvalidSignatureException("Payload format is invalid.");
            }

            return webhookEvent;
        }

        private SignatureHeaderData ParseSignature(string value)
        {
            try
            {
                long timestamp = GetTimestamp(value);
                List<string> signatures = GetSignatures(value);

                if (timestamp == -1 || !signatures.Any())
                {
                    throw new Exception();
                }

                return new SignatureHeaderData(signatures, timestamp);
            }
            catch (Exception)
            {
                throw new InvalidSignatureException("Signature format is invalid.");
            }
        }

        private static long GetTimestamp(string header)
        {
            var items = header.Split(',');

            foreach (var item in items)
            {
                var itemParts = item.Split('=');
                if (itemParts[0] == "t")
                {
                    return long.Parse(itemParts[1]);
                }
            }

            return -1;
        }

        private static List<string> GetSignatures(string header)
        {
            var signatures = new List<string>();
            var items = header.Split(',');

            foreach (var item in items)
            {
                var itemParts = item.Split('=');
                if (itemParts[0] == VERSION)
                {
                    signatures.Add(itemParts[1]);
                }
            }

            return signatures;
        }

        private string ComputeHmac(string data, string key)
        {
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));

            var hmacBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));

            return Convert.ToBase64String(hmacBytes).TrimEnd('=');
        }

        private class SignatureHeaderData(List<string> signatures, long timestamp)
        {
            public List<string> Signatures { get; } = signatures;
            public long Timestamp { get; } = timestamp;
        }

        public class InvalidSignatureException(string message) : Exception(message) { }
    }
}
