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
            VerifySignature(payload, signature, tolerance);

            if (IsLogEventBatch(payload))
            {
                throw new InvalidPayloadException("Payload is a batch of log events. Use ConstructLogEventBatch instead.");
            }

            var webhookEvent = DeserializePayload<WebhookEvent>(payload);

            ValidateEvent(webhookEvent, expectsRecord: false);

            return webhookEvent;
        }

        public WebhookEventBatch ConstructLogEventBatch(string payload, string signature, int tolerance = DEFAULT_TOLERANCE)
        {
            VerifySignature(payload, signature, tolerance);

            var batch = DeserializePayload<WebhookEventBatch>(payload);

            if (batch.Records == null)
            {
                throw new InvalidPayloadException("Payload format is invalid. Expected a 'records' array.");
            }

            foreach (var webhookEvent in batch.Records)
            {
                ValidateEvent(webhookEvent, expectsRecord: true);
            }

            return batch;
        }

        private static void ValidateEvent(WebhookEvent webhookEvent, bool expectsRecord)
        {
            if (webhookEvent.Version <= 0)
            {
                throw new InvalidPayloadException("Payload is missing required field 'version'.");
            }

            RequireField(webhookEvent.Type, "type");
            RequireField(webhookEvent.Id, "id");
            RequireField(webhookEvent.Source, "source");
            RequireField(webhookEvent.Time, "time");
            RequireField(webhookEvent.TenantId, "tenantId");

            if (expectsRecord && webhookEvent.Record == null)
            {
                throw new InvalidPayloadException("Payload is missing required field 'record'.");
            }

            if (!expectsRecord && webhookEvent.Data == null)
            {
                throw new InvalidPayloadException("Payload is missing required field 'data'.");
            }
        }

        private static void RequireField(string? value, string name)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new InvalidPayloadException($"Payload is missing required field '{name}'.");
            }
        }

        private void VerifySignature(string payload, string signature, int tolerance)
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
        }

        private T DeserializePayload<T>(string payload) where T : class
        {
            try
            {
                var result = JsonSerializer.Deserialize<T>(payload, serializerOptions);

                if (result == null)
                {
                    throw new InvalidPayloadException("Payload format is invalid.");
                }

                return result;
            }
            catch (JsonException exception)
            {
                throw new InvalidPayloadException("Payload format is invalid.", exception);
            }
        }

        private static bool IsLogEventBatch(string payload)
        {
            try
            {
                using var document = JsonDocument.Parse(payload);

                return document.RootElement.ValueKind == JsonValueKind.Object
                    && document.RootElement.TryGetProperty("records", out var records)
                    && records.ValueKind == JsonValueKind.Array;
            }
            catch (JsonException)
            {
                return false;
            }
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

        public class InvalidPayloadException : Exception
        {
            public InvalidPayloadException(string message) : base(message) { }

            public InvalidPayloadException(string message, Exception innerException) : base(message, innerException) { }
        }
    }
}
