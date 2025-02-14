using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace FreshFarmMarket.Services
{
    public class GoogleRecaptchaService
    {
        private readonly IConfiguration _configuration;
        private readonly HttpClient _httpClient;
        private readonly ILogger<GoogleRecaptchaService> _logger;

        public GoogleRecaptchaService(IConfiguration configuration, HttpClient httpClient, ILogger<GoogleRecaptchaService> logger)
        {
            _configuration = configuration;
            _httpClient = httpClient;
            _logger = logger;
        }

        public async Task<double?> VerifyCaptchaAsync(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                _logger.LogWarning("reCAPTCHA token is missing.");
                return null;
            }

            var secretKey = _configuration["GoogleReCaptcha:SecretKey"];
            if (string.IsNullOrWhiteSpace(secretKey))
            {
                _logger.LogError("Google reCAPTCHA Secret Key is missing from configuration.");
                return null;
            }

            try
            {
                var requestUri = $"https://www.google.com/recaptcha/api/siteverify?secret={secretKey}&response={token}";

                using var response = await _httpClient.PostAsync(requestUri, null);
                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogError("Failed to validate reCAPTCHA. HTTP Status: {StatusCode}", response.StatusCode);
                    return null;
                }

                var jsonString = await response.Content.ReadAsStringAsync();
                var result = JsonSerializer.Deserialize<RecaptchaResponse>(jsonString, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

                if (result?.Success == true)
                {
                    _logger.LogInformation("reCAPTCHA validation succeeded with score: {Score}", result.Score);
                    return result.Score; // ✅ Return the score instead of just true/false
                }
                else
                {
                    _logger.LogWarning("reCAPTCHA validation failed. Error codes: {Errors}", result?.ErrorCodes ?? new string[] { "Unknown Error" });
                    return null;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error occurred during reCAPTCHA validation.");
                return null;
            }
        }

        private class RecaptchaResponse
        {
            public bool Success { get; set; }
            public double Score { get; set; } // ✅ Capture the reCAPTCHA score
            public string ChallengeTs { get; set; }
            public string Hostname { get; set; }
            public string[] ErrorCodes { get; set; }
        }
    }
}
