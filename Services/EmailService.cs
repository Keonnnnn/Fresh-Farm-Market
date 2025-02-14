using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace FreshFarmMarket.Services
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailService> _logger;
        private readonly SmtpClient _smtpClient;

        public EmailService(IConfiguration configuration, ILogger<EmailService> logger)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            // Initialize SMTP client with configuration
            _smtpClient = InitializeSmtpClient();
        }

        private SmtpClient InitializeSmtpClient()
        {
            try
            {
                var smtpServer = _configuration["EmailSettings:SmtpServer"];
                var smtpPort = int.Parse(_configuration["EmailSettings:SmtpPort"]);
                var enableSsl = bool.Parse(_configuration["EmailSettings:EnableSsl"]);
                var smtpUsername = _configuration["EmailSettings:SmtpUsername"];
                var smtpPassword = _configuration["EmailSettings:SmtpPassword"];

                if (string.IsNullOrEmpty(smtpServer) || string.IsNullOrEmpty(smtpUsername) || string.IsNullOrEmpty(smtpPassword))
                {
                    throw new InvalidOperationException("SMTP settings are not properly configured in appsettings.json");
                }

                return new SmtpClient
                {
                    Host = smtpServer,
                    Port = smtpPort,
                    EnableSsl = enableSsl,
                    DeliveryMethod = SmtpDeliveryMethod.Network,
                    UseDefaultCredentials = false,
                    Credentials = new NetworkCredential(smtpUsername, smtpPassword),
                    Timeout = 30000 // 30 seconds timeout
                };
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error initializing SMTP client: {ex.Message}");
                throw new InvalidOperationException("Failed to initialize SMTP client", ex);
            }
        }

        public async Task SendEmailAsync(string to, string subject, string body)
        {
            if (string.IsNullOrEmpty(to))
                throw new ArgumentNullException(nameof(to));
            if (string.IsNullOrEmpty(subject))
                throw new ArgumentNullException(nameof(subject));
            if (string.IsNullOrEmpty(body))
                throw new ArgumentNullException(nameof(body));

            try
            {
                var fromEmail = _configuration["EmailSettings:FromEmail"];
                var fromName = _configuration["EmailSettings:FromName"];

                if (string.IsNullOrEmpty(fromEmail))
                    throw new InvalidOperationException("Sender email is not configured");

                using var mailMessage = new MailMessage
                {
                    From = new MailAddress(fromEmail, fromName ?? "Fresh Farm Market"),
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = true
                };

                mailMessage.To.Add(to);

                // Add retry logic for transient failures
                int maxRetries = 3;
                int currentRetry = 0;

                while (currentRetry < maxRetries)
                {
                    try
                    {
                        await _smtpClient.SendMailAsync(mailMessage);
                        _logger.LogInformation($"Email sent successfully to {to}");
                        return; // Success, exit the method
                    }
                    catch (SmtpException ex) when (currentRetry < maxRetries - 1)
                    {
                        currentRetry++;
                        _logger.LogWarning($"Attempt {currentRetry} failed to send email to {to}: {ex.Message}");
                        await Task.Delay(1000 * currentRetry); // Exponential backoff
                    }
                }

                throw new SmtpException($"Failed to send email after {maxRetries} attempts");
            }
            catch (SmtpException ex)
            {
                _logger.LogError($"SMTP error sending email to {to}: {ex.Message}");
                _logger.LogError($"Status code: {ex.StatusCode}");
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Unexpected error sending email to {to}: {ex.Message}");
                throw;
            }
        }

        // Implement IDisposable if needed
        public void Dispose()
        {
            _smtpClient?.Dispose();
        }
    }
}