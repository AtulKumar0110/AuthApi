using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace AuthApi.Services
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailService> _logger;

        public EmailService(IConfiguration configuration, ILogger<EmailService> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public async Task SendVerificationEmail(string email, string token)
        {
            var smtpHost = _configuration["Email:Smtp:Host"] ?? throw new Exception("SMTP Host missing");
            var smtpPort = int.Parse(_configuration["Email:Smtp:Port"] ?? "587");
            var smtpUser = _configuration["Email:Smtp:Username"] ?? throw new Exception("SMTP Username missing");
            var smtpPass = _configuration["Email:Smtp:Password"] ?? throw new Exception("SMTP Password missing");
            var fromAddress = _configuration["Email:Smtp:From"] ?? smtpUser;

            var verifyUrl = $"https://yourdomain.com/verify-email?token={Uri.EscapeDataString(token)}";

            try
            {
                _logger.LogInformation("📤 Sending verification email to: {Email}", email);

                using var client = new SmtpClient(smtpHost, smtpPort)
                {
                    Credentials = new NetworkCredential(smtpUser, smtpPass),
                    EnableSsl = true
                };

                var message = new MailMessage(fromAddress, email)
                {
                    Subject = "Verify your email",
                    Body = $"Please verify your email by clicking this link:\n\n{verifyUrl}",
                    IsBodyHtml = false
                };

                await client.SendMailAsync(message);

                _logger.LogInformation("✅ Email sent successfully to: {Email}", email);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Failed to send verification email to: {Email}", email);
                throw; // Optional: rethrow to handle upstream
            }
        }
    }
}
