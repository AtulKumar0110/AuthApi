using System.Net;
using System.Net.Mail;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
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
            var verifyUrl = $"https://yourdomain.com/verify-email?token={Uri.EscapeDataString(token)}";
            var subject = "Verify your email";
            var body = $"Please verify your email by clicking this link:\n\n{verifyUrl}";

            await SendEmailAsync(email, subject, body);
        }

        public async Task SendPasswordResetEmail(string toEmail, string token)
        {
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            var resetLink = $"https://yourfrontend.com/reset-password?token={encodedToken}&email={toEmail}";
            var subject = "Reset your password";
            var body = $"Click here to reset your password:\n\n{resetLink}";

            await SendEmailAsync(toEmail, subject, body);
        }

        private async Task SendEmailAsync(string toEmail, string subject, string body)
        {
            var smtpHost = _configuration["Email:Smtp:Host"] ?? throw new Exception("SMTP Host missing");
            var smtpPort = int.Parse(_configuration["Email:Smtp:Port"] ?? "587");
            var smtpUser = _configuration["Email:Smtp:Username"] ?? throw new Exception("SMTP Username missing");
            var smtpPass = _configuration["Email:Smtp:Password"] ?? throw new Exception("SMTP Password missing");
            var fromAddress = _configuration["Email:Smtp:From"] ?? smtpUser;

            try
            {
                _logger.LogInformation("📤 Sending email to: {Email}", toEmail);

                using var client = new SmtpClient(smtpHost, smtpPort)
                {
                    Credentials = new NetworkCredential(smtpUser, smtpPass),
                    EnableSsl = true
                };

                var message = new MailMessage(fromAddress, toEmail)
                {
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = false
                };

                await client.SendMailAsync(message);

                _logger.LogInformation("✅ Email sent successfully to: {Email}", toEmail);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Failed to send email to: {Email}", toEmail);
                throw;
            }
        }
    }
}
