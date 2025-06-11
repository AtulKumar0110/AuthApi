using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Configuration;

namespace AuthApi.Services
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;

        public EmailService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task SendVerificationEmail(string email, string token)
        {
            var smtpHost = _configuration["Email:Smtp:Host"] ?? throw new Exception("SMTP Host missing");
            var smtpPort = int.Parse(_configuration["Email:Smtp:Port"] ?? "587");
            var smtpUser = _configuration["Email:Smtp:Username"] ?? throw new Exception("SMTP Username missing");
            var smtpPass = _configuration["Email:Smtp:Password"] ?? throw new Exception("SMTP Password missing");
            var fromAddress = _configuration["Email:Smtp:From"] ?? smtpUser;

            var verifyUrl = $"https://yourdomain.com/verify-email?token={Uri.EscapeDataString(token)}";

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
        }
    }
}
