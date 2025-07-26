namespace AuthApi.Services
{
    public interface IEmailService
    {
        Task SendVerificationEmail(string email, string token);
        Task SendPasswordResetEmail(string toEmail, string token);
        Task SendAsync(string toEmail, string subject, string body);
    }
}
