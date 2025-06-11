namespace AuthApi.Services
{
    public interface IEmailService
    {
        Task SendVerificationEmail(string email, string token);
    }
}
