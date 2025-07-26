namespace AuthApi.Services // Match your root namespace
{
    public interface ISmsService
    {
        Task SendAsync(string phoneNumber, string message);
    }
}
