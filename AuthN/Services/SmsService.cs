using System.Threading.Tasks;

namespace AuthApi.Services
{
    public class SmsService : ISmsService
    {
        public async Task SendAsync(string phoneNumber, string message)
        {
            // 🧪 For now, just simulate sending SMS
            Console.WriteLine($"SMS to {phoneNumber}: {message}");
            await Task.CompletedTask;
        }
    }
}
