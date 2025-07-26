using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Threading;
using System.Threading.Tasks;
using AuthApi.Data;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Services
{
    public class TokenCleanupService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly TimeSpan _interval = TimeSpan.FromHours(1);

        public TokenCleanupService(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                using (var scope = _serviceProvider.CreateScope())
                {
                    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

                    var expiredTokens = await dbContext.PasswordResetTokens
                        .Where(t => t.ExpiryTime < DateTime.UtcNow || t.IsUsed)
                        .ToListAsync(stoppingToken);

                    if (expiredTokens.Any())
                    {
                        dbContext.PasswordResetTokens.RemoveRange(expiredTokens);
                        await dbContext.SaveChangesAsync(stoppingToken);
                    }
                }

                await Task.Delay(_interval, stoppingToken);
            }
        }
    }
}
