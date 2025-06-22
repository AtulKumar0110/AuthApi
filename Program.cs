using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using AuthApi.Data;
using AuthApi.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using AuthApi.Services; // ✅ For EmailService & SmsService
using Microsoft.Extensions.Logging;

var builder = WebApplication.CreateBuilder(args);

// ✅ Enable console and debug logging (optional, for dev use)
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

// Add services to the container
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// ✅ Register DbContext with MySQL
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseMySql(
        builder.Configuration.GetConnectionString("DefaultConnection"),
        new MySqlServerVersion(new Version(8, 0, 36))
    )
);

// ✅ Add Identity services
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// ✅ Register EmailService with ILogger support
builder.Services.AddScoped<IEmailService, EmailService>();

// ✅ Register SmsService
builder.Services.AddScoped<ISmsService, SmsService>(); // <-- 📌 ADD THIS LINE

// ✅ Add JWT Authentication
var jwtKey = builder.Configuration["Jwt:Key"];
var jwtIssuer = builder.Configuration["Jwt:Issuer"];

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtIssuer,
        ValidAudience = jwtIssuer,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
    };
});

// ✅ Add Authorization
builder.Services.AddAuthorization();

// ✅ Register Background Token Cleanup Service
builder.Services.AddHostedService<TokenCleanupService>();

var app = builder.Build();

// ✅ Configure middleware
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
