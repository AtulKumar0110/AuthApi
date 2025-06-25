using System;

public class CustomToken
{
    public int Id { get; set; }
    public string UserId { get; set; }
    public string TokenHash { get; set; }
    public string Purpose { get; set; } // e.g., "EmailVerification", "PasswordReset"
    public DateTime ExpiryTime { get; set; }
    public bool IsUsed { get; set; } = false;
}
