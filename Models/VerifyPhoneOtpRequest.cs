using System.ComponentModel.DataAnnotations;

public class VerifyPhoneOtpRequest
{
    [Required]
    public string PhoneNumber { get; set; }

    [Required]
    public string Otp { get; set; }
}
