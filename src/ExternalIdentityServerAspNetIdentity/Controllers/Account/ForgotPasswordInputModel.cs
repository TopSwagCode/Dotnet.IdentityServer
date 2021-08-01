using System.ComponentModel.DataAnnotations;

namespace ExternalIdentityServerAspNetIdentity.Controllers.Account
{
    public class ForgotPasswordInputModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        public string Base64ReturnUrl { get; set; }
    }
}