using System.ComponentModel.DataAnnotations;

namespace IdentityServerAspNetIdentity.Controllers.Account
{
    public class ForgotPasswordInputModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        public string Base64ReturnUrl { get; set; }
    }
}