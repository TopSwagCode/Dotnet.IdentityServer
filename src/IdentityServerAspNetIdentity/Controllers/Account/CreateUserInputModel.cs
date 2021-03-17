using System;
using System.ComponentModel.DataAnnotations;

namespace IdentityServerHost.Quickstart.UI
{
    public class CreateUserInputModel
    {
        [Required]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
        [Required]
        public string PasswordRepeat { get; set; }
        [Required]
        public string Email { get; set; }
        public Guid? EmailValidationToken { get; set; }
        public string Base64ReturnUrl { get; set; }
    }
}