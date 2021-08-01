using System.ComponentModel.DataAnnotations;

namespace ExternalIdentityServerAspNetIdentity.Controllers.Account
{
    public class ResetPasswordModela // TODO Rename. ResetPasswordModel is taken by identity itself
    {
        [DataType(DataType.Password)]
        public string Password { get; set; }
        [DataType(DataType.Password)]

        public string ConfirmPassword { get; set; }
        public string Email { get; set; }
        public string Token { get; set; }
    }
}