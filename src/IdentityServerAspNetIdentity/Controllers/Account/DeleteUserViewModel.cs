namespace IdentityServerAspNetIdentity.Controllers.Account
{
    public class DeleteUserViewModel : DeleteUserInputModel
    {
        public bool IsLocalUser { get; set; }
    }
}