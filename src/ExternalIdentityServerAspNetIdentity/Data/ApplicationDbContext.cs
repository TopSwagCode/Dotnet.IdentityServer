using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using ExternalIdentityServerAspNetIdentity.Models;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace ExternalIdentityServerAspNetIdentity.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<UserSignupRequest> UserSignupRequests { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            // Customize the ASP.NET Identity model and override the defaults if needed.
            // For example, you can rename the ASP.NET Identity table names and more.
            // Add your customizations after calling base.OnModelCreating(builder);

            UserSignupRequestEntityBuilder(builder.Entity<UserSignupRequest>());
        }

        private void UserSignupRequestEntityBuilder(EntityTypeBuilder<UserSignupRequest> entityTypeBuilder)
        {
            entityTypeBuilder.HasKey(x => x.EmailValidationToken);
            entityTypeBuilder.Property(x => x.Email).IsRequired();
            entityTypeBuilder.Property(x => x.ExpireOnUtc).IsRequired();
            entityTypeBuilder.Property(x => x.IsEmailValidationTokenUsed).IsRequired();
        }
    }
}
