cd .\IdentityServerAspNetIdentity

dotnet ef migrations add MigrationName -c ApplicationDbContext -o Data/Migrations/IdentityServer/ApplicationDb

dotnet ef migrations add UserSignupRequest -c ApplicationDbContext -o Data/Migrations/IdentityServer/ApplicationDb