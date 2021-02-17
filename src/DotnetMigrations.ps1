cd .\IdentityServerAspNetIdentity

dotnet ef database update --context ApplicationDbContext
dotnet ef database update --context PersistedGrantDbContext
dotnet ef database update --context ConfigurationDbContext
