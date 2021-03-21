using IdentityServer4;
using IdentityServer4.EntityFramework.DbContexts;
using IdentityServerAspNetIdentity.Data;
using IdentityServerAspNetIdentity.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Linq;
using System.Reflection;
using IdentityServer4.EntityFramework.Mappers;
using IdentityServerAspNetIdentity.Services;
using IdentityServer4.Models;
using IdentityModel;
using Microsoft.IdentityModel.Tokens;
using System;
using SendGrid.Extensions.DependencyInjection;

namespace IdentityServerAspNetIdentity
{
    public class Startup
    {
        public IWebHostEnvironment Environment { get; }
        public IConfiguration Configuration { get; }

        public Startup(IWebHostEnvironment environment, IConfiguration configuration)
        {
            Environment = environment;
            Configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            //IdentityModelEventSource.ShowPII = true; // Better Identity stacktraces and messages. (Insecure)

            services.AddControllersWithViews();

            services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));

            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            var migrationsAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;

            var builder = services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;

                // see https://identityserver4.readthedocs.io/en/latest/topics/resources.html
                options.EmitStaticAudienceClaim = true;
                options.IssuerUri = Configuration["Identity:IssuerUri"];
            })
                .AddConfigurationStore(options => // this adds the config data from DB (clients, resources)
            {
                options.ConfigureDbContext = builder =>
                    builder.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"),
                        sql => sql.MigrationsAssembly(migrationsAssembly));
            }) // this adds the operational data from DB (codes, tokens, consents)
                .AddOperationalStore(options =>
            {
                options.ConfigureDbContext = builder =>
                    builder.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"),
                        sql => sql.MigrationsAssembly(migrationsAssembly));

                options.EnableTokenCleanup = true; // this enables automatic token cleanup. this is optional.
                options.TokenCleanupInterval = 30;
            })
            .AddAspNetIdentity<ApplicationUser>()
            .AddProfileService<ProfileService>();

            if (Environment.IsDevelopment())
            {
                builder.AddDeveloperSigningCredential();
            }
            else
            {
                var rsa = new RsaKeyService(Environment, TimeSpan.FromDays(30));
                services.AddTransient<RsaKeyService>(provider => rsa);
                builder.AddSigningCredential(rsa.GetKey(), IdentityServerConstants.RsaSigningAlgorithm.RS512);
            }

            services.AddAuthentication()
                .AddGoogle(options =>
                {
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    
                    // register your IdentityServer with Google at https://console.developers.google.com
                    // enable the Google+ API
                    // set the redirect URI to http://identity:5000/signin-google
                    options.ClientId = Configuration["Identity:Google:ClientId"];
                    options.ClientSecret = Configuration["Identity:Google:ClientSecret"];
                });

            services.AddSendGrid(options => // Use whatever email provider you want to. I use SendGrid, because it has a basic free plan to get started with.
            {
                options.ApiKey = Configuration["SendGridApiKey"];
            });

            services.AddTransient<IEmailService, FakeEmailService>();
        }

        public void Configure(IApplicationBuilder app)
        {
            InitializeDatabase(app);

            if (Environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }

            app.UseStaticFiles();

            app.UseRouting();

            app.UseIdentityServer();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }

        private void InitializeDatabase(IApplicationBuilder app)
        {
            using var serviceScope = app.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope();

            serviceScope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.Migrate();

            var context = serviceScope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
            context.Database.Migrate();

            // TODO: Move Setup logic to other project?
            if (!context.Clients.Any())
            {
                foreach (var client in Config.Clients)
                {
                    context.Clients.Add(client.ToEntity());
                }
                context.SaveChanges();
            }

            if (!context.IdentityResources.Any())
            {
                foreach (var resource in Config.IdentityResources)
                {
                    context.IdentityResources.Add(resource.ToEntity());
                }
                context.SaveChanges();
            }

            if (!context.ApiScopes.Any())
            {
                foreach (var resource in Config.ApiScopes)
                {
                    context.ApiScopes.Add(resource.ToEntity());
                }
                context.SaveChanges();
            }

            /*
                if (!context.ApiResources.Any())
                {
                    foreach (var resource in Config.ApiScopes)
                    {
                        context.ApiResources.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }
                */
        }
    }

    public sealed class ProfileWithIdentityResource : IdentityResources.Profile
    {
        public ProfileWithIdentityResource()
        {
            this.UserClaims.Add(JwtClaimTypes.Role);
        }
    }
}