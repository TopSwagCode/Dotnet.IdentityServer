using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using BlazorClient.Pages;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication;
using Microsoft.AspNetCore.Components.WebAssembly.Authentication.Internal;

namespace BlazorClient
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var builder = WebAssemblyHostBuilder.CreateDefault(args);
            builder.RootComponents.Add<App>("#app");

            builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });

            builder.Services.AddOidcAuthentication(options =>
            {
                // Configure your authentication provider options here.
                // For more information, see https://aka.ms/blazor-standalone-auth
                builder.Configuration.Bind("Local", options.ProviderOptions);
                options.UserOptions.RoleClaim = "role";
            }).AddAccountClaimsPrincipalFactory<
                ArrayClaimsPrincipalFactory<RemoteUserAccount>>();

            builder.Services.AddApiAuthorization();
            
            builder.Services.AddScoped<CustomAuthorizationMessageHandler>();

            builder.Services.AddHttpClient<WeatherForecastClient>(
                    client => client.BaseAddress = new Uri("https://localhost:6002/"))
                .AddHttpMessageHandler<CustomAuthorizationMessageHandler>();
            
            await builder.Build().RunAsync();
        }
    }

    public class WeatherForecastClient
    {
        private readonly HttpClient http;

        public WeatherForecastClient(HttpClient http)
        {
            this.http = http;
        }

        public async Task<FetchData.WeatherForecast[]> GetForecastAsync()
        {
            var forecasts = new FetchData.WeatherForecast[0];

            try
            {
                forecasts = await http.GetFromJsonAsync<FetchData.WeatherForecast[]>(
                    "WeatherForecast");
            }
            catch (AccessTokenNotAvailableException exception)
            {
                exception.Redirect();
            }

            return forecasts;
        }
    }

    public class CustomAuthorizationMessageHandler : AuthorizationMessageHandler
    {
        public CustomAuthorizationMessageHandler(IAccessTokenProvider provider,
            NavigationManager navigationManager)
            : base(provider, navigationManager)
        {
            ConfigureHandler(authorizedUrls: new[] { "https://localhost:6002/weatherforecast" });
        }
    }

    public class ArrayClaimsPrincipalFactory<TAccount> : AccountClaimsPrincipalFactory<TAccount> where TAccount : RemoteUserAccount
    {
        public ArrayClaimsPrincipalFactory(IAccessTokenProviderAccessor accessor)
            : base(accessor)
        { }


        // when a user belongs to multiple roles, IS4 returns a single claim with a serialised array of values
        // this class improves the original factory by deserializing the claims in the correct way
        public async override ValueTask<ClaimsPrincipal> CreateUserAsync(TAccount account, RemoteAuthenticationUserOptions options)
        {
            var user = await base.CreateUserAsync(account, options);

            var claimsIdentity = (ClaimsIdentity)user.Identity;

            if (account != null)
            {
                foreach (var kvp in account.AdditionalProperties)
                {
                    var name = kvp.Key;
                    var value = kvp.Value;
                    if (value != null &&
                        (value is JsonElement element && element.ValueKind == JsonValueKind.Array))
                    {
                        claimsIdentity.RemoveClaim(claimsIdentity.FindFirst(kvp.Key));

                        var claims = element.EnumerateArray()
                            .Select(x => new Claim(kvp.Key, x.ToString()));

                        claimsIdentity.AddClaims(claims);
                    }
                }
            }

            return user;
        }
    }
}
