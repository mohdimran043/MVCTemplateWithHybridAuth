using IdentityModel;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace MVCWebApplication
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
            services.AddAuthorization(options =>
            {
                options.AddPolicy("All", policy => policy.RequireRole("admin", "editor"));
                options.AddPolicy("Admin", policy => policy.RequireRole("admin"));
            });
            services.AddAuthentication(options =>
                {
                    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                    options.DefaultSignOutScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                }).AddCookie().AddOpenIdConnect(options => SetOpenIdConnectOptions(options));

        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseAuthentication();

            app.UseStaticFiles();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
       
        private void SetOpenIdConnectOptions(OpenIdConnectOptions options)
        {

            options.Authority = "http://localhost:4343/";
            options.ClientId = "mvc-client-hybrid";
            options.RequireHttpsMetadata = false;
            options.ClientSecret = "segredo";
            options.SignInScheme = "Cookies";
            options.SaveTokens = true;
            
            options.GetClaimsFromUserInfoEndpoint = true;
            options.ResponseType = "code token id_token";            
            options.Scope.Add("openid");
            options.Scope.Add("offline_access");


            options.Events.OnRedirectToIdentityProvider = context =>
            {
                // only modify requests to the authorization endpoint
                if (context.ProtocolMessage.RequestType == OpenIdConnectRequestType.Authentication)
                {
                    // generate code_verifier
                    var codeVerifier = CryptoRandom.CreateUniqueId(32);

                    // store codeVerifier for later use
                    context.Properties.Items.Add("code_verifier", codeVerifier);

                    // create code_challenge
                    string codeChallenge;
                    using (var sha256 = SHA256.Create())
                    {
                        var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
                        codeChallenge = Base64Url.Encode(challengeBytes);
                    }

                    // add code_challenge and code_challenge_method to request
                    context.ProtocolMessage.Parameters.Add("code_challenge", codeChallenge);
                    context.ProtocolMessage.Parameters.Add("code_challenge_method", "S256");
                }

                return Task.CompletedTask;
            };

            options.Events.OnAuthorizationCodeReceived = context =>
            {
                // only when authorization code is being swapped for tokens
                if (context.TokenEndpointRequest?.GrantType == OpenIdConnectGrantTypes.AuthorizationCode)
                {
                    // get stored code_verifier
                    if (context.Properties.Items.TryGetValue("code_verifier", out var codeVerifier))
                    {
                        // add code_verifier to token request
                        context.TokenEndpointRequest.Parameters.Add("code_verifier", codeVerifier);
                    }
                }

                return Task.CompletedTask;
            };

        }
    }
}
