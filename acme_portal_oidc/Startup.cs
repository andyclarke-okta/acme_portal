using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using okta_aspnetcore_mvc_example.Services;
using Okta.AspNetCore;
using System.Threading.Tasks;
using System.Linq;
using System.Security.Claims;

namespace okta_aspnetcore_mvc_example
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

            // Add Applciation Services
            services.AddScoped<IViewRenderService, ViewRenderService>();
            services.AddScoped<IEmailService, EmailService>();

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
           .AddCookie(options => {
               options.Cookie.Name = "AcmePortalApp";
               //options.AccessDeniedPath = "/Authorization/AccessDenied";
           })
           .AddOktaMvc(new OktaMvcOptions
           {
               // Replace these values with your Okta configuration
               OktaDomain = Configuration.GetValue<string>("OktaWeb:OktaDomain"),
               ClientId = Configuration.GetValue<string>("OktaWeb:ClientId"),
               ClientSecret = Configuration.GetValue<string>("OktaWeb:ClientSecret"),
               //CallbackPath = Configuration.GetValue<string>("OktaWeb:CallbackPath"),
               //PostLogoutRedirectUri = Configuration.GetValue<string>("OktaWeb:PostLogoutRedirectUri"),
               AuthorizationServerId = Configuration.GetValue<string>("OktaWeb:AuthorizationServerId"),
               Scope = new List<string> { "openid", "profile", "email", "groups" },
               OnTokenValidated = myTokenValidated
           }) ;


            

            services.AddControllersWithViews();
        }

        public Task myTokenValidated(TokenValidatedContext context )
        {
            ////get name from claims
            //var myName = context.Principal.Claims.FirstOrDefault(c => c.Type == "name").Value;

            ////add accessoken to claims to support call to Web Api
            //var accessToken = context.TokenEndpointResponse.AccessToken;
            //var claims = new List<Claim>();
            //claims.Add(new Claim("accessToken", accessToken));
            //var appIdentity = new ClaimsIdentity(claims);
            //context.Principal.AddIdentity(appIdentity);


            return Task.FromResult(0);
        }



        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
