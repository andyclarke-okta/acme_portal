using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.Cookies;
using okta_aspnetcore_mvc_example.Models;
using System.Security.Claims;
using RestSharp;

namespace okta_aspnetcore_mvc_example.Controllers
{
    public class OidcController : Controller
    {

        private readonly ILogger<OidcController> _logger;
        private readonly IConfiguration _config;
        //private readonly IHttpClientFactory _clientFactory;
        //public OidcController(ILogger<OidcController> logger, IConfiguration config, IHttpClientFactory clientFactory)
        public OidcController(ILogger<OidcController> logger, IConfiguration config)
        {
            _logger = logger;
            _config = config;
            //_clientFactory = clientFactory;
        }

        [HttpGet]
        public async Task<ActionResult> ValidationEndpoint(string code, string state)
        {
            string error = null;
            string error_description = null;
            string token_type = null;
            string scope = null;
            string id_token_status = null;
            string idToken = "";
            string access_token_status = null;
            string accessToken = "";
            string refresh_token_status = null;
            string refreshToken = "";
            IRestResponse<TokenRequestResponse> response = null;
            System.Security.Claims.ClaimsPrincipal claimsPrincipal = null;

            string basicAuth = _config.GetValue<string>("OktaWeb:ClientId") + ":" + _config.GetValue<string>("OktaWeb:ClientSecret");

            var bytesBasicAuth = System.Text.Encoding.UTF8.GetBytes(basicAuth);
            string encodedBasicAuth = System.Convert.ToBase64String(bytesBasicAuth);

            try
            {
                var client = new RestClient(_config.GetValue<string>("OktaWeb:Authority") + "/v1/token");
                var request = new RestRequest(Method.POST);
                request.AddHeader("Accept", "application/json");
                request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
                request.AddHeader("Authorization", " Basic " + encodedBasicAuth);
                request.AddQueryParameter("grant_type", "authorization_code");
                request.AddQueryParameter("code", code);
                request.AddQueryParameter("redirect_uri", _config.GetValue<string>("OktaWeb:RedirectUri"));

                response = client.Execute<TokenRequestResponse>(request);


                if (response.Data != null)
                {
                    error = response.Data.error;
                    error_description = response.Data.error_description;
                    token_type = response.Data.token_type;
                    scope = response.Data.scope;
                }

                //accessToken
                if (response.Data.access_token != null)
                {
                    accessToken = response.Data.access_token;
                    access_token_status = "access_token present";
                    //TempData["accessToken"] = response.Data.access_token;
                }
                else
                {
                    access_token_status = "access_token NOT present";
                }

                //refreshToken
                if (response.Data.refresh_token != null)
                {
                    refreshToken = response.Data.refresh_token;
                    refresh_token_status = "refresh_token present";
                    //TempData["refreshToken"] = response.Data.refresh_token;
                }
                else
                {
                    refresh_token_status = "refresh_token NOT present";
                }

                //idToken
                if (response.Data.id_token != null)
                {
                    id_token_status = "id_token present";
                    idToken = response.Data.id_token;

                    string issuer = _config.GetValue<string>("OktaWeb:Authority");
                    string audience = _config.GetValue<string>("OktaWeb:ClientId");

                    claimsPrincipal = ValidateIdToken(idToken, issuer, audience);
                    if (claimsPrincipal.Identity.IsAuthenticated)
                    {

                        ClaimsIdentity claimsIdentity = (ClaimsIdentity)claimsPrincipal.Identity;
                        //claimsIdentity.AddClaim(new Claim("idToken", idToken));
                        //claimsIdentity.AddClaim(new Claim("accessToken", accessToken));
                        //claimsIdentity.AddClaim(new Claim("refreshToken", refreshToken));

                        var authProperties = new AuthenticationProperties
                        {
                            //AllowRefresh = <bool>,
                            // Refreshing the authentication session should be allowed.

                            //ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10),
                            // The time at which the authentication ticket expires. A 
                            // value set here overrides the ExpireTimeSpan option of 
                            // CookieAuthenticationOptions set with AddCookie.

                            //IsPersistent = true,
                            // Whether the authentication session is persisted across 
                            // multiple requests. When used with cookies, controls
                            // whether the cookie's lifetime is absolute (matching the
                            // lifetime of the authentication ticket) or session-based.

                            //IssuedUtc = <DateTimeOffset>,
                            // The time at which the authentication ticket was issued.

                            //RedirectUri = <string>
                            // The full path or absolute URI to be used as an http 
                            // redirect response value.
                        };

                        List<AuthenticationToken> authTokens = new List<AuthenticationToken>();
                        AuthenticationToken myIdToken = new AuthenticationToken() { Name = "id_token", Value = idToken };
                        authTokens.Add(myIdToken);
                        AuthenticationToken myAccessToken = new AuthenticationToken() { Name = "access_token", Value = accessToken };
                        authTokens.Add(myAccessToken);

                        authProperties.StoreTokens(authTokens);

                        await HttpContext.SignInAsync(
                            CookieAuthenticationDefaults.AuthenticationScheme,
                            claimsPrincipal,
                            authProperties);

                    }
                    else
                    {
                        TempData["errMessage"] = "Invalid ID Token!";

                    }
                    //TempData["idToken"] = idToken;
                }
                else
                {
                    id_token_status = "id_token NOT present";
                }


            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex.ToString());

            }

            return RedirectToAction("Index", "Home");
        }


        public System.Security.Claims.ClaimsPrincipal ValidateIdToken(string idToken, string issuer, string audience)
        {
            System.Security.Claims.ClaimsPrincipal claimPrincipal = null;

            IConfigurationManager<OpenIdConnectConfiguration> configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>($"{issuer}/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever());
            //OpenIdConnectConfiguration openIdConfig = RunSync(async () => await configurationManager.GetConfigurationAsync(CancellationToken.None));


            OpenIdConnectConfiguration openIdConfig = configurationManager.GetConfigurationAsync(CancellationToken.None).Result;


            Microsoft.IdentityModel.Tokens.TokenValidationParameters validationParameters =
                new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidAudience = audience,
                    ValidIssuer = issuer,
                    IssuerSigningKeys = openIdConfig.SigningKeys,
                    ValidateIssuerSigningKey = true,
                    ValidateAudience = true,
                    ValidateIssuer = true,
                    ValidateLifetime = true
                };

            Microsoft.IdentityModel.Tokens.SecurityToken validatedToken;
            System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();

            try
            {
                claimPrincipal = handler.ValidateToken(idToken, validationParameters, out validatedToken);

            }
            catch (Exception ex)
            {
                var error = ex.Message;
            }




            return claimPrincipal;
        }




    }
}