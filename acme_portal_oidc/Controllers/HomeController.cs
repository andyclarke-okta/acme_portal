using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Okta.AspNetCore;
using Okta.Sdk;
using Okta.Sdk.Configuration;
using okta_aspnetcore_mvc_example.Models;
using FluentEmail.Core;
using FluentEmail.Mailgun;
using okta_aspnetcore_mvc_example.Services;
using System.Security.Claims;
using RestSharp;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;

namespace okta_aspnetcore_mvc_example.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        private readonly IConfiguration _config;
        private readonly IViewRenderService _viewRenderService;
        private readonly IEmailService _emailService;
        public List<AppLink>  _userAppList = null;

        public HomeController(ILogger<HomeController> logger, IConfiguration config, IViewRenderService viewRenderService,IEmailService emailService)
        {
            _logger = logger;
            _config = config;
            _viewRenderService = viewRenderService;
            _emailService = emailService;
        }
    

        public IActionResult Index()
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                _userAppList = GetUserApps();
            }
            return View(_userAppList);
        }

        public IActionResult About()
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                _userAppList = GetUserApps();
            }
            return View(_userAppList);
            //return View();
        }


        //[Authorize]
        //public ActionResult Login()
        //{
        //    ViewBag.Message = "Global Login";

        //    if (!HttpContext.User.Identity.IsAuthenticated)
        //    {
        //        var properties = new AuthenticationProperties();
        //        //without this, the redirect defaults to entry point of initialization
        //        //properties.RedirectUri = "/Home/PostLogOut";
        //        return Challenge(properties, OktaDefaults.MvcAuthenticationScheme);
        //    }
        //    return RedirectToAction("Index", "Home");
        //    //return RedirectToAction("PostLogin", "Home");
        //}


        public ActionResult Login()
        {
            ViewBag.Message = "Login";

            if (HttpContext.User.Identity.IsAuthenticated)
            {
                _userAppList = GetUserApps();
            }

            //TempData["redirectUri"] = "https://localhost:44306/Home/Login";
            //return View("../Account/authnLogin",_userAppList);

            return View("../Account/oidcAuthCodeLogin", _userAppList);

            //return View("../Account/oidcImplicitLogin", _userAppList);

            //return View("../Account/oidcSignInWithSessionToken", _userAppList);

            //return RedirectToAction("SignInRemote", "Account");
        }



        [HttpPost]
        public async Task<IActionResult> ImplicitLanding(string accessToken, string idToken)
        {
            System.Security.Claims.ClaimsPrincipal claimPrincipal = null;

            Microsoft.IdentityModel.Tokens.TokenValidationParameters validationParameters =
                new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidateIssuerSigningKey = false,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateLifetime = false
                };

            System.IdentityModel.Tokens.Jwt.JwtSecurityToken jwtSecurityToken;
            System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();

            jwtSecurityToken = handler.ReadJwtToken(idToken);
            List<System.Security.Claims.Claim> claims = jwtSecurityToken.Claims.ToList();
            //claims.Add(new Claim("idToken", idToken));
            //claims.Add(new Claim("accessToken", accessToken));

            var claimsIdentity = new ClaimsIdentity(
                claims, CookieAuthenticationDefaults.AuthenticationScheme);

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
            AuthenticationToken myToken = new AuthenticationToken() { Name = "id_token", Value = idToken };
            authTokens.Add(myToken);
            AuthenticationToken myAccessToken = new AuthenticationToken() { Name = "access_token", Value = accessToken };
            authTokens.Add(myAccessToken);



            authProperties.StoreTokens(authTokens);

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                authProperties);



            return View();
        }



        //[HttpPost]
        //public ActionResult Logout()
        //{
        //    return new SignOutResult(
        //        new[]
        //        {
        //             OktaDefaults.MvcAuthenticationScheme,
        //             CookieAuthenticationDefaults.AuthenticationScheme,
        //        },
        //       new AuthenticationProperties { RedirectUri = "/Home/Index" });
        //    //new AuthenticationProperties { RedirectUri = "/Home/PostLogOut" });
        //}

        public ActionResult Register()
        {
            ViewBag.Message = "Registration Page.";

            return View();
            //return RedirectToAction("Index", "Home");
            //return RedirectToAction("PostLogin", "Home");
        }

        [HttpPost]
        public async Task<ActionResult> RegisterRoute([FromForm]RegisterUser newuser)
        {

            Okta.Sdk.IUser oktaUser = null;

            var client = new OktaClient(new OktaClientConfiguration
            {
                OktaDomain = _config.GetValue<string>("OktaWeb:OktaDomain"),
                Token = _config.GetValue<string>("OktaWeb:ApiToken")
            });


            UserProfile userProfile = new UserProfile
            {
                FirstName = newuser.firstName,
                LastName = newuser.lastName,
                Email = newuser.email,
                Login = newuser.email
            };

            // Create a user with the specified password
            oktaUser = await client.Users.CreateUserAsync(new CreateUserWithPasswordOptions
            {
                // User profile object
                Profile = userProfile,
                Password = newuser.password,
                Activate = false,
            });

            oktaUser.Profile["customId"] = newuser.customId;
            await oktaUser.UpdateAsync();

            return View("PostRegister");
        }

        [Authorize]
        public ActionResult PostLogin()
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                _userAppList = GetUserApps();
            }
            return View(_userAppList);
            //return View();
        }

        public ActionResult PostLogOut()
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                _userAppList = GetUserApps();
            }
            return View(_userAppList);
            //return View();
        }



        public List<AppLink> GetUserApps()
        {
            Okta.Sdk.User oktaUser = null;
            List<AppLink> userAppList = new List<AppLink>();

            var client = new OktaClient(new OktaClientConfiguration
            {
                OktaDomain = _config.GetValue<string>("OktaWeb:OktaDomain"),
                Token = _config.GetValue<string>("OktaWeb:ApiToken")
            });

            var oktaId = this.User.Claims.FirstOrDefault(x => x.Type == "sub").Value;

          

            oktaUser = (Okta.Sdk.User)client.Users.GetUserAsync(oktaId).Result;

            //string userId = oktaUser.Id;

            ////var myResource = client.GetAsync<Okta.Sdk.Resource>(new Okta.Sdk.HttpRequest
            ////{
            ////    Uri = $"/api/v1/users/{userId}/appLinks",
            ////    PathParameters = new Dictionary<string, object>()
            ////    {
            ////        ["userId"] = oktaId,
            ////    }
            ////});

            ////Okta.Sdk.IResource;

            //CollectionClient<Okta.Sdk.IResource> myCol = client.GetCollection<Okta.Sdk.IResource>(new Okta.Sdk.HttpRequest
            //{
            //    Uri = $"/api/v1/users/{userId}/appLinks",
            //    PathParameters = new Dictionary<string, object>()
            //    {
            //        ["userId"] = oktaId,
            //    }
            //});

            var myList = client.Users.ListAppLinks(oktaId).ToListAsync().Result;
            foreach (var item in myList)
            {
                if (item.Label.IndexOf("Portal") < 0 )
                {
                    userAppList.Add((AppLink)item);
                }
                
            }

            return userAppList;
        }


        [HttpGet]
        [Authorize]
        public async Task<ActionResult> RequestApp()
        {
            string myManager = null;
            string oktaId = null;
            string myName = null;

            if (User.Identity.IsAuthenticated)
            {
                myName = User.Identity.Name;
                oktaId = User.Claims.FirstOrDefault(x => x.Type == "sub").Value;
                myManager = User.Claims.FirstOrDefault(x => x.Type == "manager").Value;
            }
            else
            {
                myName = "unknown";
                oktaId = "9876543";
            }


            //send email
            var basePath = $"{Request.Scheme}://{Request.Host}";
            EmailViewModel emailViewModel = new EmailViewModel
            {
                OktaId = oktaId,
                Name = myName,
                LinkExpiry = "72",
                AcceptToken = "123456",
                RejectToken = "987654",
                BasePath = basePath
            };
            var result = await _viewRenderService.RenderToStringAsync("Shared/_AccessApproval", emailViewModel);
            var isSuccess = await _emailService.SendEmail("admin@aclarkesylvania.com", myManager, "Application Approval Request", result);

            //needed whenever Layout page is rendered
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                _userAppList = GetUserApps();
            }

            return View("RequestApp", _userAppList);
        }



        [HttpGet]
        public ActionResult RequestReply(string token, string locator)
        {

            ProcessRequestReply(token, locator);

            return View("RequestReply");
            //return RedirectToAction("Index", "Home");
        }



        public string ProcessRequestReply(string token, string oktaId)
        {
            Okta.Sdk.User oktaUser = null;

            var client = new OktaClient(new OktaClientConfiguration
            {
                OktaDomain = _config.GetValue<string>("OktaWeb:OktaDomain"),
                Token = _config.GetValue<string>("OktaWeb:ApiToken")
            });

            if (string.IsNullOrEmpty(token) && TempData["token"] != null)
            {
                token = TempData["token"].ToString();
            }

            if (oktaId != null)
            {
                //get user to ensure state
                oktaUser = (Okta.Sdk.User)client.Users.GetUserAsync(oktaId).Result;
 
                if (token == "123456")
                {
                    //add user to group
                    var group = client.Groups.FirstOrDefaultAsync(x => x.Profile.Name == "OIDC_users").Result;
                    if (group != null && oktaUser != null)
                    {
                        client.Groups.AddUserToGroupAsync(group.Id, oktaUser.Id); ;
                    }



                    //send approval notice email
                    var basePath = $"{Request.Scheme}://{Request.Host}";
                    EmailViewModel emailViewModel = new EmailViewModel
                    {
                        OktaId = oktaUser.Id,
                        Name = string.Format("{0} {1}", oktaUser.Profile.FirstName, oktaUser.Profile.LastName),
                        LinkExpiry = "72",
                        AcceptToken = "123456",
                        RejectToken = "987654",
                        BasePath = basePath
                    };
                    var result = _viewRenderService.RenderToStringAsync("Shared/_AccessGranted", emailViewModel).Result;
                    var isSuccess = _emailService.SendEmail("admin@aclarkesylvania.com", oktaUser.Profile.Email , "Application Access Approved", result);

                }
                else
                {
                    //send reject notice email
                    var basePath = $"{Request.Scheme}://{Request.Host}";
                    EmailViewModel emailViewModel = new EmailViewModel
                    {
                        OktaId = oktaUser.Id,
                        Name = string.Format("{0} {1}", oktaUser.Profile.FirstName, oktaUser.Profile.LastName),
                        LinkExpiry = "72",
                        AcceptToken = "123456",
                        RejectToken = "987654",
                        BasePath = basePath
                    };
                    var result = _viewRenderService.RenderToStringAsync("Shared/_AccessRejected", emailViewModel).Result;
                    var isSuccess = _emailService.SendEmail("admin@aclarkesylvania.com", oktaUser.Profile.Email, "Application Access Rejected", result);

                }

                return "success";
            }
            else
            {
                return "failed";
            }
        }


        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [Authorize]
        public IActionResult Profile()
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                _userAppList = GetUserApps();
            }
            return View(_userAppList);
            //return View(HttpContext.User.Claims);
        }






        //[HttpPost]
        public IActionResult SendApi()
        {
            //from asp.net middleware
            var accessToken = HttpContext.GetTokenAsync("access_token").Result;
            //var refreshToken = HttpContext.GetTokenAsync("refresh_token").Result;
            //var expiresAt = DateTimeOffset.Parse( HttpContext.GetTokenAsync("expires_at").Result);

            //from user.Identity Claims
            //string myAccessToken = HttpContext.User.Claims.FirstOrDefault(x => x.Type == "accessToken").Value;

            string rspSendApi = SendTokenToWebApi(accessToken, _config.GetValue<string>("SendApi:BackendApi"));

            var modRsp = JObject.Parse(rspSendApi);

            ApiResponseModel anotherMod = JsonConvert.DeserializeObject<ApiResponseModel>(rspSendApi);


            ViewData["apiRsp"] = anotherMod;
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                _userAppList = GetUserApps();
            }
            return View(_userAppList);

            //return View(anotherMod);
            //return RedirectToAction("ApiResponseLanding", "Home");
        }


        public string SendTokenToWebApi(string access_token, string destPage)
        {
            string rsp = "Api call failed";

            IRestResponse response = null;

            var client = new RestClient(destPage);
            var request = new RestRequest(Method.GET);
            // request.AddHeader("cache-control", "no-cache");
            request.AddHeader("Accept", "application/json");
            request.AddHeader("Content-Type", "application/json");
            request.AddHeader("Authorization", "Bearer " + access_token);
            response = client.Execute(request);

            if (response.StatusDescription == "Forbidden" || response.StatusDescription == "Unauthorized")
            {
                return rsp;
            }


            if (response.StatusDescription == "OK")
            {
                return response.Content;       
            }
            else
            {
                return rsp;
            }
        }


    }
}
