using System;
using System.Collections.Generic;
using System.Linq;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Serialization;
using SMART.Models;
using SMART.Controllers;
using static SMART.Models.SMARTBANK;

// Project
namespace SMART
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
			services.AddControllersWithViews().AddRazorRuntimeCompilation();

			// Cookie policy
			services.Configure<CookiePolicyOptions>(options =>
			{

				// This lambda determines whether user consent for non-essential cookies is needed for a given request.
				options.CheckConsentNeeded = context => true;
				options.MinimumSameSitePolicy = SameSiteMode.Unspecified;
				options.OnAppendCookie = cookieContext =>
					CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
				options.OnDeleteCookie = cookieContext =>
					CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
			});

			// Memory cache
			services.AddMemoryCache();

			// Add framework services
			services
				.AddMvc()
				.AddNewtonsoftJson(options => options.SerializerSettings.ContractResolver = new DefaultContractResolver());

			// Add HttpContext accessor
			services.AddHttpContextAccessor();

			// Adds a default in-memory implementation of IDistributedCache.
			services.AddDistributedMemoryCache();

			// Session
			services.AddSession(options => {
				options.Cookie.Name = ".SMARTBANK.Session";
				options.Cookie.IsEssential = true;
				options.IdleTimeout = TimeSpan.FromMinutes(Config.SessionTimeout);
			});
			services.AddAuthentication()
			;

			// JWT
			var tokenValidationParameters = new TokenValidationParameters
			{

				// Token signature will be verified using a private key.
				ValidateIssuerSigningKey = true,
				IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Jwt:SecretKey"])),

				// Token will only be valid if contains below domain (e.g http://localhost) for "iss" claim.
				ValidateIssuer = true,
				ValidIssuer = Configuration["Jwt:Issuer"],

				// Token will only be valid if contains below domain (e.g http://localhost) for "aud" claim.
				ValidateAudience = true,
				ValidAudience = Configuration["Jwt:Audience"],

				// Token will only be valid if not expired yet, with 5 minutes clock skew.
				ValidateLifetime = true
			};

			// Authentication
			services.AddAuthentication(options => {
				options.DefaultAuthenticateScheme = "default";
			})
			.AddPolicyScheme("default", "Authorization Bearer or Cookies", options => {
				options.ForwardDefaultSelector = context =>
				{
					if (IsApi())
						return JwtBearerDefaults.AuthenticationScheme;
					return CookieAuthenticationDefaults.AuthenticationScheme;
				};
			})
			.AddCookie(options => {
				options.ExpireTimeSpan = TimeSpan.FromMinutes(Config.SessionTimeout);
			})
			.AddJwtBearer(options => {
				options.TokenValidationParameters = tokenValidationParameters;
			});

			// HTTP context accessor
			services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

			// Configure supported cultures and localization options
			var ci = Configuration["Culture"];
			services.Configure<RequestLocalizationOptions>(options =>
			{

				// State what the default culture for your application is. This will be used if no specific culture
				// can be determined for a given request.

				options.DefaultRequestCulture = new RequestCulture(culture: ci, uiCulture: ci);

				// You must explicitly state which cultures your application supports.
				// These are the cultures the app supports for formatting numbers, dates, etc.

				options.SupportedCultures = new[]
				{
					new CultureInfo(ci)
				};
			});

			// CORS
			services.AddCors(options =>
			{
			});
		}

		// Check SameSite
		private void CheckSameSite(HttpContext httpContext, CookieOptions options)
		{
			if (options.SameSite == SameSiteMode.None && GetMobileDetect().DisallowSameSiteNone())
				options.SameSite = SameSiteMode.Unspecified;
		}

		// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
		public void Configure(IApplicationBuilder app, IWebHostEnvironment env, IAntiforgery antiforgery, IHttpContextAccessor httpContextAccessor)
		{
			var locOptions = app.ApplicationServices.GetService<IOptions<RequestLocalizationOptions>>();
			app.UseRequestLocalization(locOptions.Value);
			if (env.IsDevelopment())
			{
				app.UseDeveloperExceptionPage();
			}
			else
			{
				app.UseExceptionHandler("/Home/Error");
			}
			app.UseStaticFiles(FileOptions);
			app.UseRouting();
			app.UseCookiePolicy();
			SMARTBANK.Configure(httpContextAccessor, env, Configuration, antiforgery);
			app.UseSession(); // IMPORTANT: MUST be before UseMvc()
			app.UseCors("CorsPolicy");
			app.UseEndpoints(endpoints =>
			{
				endpoints.MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}");
			});
		}
	}
}