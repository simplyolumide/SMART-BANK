// ASP.NET Maker 2020
// Copyright (c) 2019 e.World Technology Limited. All rights reserved.

using System;
using System.ComponentModel.DataAnnotations;
using System.Reflection;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using SMART.Models;
using static SMART.Models.SMARTBANK;

// API Controllers
namespace SMART.Controllers
{
	[ApiController]
	[Route("api/[controller]/")]

	public abstract class ApiController : Controller
	{

		public static Lang Language = Language ?? new Lang();

		// Constructor
		public ApiController() => UseSession = !Empty(Param(Config.TokenName));
	}

	/// <summary>
	/// List records from a table
	/// </summary>
	/// <example>
	/// api/list/cars
	/// </example>
	public class ListController : ApiController
	{
		[HttpGet("{table}")]

		public async Task<IActionResult> List([FromRoute] string table)
		{
			if (Config.TableClassNames.TryGetValue(table, out string className)) {
				var obj = CreateInstance(className + "_List", new object[] { this });
				return await obj.Run();
			} else {
				return new JsonBoolResult(new { success = false, error = Language.Phrase("TableNotFound"), version = Config.ProductVersion }, false);
			}
		}
	}

	/// <summary>
	/// Get a record from a table
	/// </summary>
	/// <example>
	/// api/view/cars/1
	/// </example>
	public class ViewController : ApiController
	{
		[HttpGet("{table}/{*key}")]

		public async Task<IActionResult> Get([FromRoute] string table)
		{
			if (Config.TableClassNames.TryGetValue(table, out string className)) {
				var obj = CreateInstance(className + "_View", new object[] { this });
				return await obj.Run();
			} else {
				return new JsonBoolResult(new { success = false, error = Language.Phrase("TableNotFound"), version = Config.ProductVersion }, false);
			}
		}
	}

	/// <summary>
	/// Insert a record to a table by POST
	/// </summary>
	/// <example>
	/// api/add
	/// </example>
	public class AddController : ApiController
	{

		// Post
		[HttpPost]

		public async Task<IActionResult> Post([FromForm] string table) => await Add(table);

		// Post with route
		[HttpPost("{table}")]

		public async Task<IActionResult> PostWithRoute([FromRoute] string table) => await Add(table);

		// Add
		protected async Task<IActionResult> Add(string table)
		{
			if (Config.TableClassNames.TryGetValue(table, out string className)) {
				var obj = CreateInstance(className + "_Add", new object[] { this });
				return await obj.Run();
			} else {
				return new JsonBoolResult(new { success = false, error = Language.Phrase("TableNotFound"), version = Config.ProductVersion }, false);
			}
		}
	}

	/// <summary>
	/// Edit a record by POST
	/// </summary>
	/// <example>
	/// api/edit/cars/1
	/// </example>
	public class EditController : ApiController
	{
		[HttpPost("{table}/{*key}")]

		public async Task<IActionResult> Edit([FromRoute] string table)
		{
			if (Config.TableClassNames.TryGetValue(table, out string className)) {
				var obj = CreateInstance(className + "_Edit", new object[] { this });
				return await obj.Run();
			} else {
				return new JsonBoolResult(new { success = false, error = Language.Phrase("TableNotFound"), version = Config.ProductVersion }, false);
			}
		}
	}

	/// <summary>
	/// Delete a record from a table
	/// </summary>
	/// <example>
	/// api/delete/cars/1
	/// </example>
	public class DeleteController : ApiController
	{
		[HttpPost("{table}/{*key}")]

		public async Task<IActionResult> Delete([FromRoute] string table)
		{
			if (Config.TableClassNames.TryGetValue(table, out string className)) {
				var obj = CreateInstance(className + "_Delete", new object[] { this });
				return await obj.Run();
			} else {
				return new JsonBoolResult(new { success = false, error = Language.Phrase("TableNotFound"), version = Config.ProductVersion }, false);
			}
		}
	}

	/// <summary>
	/// Login by POST
	/// </summary>
	/// <example>
	/// api/login
	/// </example>
	public class LoginController : ApiController
	{
		[AllowAnonymous]
		[HttpPost]

		public async Task<IActionResult> Post([FromForm] LoginModel model)
		{

			// User profile
			Profile = new UserProfile();

			// Security
			Security = new AdvancedSecurity();

			// As an example, AuthService.CreateToken can return Jose.JWT.Encode(claims, YourTokenSecretKey, Jose.JwsAlgorithm.HS256);
			if (await Security.ValidateUser(model, false))
				return Ok(new { JWT = Security.JwtToken });
			return BadRequest("Invalid username or password!");
		}
	}

	/// <summary>
	/// Get a file
	/// </summary>
	/// <example>
	/// api/file/cars/Picture/1
	/// </example>

	[AllowAnonymous]

	public class FileController : ApiController
	{
		[HttpGet("{table}/{field}/{*key}")]

		public async Task<IActionResult> GetFile([FromRoute] string table, [FromRoute] string field, [FromRoute] string key)
		{
			var obj = new FileViewer(this);
			return await obj.GetFile(table, field, key);
		}
		[HttpGet("{fn}")]

		public async Task<IActionResult> GetFile([FromRoute] string fn)
		{
			var obj = new FileViewer(this);
			return await obj.GetFile(fn);
		}
	}

	/// <summary>
	/// File upload
	/// </summary>
	/// <example>
	/// api/upload
	/// </example>
	public class UploadController : ApiController
	{
		[HttpPost]
		[HttpPut]

		public async Task<IActionResult> Post()
		{
			var obj = new HttpUpload();
			return await obj.GetUploadedFiles();
		}
	}

	/// <summary>
	/// File upload with jQuery File Upload
	/// </summary>
	/// <example>
	/// api/jupload
	/// </example>
	public class JUploadController : ApiController
	{
		[HttpPost]
		[HttpPut]
		[HttpGet]

		public async Task<IActionResult> Post()
		{
			var obj = new UploadHandler(this);
			return await obj.Run();
		}
	}

	/// <summary>
	/// Session handler
	/// </summary>
	/// <example>
	/// api/session
	/// </example>

	[AllowAnonymous]

	public class SessionController : ApiController
	{
		[HttpGet]

		public IActionResult Get()
		{
			var obj = new SessionHandler(this);
			return obj.GetSession();
		}
	}

	/// <summary>
	/// Lookup (UpdateOption/ModalLookup/AutoSuggest/AutoFill)
	/// </summary>
	/// <example>
	/// api/lookup
	/// </example>

	[AllowAnonymous]

	public class LookupController : ApiController
	{
		[HttpPost]

		public async Task<IActionResult> Post([FromForm] string page)
		{
			string className = "_" + page;
			Type t = Type.GetType(Config.ProjectClassName + "+" + className) ?? // This class
				Type.GetType(Config.ProjectClassName + "Base+" + className); // Base class
			if (t != null) {
				MethodInfo m = t.GetMethod("Lookup");
				if (m != null) {
					var obj = CreateInstance(className, new object[] { this });
					return await obj.Lookup();
				}
			}
			return new JsonBoolResult(new { success = false, error = Language.Phrase("TableNotFound"), version = Config.ProductVersion }, false);
		}
	}

	/// <summary>
	/// Import progress
	/// </summary>
	/// <example>
	/// api/progress/{token}
	/// </example>
	public class ProgressController : ApiController
	{

		private IMemoryCache _cache;

		public ProgressController(IMemoryCache memoryCache)
		{
			_cache = memoryCache;
		}

		public IActionResult Get([FromQuery] string filetoken)
		{
			if (!Empty(filetoken) && _cache.TryGetValue<string>(filetoken, out string value))
				return Content(value, "application/json");
			return new EmptyResult();
		}
	}

	/// <summary>
	/// Chart exporter
	/// </summary>
	/// <example>
	/// api/chart
	/// </example>
	public class ChartController : ApiController
	{
		[HttpPost]

		public async Task<IActionResult> Post()
		{
			var exporter = new ChartExporter(this);
			return await exporter.Export();
		}
	}
}