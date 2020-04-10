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

// Controllers
namespace SMART.Controllers
{

	// Partial class
	[AutoValidateAntiforgeryToken]

	public partial class HomeController : Controller
	{

		private IMemoryCache _cache;

		// Constructor
		public HomeController(ILogger<HomeController> logger, IMemoryCache memoryCache)
		{
			_cache = memoryCache;
			Logger = logger;
			UseSession = true;
		}

		// menu
		[Route("ewmenu")]
		[Route("Home/ewmenu")]

		public IActionResult ewmenu() => View();

		// ewemail
		[Route("ewemail")]
		[Route("Home/ewemail")]

		public IActionResult ewemail() => View();

		// index
		[Route("")]
		[Route("Index")]
		[Route("Home/Index")]

		public async Task<IActionResult> Index()
		{

			// Create page object
			_index = new __index(this);

			// Run the page
			return await _index.Run();
		}

		// error
		[Route("Error")]
		[Route("Home/Error")]

		public async Task<IActionResult> Error()
		{

			// Create page object
			_error = new __error(this);

			// Run the page
			return await _error.Run();
		}

		// Dispose
		protected override void Dispose(bool disposing) {
			try {
				base.Dispose(disposing);
			} finally {
				CurrentPage?.Terminate();
			}
		}
	}
}