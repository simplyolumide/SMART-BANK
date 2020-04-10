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
	public partial class HomeController : Controller
	{

		// list
		[Route("Accountslist/{AccountID?}")]
		[Route("Home/Accountslist/{AccountID?}")]

		public async Task<IActionResult> Accountslist()
		{

			// Create page object
			Accounts_List = new _Accounts_List(this);
			Accounts_List.Cache = _cache;

			// Run the page
			return await Accounts_List.Run();
		}

		// add
		[Route("Accountsadd/{AccountID?}")]
		[Route("Home/Accountsadd/{AccountID?}")]

		public async Task<IActionResult> Accountsadd()
		{

			// Create page object
			Accounts_Add = new _Accounts_Add(this);

			// Run the page
			return await Accounts_Add.Run();
		}

		// view
		[Route("Accountsview/{AccountID?}")]
		[Route("Home/Accountsview/{AccountID?}")]

		public async Task<IActionResult> Accountsview()
		{

			// Create page object
			Accounts_View = new _Accounts_View(this);

			// Run the page
			return await Accounts_View.Run();
		}

		// edit
		[Route("Accountsedit/{AccountID?}")]
		[Route("Home/Accountsedit/{AccountID?}")]

		public async Task<IActionResult> Accountsedit()
		{

			// Create page object
			Accounts_Edit = new _Accounts_Edit(this);

			// Run the page
			return await Accounts_Edit.Run();
		}

		// delete
		[Route("Accountsdelete/{AccountID?}")]
		[Route("Home/Accountsdelete/{AccountID?}")]

		public async Task<IActionResult> Accountsdelete()
		{

			// Create page object
			Accounts_Delete = new _Accounts_Delete(this);

			// Run the page
			return await Accounts_Delete.Run();
		}
	}
}