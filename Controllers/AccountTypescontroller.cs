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
		[Route("AccountTypeslist/{AccountTypeID?}")]
		[Route("Home/AccountTypeslist/{AccountTypeID?}")]

		public async Task<IActionResult> AccountTypeslist()
		{

			// Create page object
			AccountTypes_List = new _AccountTypes_List(this);
			AccountTypes_List.Cache = _cache;

			// Run the page
			return await AccountTypes_List.Run();
		}

		// add
		[Route("AccountTypesadd/{AccountTypeID?}")]
		[Route("Home/AccountTypesadd/{AccountTypeID?}")]

		public async Task<IActionResult> AccountTypesadd()
		{

			// Create page object
			AccountTypes_Add = new _AccountTypes_Add(this);

			// Run the page
			return await AccountTypes_Add.Run();
		}

		// view
		[Route("AccountTypesview/{AccountTypeID?}")]
		[Route("Home/AccountTypesview/{AccountTypeID?}")]

		public async Task<IActionResult> AccountTypesview()
		{

			// Create page object
			AccountTypes_View = new _AccountTypes_View(this);

			// Run the page
			return await AccountTypes_View.Run();
		}

		// edit
		[Route("AccountTypesedit/{AccountTypeID?}")]
		[Route("Home/AccountTypesedit/{AccountTypeID?}")]

		public async Task<IActionResult> AccountTypesedit()
		{

			// Create page object
			AccountTypes_Edit = new _AccountTypes_Edit(this);

			// Run the page
			return await AccountTypes_Edit.Run();
		}

		// delete
		[Route("AccountTypesdelete/{AccountTypeID?}")]
		[Route("Home/AccountTypesdelete/{AccountTypeID?}")]

		public async Task<IActionResult> AccountTypesdelete()
		{

			// Create page object
			AccountTypes_Delete = new _AccountTypes_Delete(this);

			// Run the page
			return await AccountTypes_Delete.Run();
		}
	}
}