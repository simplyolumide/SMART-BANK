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
		[Route("Transactionslist/{TransactionID?}")]
		[Route("Home/Transactionslist/{TransactionID?}")]

		public async Task<IActionResult> Transactionslist()
		{

			// Create page object
			Transactions_List = new _Transactions_List(this);
			Transactions_List.Cache = _cache;

			// Run the page
			return await Transactions_List.Run();
		}

		// add
		[Route("Transactionsadd/{TransactionID?}")]
		[Route("Home/Transactionsadd/{TransactionID?}")]

		public async Task<IActionResult> Transactionsadd()
		{

			// Create page object
			Transactions_Add = new _Transactions_Add(this);

			// Run the page
			return await Transactions_Add.Run();
		}

		// view
		[Route("Transactionsview/{TransactionID?}")]
		[Route("Home/Transactionsview/{TransactionID?}")]

		public async Task<IActionResult> Transactionsview()
		{

			// Create page object
			Transactions_View = new _Transactions_View(this);

			// Run the page
			return await Transactions_View.Run();
		}

		// edit
		[Route("Transactionsedit/{TransactionID?}")]
		[Route("Home/Transactionsedit/{TransactionID?}")]

		public async Task<IActionResult> Transactionsedit()
		{

			// Create page object
			Transactions_Edit = new _Transactions_Edit(this);

			// Run the page
			return await Transactions_Edit.Run();
		}

		// delete
		[Route("Transactionsdelete/{TransactionID?}")]
		[Route("Home/Transactionsdelete/{TransactionID?}")]

		public async Task<IActionResult> Transactionsdelete()
		{

			// Create page object
			Transactions_Delete = new _Transactions_Delete(this);

			// Run the page
			return await Transactions_Delete.Run();
		}
	}
}