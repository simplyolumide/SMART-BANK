// ASP.NET Maker 2020
// Copyright (c) 2019 e.World Technology Limited. All rights reserved.

using MailKit.Net.Smtp;
using Microsoft.Data.SqlClient;
using MimeKit;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.ComponentModel.DataAnnotations;
using System.Data;
using System.Data.Common;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Dynamic;
using System.Globalization;
using System.IO;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Mime;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.NewtonsoftJson;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using Dapper;
using Ganss.XSS;
using ImageMagick;
using MimeDetective.InMemory;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;
using static SMART.Models.SMARTBANK;
using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.html;
using iTextSharp.text.html.simpleparser;

// Models
namespace SMART.Models {

	// Partial class
	public partial class SMARTBANK {

		/// <summary>
		/// Transactions_Edit
		/// </summary>
		public static _Transactions_Edit Transactions_Edit {
			get => HttpData.Get<_Transactions_Edit>("Transactions_Edit");
			set => HttpData["Transactions_Edit"] = value;
		}

		/// <summary>
		/// Page class for Transactions
		/// </summary>
		public class _Transactions_Edit : _Transactions_EditBase
		{

			// Construtor
			public _Transactions_Edit(Controller controller = null) : base(controller) {
			}
		}

		/// <summary>
		/// Page base class
		/// </summary>
		public class _Transactions_EditBase : _Transactions, IAspNetMakerPage
		{

			// Page ID
			public string PageID = "edit";

			// Project ID
			public string ProjectID = "{31239A93-3DBA-4D73-A306-C1D3BFE7959E}";

			// Table name
			public string TableName { get; set; } = "Transactions";

			// Page object name
			public string PageObjName = "Transactions_Edit";

			// Page headings
			public string Heading = "";

			public string Subheading = "";

			public string PageHeader = "";

			public string PageFooter = "";

			// Token
			public string Token = null; // DN

			public bool CheckToken = Config.CheckToken;

			// Action result // DN
			public IActionResult ActionResult;

			// Cache // DN
			public IMemoryCache Cache;

			// Page terminated // DN
			private bool _terminated = false;

			// Page URL
			private string _pageUrl = "";

			// Page action result
			public IActionResult PageResult() {
				if (ActionResult != null)
					return ActionResult;
				SetupMenus();
				return Controller.View();
			}

			// Page heading
			public string PageHeading {
				get {
					if (!Empty(Heading))
						return Heading;
					else if (!Empty(Caption))
						return Caption;
					else
						return "";
				}
			}

			// Page subheading
			public string PageSubheading {
				get {
					if (!Empty(Subheading))
						return Subheading;
					if (!Empty(TableName))
						return Language.Phrase(PageID);
					return "";
				}
			}

			// Page name
			public string PageName => CurrentPageName();

			// Page URL
			public string PageUrl {
				get {
					if (_pageUrl == "") {
						_pageUrl = CurrentPageName() + "?";
					}
					return _pageUrl;
				}
			}

			// Private properties
			private string _message = "";

			private string _failureMessage = "";

			private string _successMessage = "";

			private string _warningMessage = "";

			// Message
			public string Message {
				get => Session.TryGetValue(Config.SessionMessage, out string message) ? message : _message;
				set {
					_message = AddMessage(Message, value);
					Session[Config.SessionMessage] = _message;
				}
			}

			// Failure Message
			public string FailureMessage {
				get => Session.TryGetValue(Config.SessionFailureMessage, out string failureMessage) ? failureMessage : _failureMessage;
				set {
					_failureMessage = AddMessage(FailureMessage, value);
					Session[Config.SessionFailureMessage] = _failureMessage;
				}
			}

			// Success Message
			public string SuccessMessage {
				get => Session.TryGetValue(Config.SessionSuccessMessage, out string successMessage) ? successMessage : _successMessage;
				set {
					_successMessage = AddMessage(SuccessMessage, value);
					Session[Config.SessionSuccessMessage] = _successMessage;
				}
			}

			// Warning Message
			public string WarningMessage {
				get => Session.TryGetValue(Config.SessionWarningMessage, out string warningMessage) ? warningMessage : _warningMessage;
				set {
					_warningMessage = AddMessage(WarningMessage, value);
					Session[Config.SessionWarningMessage] = _warningMessage;
				}
			}

			// Clear message
			public void ClearMessage() {
				_message = "";
				Session[Config.SessionMessage] = _message;
			}

			// Clear failure message
			public void ClearFailureMessage() {
				_failureMessage = "";
				Session[Config.SessionFailureMessage] = _failureMessage;
			}

			// Clear success message
			public void ClearSuccessMessage() {
				_successMessage = "";
				Session[Config.SessionSuccessMessage] = _successMessage;
			}

			// Clear warning message
			public void ClearWarningMessage() {
				_warningMessage = "";
				Session[Config.SessionWarningMessage] = _warningMessage;
			}

			// Clear all messages
			public void ClearMessages() {
				ClearMessage();
				ClearFailureMessage();
				ClearSuccessMessage();
				ClearWarningMessage();
			}

			// Get message
			public string GetMessage() { // DN
				bool hidden = true;
				string html = "";

				// Message
				string message = Message;
				Message_Showing(ref message, "");
				if (!Empty(message)) { // Message in Session, display
					if (!hidden)
						message = "<button type=\"button\" class=\"close\" data-dismiss=\"alert\" aria-label=\"Close\"><span aria-hidden=\"true\">&times;</span></button>" + message;
					html += "<div class=\"alert alert-info alert-dismissible ew-info\"><i class=\"icon fas fa-info\"></i>" + message + "</div>";
					Session[Config.SessionMessage] = ""; // Clear message in Session
				}

				// Warning message
				string warningMessage = WarningMessage;
				Message_Showing(ref warningMessage, "warning");
				if (!Empty(warningMessage)) { // Message in Session, display
					if (!hidden)
						warningMessage = "<button type=\"button\" class=\"close\" data-dismiss=\"alert\" aria-label=\"Close\"><span aria-hidden=\"true\">&times;</span></button>" + warningMessage;
					html += "<div class=\"alert alert-warning alert-dismissible ew-warning\"><i class=\"icon fas fa-exclamation\"></i>" + warningMessage + "</div>";
					Session[Config.SessionWarningMessage] = ""; // Clear message in Session
				}

				// Success message
				string successMessage = SuccessMessage;
				Message_Showing(ref successMessage, "success");
				if (!Empty(successMessage)) { // Message in Session, display
					if (!hidden)
						successMessage = "<button type=\"button\" class=\"close\" data-dismiss=\"alert\" aria-label=\"Close\"><span aria-hidden=\"true\">&times;</span></button>" + successMessage;
					html += "<div class=\"alert alert-success alert-dismissible ew-success\"><i class=\"icon fas fa-check\"></i>" + successMessage + "</div>";
					Session[Config.SessionSuccessMessage] = ""; // Clear message in Session
				}

				// Failure message
				string errorMessage = FailureMessage;
				Message_Showing(ref errorMessage, "failure");
				if (!Empty(errorMessage)) { // Message in Session, display
					if (!hidden)
						errorMessage = "<button type=\"button\" class=\"close\" data-dismiss=\"alert\" aria-label=\"Close\"><span aria-hidden=\"true\">&times;</span></button>" + errorMessage;
					html += "<div class=\"alert alert-danger alert-dismissible ew-error\"><i class=\"icon fas fa-ban\"></i>" + errorMessage + "</div>";
					Session[Config.SessionFailureMessage] = ""; // Clear message in Session
				}
				return "<div class=\"ew-message-dialog" + (hidden ? " d-none" : "") + "\">" + html + "</div>"; // DN
			}

			// Show message as IHtmlContent // DN
			public IHtmlContent ShowMessages() => new HtmlString(GetMessage());

			// Get messages
			public Dictionary<string, string> GetMessages() {
				var d = new Dictionary<string, string>();

				// Message
				string message = Message;
				if (!Empty(message)) { // Message in Session, display
					d.Add("message", message);
					Session[Config.SessionMessage] = ""; // Clear message in Session
				}

				// Warning message
				string warningMessage = WarningMessage;
				if (!Empty(warningMessage)) { // Message in Session, display
					d.Add("warningMessage", warningMessage);
					Session[Config.SessionWarningMessage] = ""; // Clear message in Session
				}

				// Success message
				string successMessage = SuccessMessage;
				if (!Empty(successMessage)) { // Message in Session, display
					d.Add("successMessage", successMessage);
					Session[Config.SessionSuccessMessage] = ""; // Clear message in Session
				}

				// Failure message
				string failureMessage = FailureMessage;
				if (!Empty(failureMessage)) { // Message in Session, display
					d.Add("failureMessage", failureMessage);
					Session[Config.SessionFailureMessage] = ""; // Clear message in Session
				}
				return d;
			}

			// Show Page Header
			public IHtmlContent ShowPageHeader() {
				string header = PageHeader;
				Page_DataRendering(ref header);
				if (!Empty(header)) // Header exists, display
					return new HtmlString("<p id=\"ew-page-header\">" + header + "</p>");
				return null;
			}

			// Show Page Footer
			public IHtmlContent ShowPageFooter() {
				string footer = PageFooter;
				Page_DataRendered(ref footer);
				if (!Empty(footer)) // Footer exists, display
					return new HtmlString("<p id=\"ew-page-footer\">" + footer + "</p>");
				return null;
			}

			// Validate page request
			public bool IsPageRequest => true;

			// Valid post
			protected async Task<bool> ValidPost() => !CheckToken || !IsPost() || IsApi() || await Antiforgery.IsRequestValidAsync(HttpContext);

			// Create token
			public void CreateToken() {
				Token ??= Antiforgery.GetAndStoreTokens(HttpContext).RequestToken;
				CurrentToken = Token; // Save to global variable
			}

			// Constructor
			public _Transactions_EditBase(Controller controller = null) { // DN
				if (controller != null)
					Controller = controller;

				// Initialize
				CurrentPage = this;

				// Language object
				Language ??= new Lang();

				// Table object (Transactions)
				if (Transactions == null || Transactions is _Transactions)
					Transactions = this;

				// Start time
				StartTime = Environment.TickCount;

				// Debug message
				LoadDebugMessage();

				// Open connection
				Conn = Connection; // DN
			}
			#pragma warning disable 1998

			// Export view result
			public async Task<IActionResult> ExportView() { // DN
				if (!Empty(CustomExport) && CustomExport == Export && Config.Export.TryGetValue(CustomExport, out string classname)) {
					IActionResult result = null;
					string content = await GetViewOutput();
					if (Empty(ExportFileName))
						ExportFileName = TableVar;
					dynamic doc = CreateInstance(classname, new object[] { Transactions, "" }); // DN
					doc.Text.Append(content);
					result = doc.Export();
					DeleteTempImages(); // Delete temp images
					return result;
				}
				return null;
			}
			#pragma warning restore 1998

			/// <summary>
			/// Terminate page
			/// </summary>
			/// <param name="url">URL to rediect to</param>
			/// <returns>Page result</returns>
			public IActionResult Terminate(string url = "") { // DN
				if (_terminated) // DN
					return null;

				// Page Unload event
				Page_Unload();

				// Global Page Unloaded event
				Page_Unloaded();
				if (!IsApi())
					Page_Redirecting(ref url);

				// Close connection
				CloseConnections();

				// Gargage collection
				Collect(); // DN

				// Terminate
				_terminated = true; // DN

				// Return for API
				if (IsApi()) {
					bool res = !Empty(url);
					if (!res) { // Show error
						var showError = new Dictionary<string, string> { { "success", "false" }, { "version", Config.ProductVersion } };
						foreach (var (key, value) in GetMessages())
							showError.Add(key, value);
						return Controller.Json(showError);
					}
				} else if (ActionResult != null) { // Check action result
					return ActionResult;
				}

				// Go to URL if specified
				if (!Empty(url)) {
					if (!Config.Debug)
						ResponseClear();
					if (!Response.HasStarted) {

						// Handle modal response
						if (IsModal) { // Show as modal
							var row = new Dictionary<string, string> { {"url", GetUrl(url)}, {"modal", "1"} };
							string pageName = GetPageName(url);
							if (pageName != ListUrl) { // Not List page
								row.Add("caption", GetModalCaption(pageName));
								if (pageName == "Transactionsview")
									row.Add("view", "1");
							} else { // List page should not be shown as modal => error
								row.Add("error", FailureMessage);
								ClearFailureMessage();
							}
							return Controller.Json(row);
						} else {
							SaveDebugMessage();
							return Controller.LocalRedirect(AppPath(url));
						}
					}
				}
				return null;
			}

			// Get all records from datareader
			protected async Task<List<Dictionary<string, object>>> GetRecordsFromRecordset(DbDataReader rs)
			{
				var rows = new List<Dictionary<string, object>>();
				while (rs != null && await rs.ReadAsync()) {
					await LoadRowValues(rs); // Set up DbValue/CurrentValue
					rows.Add(GetRecordFromDictionary(GetDictionary(rs)));
				}
				return rows;
			}

			// Get the first record from datareader
			protected async Task<Dictionary<string, object>> GetRecordFromRecordset(DbDataReader rs)
			{
				if (rs != null) {
					await LoadRowValues(rs); // Set up DbValue/CurrentValue
					return GetRecordFromDictionary(GetDictionary(rs));
				}
				return null;
			}

			// Get the first record from the list of records
			protected Dictionary<string, object> GetRecordFromRecordset(List<Dictionary<string, object>> ar) => GetRecordFromDictionary(ar[0]);

			// Get record from Dictionary
			protected Dictionary<string, object> GetRecordFromDictionary(Dictionary<string, object> ar) {
				var row = new Dictionary<string, object>();
				foreach (var (key, value) in ar) {
					if (Fields.TryGetValue(key, out DbField fld)) {
						if (fld.Visible || fld.IsPrimaryKey) { // Primary key or Visible
							if (fld.HtmlTag == "FILE") { // Upload field
								if (Empty(value)) {
									row[key] = null;
								} else {
									if (fld.DataType == Config.DataTypeBlob) {
										string url = FullUrl(GetPageName(Config.ApiUrl) + "/" + Config.ApiFileAction + "/" + fld.TableVar + "/" + fld.Param + "/" + GetRecordKeyValue(ar)); // Query string format
										row[key] = new Dictionary<string, object> { { "mimeType", ContentType((byte[])value) }, { "url", url } };
									} else if (!fld.UploadMultiple || !Convert.ToString(value).Contains(Config.MultipleUploadSeparator)) { // Single file
										row[key] = new Dictionary<string, object> { { "mimeType", ContentType(Convert.ToString(value)) }, { "url", FullUrl(fld.HrefPath + Convert.ToString(value)) } };
									} else { // Multiple files
										var files = Convert.ToString(value).Split(Config.MultipleUploadSeparator);
										row[key] = files.Where(file => !Empty(file)).Select(file => new Dictionary<string, object> { { "type", ContentType(file) }, { "url", FullUrl(fld.HrefPath + file) } });
									}
								}
							} else {
								row[key] = Convert.ToString(value);
							}
						}
					}
				}
				return row;
			}

			// Get record key value from array
			protected string GetRecordKeyValue(Dictionary<string, object> ar) {
				string key = "";
				key += UrlEncode(Convert.ToString(ar["TransactionID"]));
				return key;
			}

			// Hide fields for Add/Edit
			protected void HideFieldsForAddEdit() {
				if (IsAdd || IsCopy || IsGridAdd)
					TransactionID.Visible = false;
			}
			#pragma warning disable 219

			/// <summary>
			/// Lookup data from table
			/// </summary>
			public async Task<JsonBoolResult> Lookup() {
				Language ??= new Lang(Config.LanguageFolder, Post("language"));

				// Set up API request
				if (!await SetupApiRequest())
					return JsonBoolResult.FalseResult;

				// Get lookup object
				string fieldName = Post("field");
				DbField lookupField = FieldByName(fieldName);
				if (lookupField == null)
					return JsonBoolResult.FalseResult;
				Lookup<DbField> lookup = lookupField.Lookup;
				if (lookup == null)
					return JsonBoolResult.FalseResult;
				string lookupType = Post("ajax");
				int pageSize = -1;
				int offset = -1;
				string searchValue = "";
				if (SameText(lookupType, "modal")) {
					searchValue = Post("sv");
					if (!Post("recperpage", out StringValues rpp))
						pageSize = 10;
					else
						pageSize = ConvertToInt(rpp.ToString());
					offset = Post<int>("start");
				} else if (SameText(lookupType, "autosuggest")) {
					searchValue = Get("q");
					pageSize = IsNumeric(Param("n")) ? Param<int>("n") : -1;
					if (pageSize <= 0)
						pageSize = Config.AutoSuggestMaxEntries;
					int start = IsNumeric(Param("start")) ? Param<int>("start") : -1;
					int page = IsNumeric(Param("page")) ? Param<int>("page") : -1;
					offset = start >= 0 ? start : (page > 0 && pageSize > 0 ? (page - 1) * pageSize : 0);
				}
				string userSelect = Decrypt(Post("s"));
				string userFilter = Decrypt(Post("f"));
				string userOrderBy = Decrypt(Post("o"));

				// Selected records from modal, skip parent/filter fields and show all records
				lookup.LookupType = lookupType; // Lookup type
				if (Post("keys[]", out StringValues keys)) { // Selected records from modal
					lookup.FilterFields = new Dictionary<string, string>(); // Skip parent fields if any
					pageSize = -1; // Show all records
					lookup.FilterValues.Add(string.Join(",", keys));
				} else { // Lookup values
					lookup.FilterValues.Add(Post<string>("v0") ?? Post("lookupValue"));
				}
				int cnt = IsDictionary(lookup.FilterFields) ? lookup.FilterFields.Count : 0;
				for (int i = 1; i <= cnt; i++)
					lookup.FilterValues.Add(UrlDecode(Post("v" + i)));
				lookup.SearchValue = searchValue;
				lookup.PageSize = pageSize;
				lookup.Offset = offset;
				if (userSelect != "")
					lookup.UserSelect = userSelect;
				if (userFilter != "")
					lookup.UserFilter = userFilter;
				if (userOrderBy != "")
					lookup.UserOrderBy = userOrderBy;
				return await lookup.ToJson(this);
			}
			#pragma warning restore 219
			#pragma warning disable 1998

			/// <summary>
			/// Set up API request
			/// </summary>
			public async Task<bool> SetupApiRequest()
			{

				// Check security for API request
				if (ValidApiRequest()) {
					return true;
				}
				return false;
			}
			#pragma warning restore 1998

			private Pager _pager; // DN

			public int DisplayRecords = 1; // Number of display records

			public int StartRecord;

			public int StopRecord;

			public int TotalRecords = -1;

			public int RecordRange = 10;

			public int RecordCount;

			public Dictionary<string, string> RecordKeys = new Dictionary<string, string>();

			public string FormClassName = "ew-horizontal ew-form ew-edit-form";

			public bool IsModal = false;

			public bool IsMobileOrModal = false;

			public string DbMasterFilter = "";

			public string DbDetailFilter = "";

			public DbDataReader Recordset; // DN

			public DbDataReader OldRecordset;

			public Pager Pager {
				get {
					_pager ??= new PrevNextPager(StartRecord, DisplayRecords, TotalRecords, "", RecordRange, AutoHidePager);
					return _pager;
				}
			}
			#pragma warning disable 219

			/// <summary>
			/// Page run
			/// </summary>
			/// <returns>Page result</returns>
			public async Task<IActionResult> Run() {

				// Header
				Header(Config.Cache);

				// Is modal
				IsModal = Param<bool>("modal");

				// User profile
				Profile = new UserProfile();

				// Security
				if (!await SetupApiRequest()) {
					Security ??= CreateSecurity(); // DN
				}

				// Create form object
				CurrentForm = new HttpForm();
				CurrentAction = Param("action"); // Set up current action
				TransactionID.SetVisibility();
				TransactionDate.SetVisibility();
				AccountID.SetVisibility();
				Description.SetVisibility();
				Debit.SetVisibility();
				Credit.SetVisibility();
				HideFieldsForAddEdit();

				// Do not use lookup cache
				SetUseLookupCache(false);

				// Global Page Loading event
				Page_Loading();

				// Page Load event
				Page_Load();

				// Check token
				if (!await ValidPost())
					End(Language.Phrase("InvalidPostRequest"));

				// Check action result
				if (ActionResult != null) // Action result set by server event // DN
					return ActionResult;

				// Create token
				CreateToken();

				// Set up lookup cache
				await SetupLookupOptions(AccountID);

				// Check modal
				if (IsModal)
					SkipHeaderFooter = true;
				IsMobileOrModal = IsMobile() || IsModal;
				FormClassName = "ew-form ew-edit-form ew-horizontal";

				// Load record by position
				bool loadByPosition = false;
				bool loaded = false;
				bool postBack = false;
				StringValues sv;

				// Set up current action and primary key
				if (IsApi()) {
					CurrentAction = "update"; // Update record directly
					postBack = true;
				} else if (Post("action", out sv)) {
					CurrentAction = sv; // Get action code
					if (!IsShow) // Not reload record, handle as postback
						postBack = true;

					// Load key from form
					string[] keyValues = null;
					object rv;
					if (IsApi() && RouteValues.TryGetValue("key", out object k))
						keyValues = k.ToString().Split('/');
					if (RouteValues.TryGetValue("TransactionID", out rv)) { // DN
						TransactionID.FormValue = Convert.ToString(rv);
						RecordKeys["TransactionID"] = TransactionID.FormValue;
					} else if (CurrentForm.HasValue("x_TransactionID")) {
						TransactionID.FormValue = CurrentForm.GetValue("x_TransactionID");
						RecordKeys["TransactionID"] = TransactionID.FormValue;
					} else if (IsApi() && !Empty(keyValues)) {
						RecordKeys["TransactionID"] = Convert.ToString(keyValues[0]);
					}
				} else {
					CurrentAction = "show"; // Default action is display

					// Load key from QueryString
					bool loadByQuery = false;
					string[] keyValues = null;
					object rv;
					if (IsApi() && RouteValues.TryGetValue("key", out object k))
						keyValues = k.ToString().Split('/');
					if (RouteValues.TryGetValue("TransactionID", out rv)) { // DN
						TransactionID.QueryValue = Convert.ToString(rv);
						RecordKeys["TransactionID"] = TransactionID.QueryValue;
						loadByQuery = true;
					} else if (Get("TransactionID", out sv)) {
						TransactionID.QueryValue = sv;
						RecordKeys["TransactionID"] = TransactionID.QueryValue;
						loadByQuery = true;
					} else if (IsApi() && !Empty(keyValues)) {
						TransactionID.QueryValue = Convert.ToString(keyValues[0]);
						RecordKeys["TransactionID"] = TransactionID.QueryValue;
						loadByQuery = true;
					} else {
						TransactionID.CurrentValue = System.DBNull.Value;
					}
					if (!loadByQuery)
						loadByPosition = true;
				}
				StartRecord = 1; // Initialize start position
				Recordset = await LoadRecordset(); // Load records
				TotalRecords = await ListRecordCount(); // Get record count // DN
				if (TotalRecords <= 0) { // No record found
					if (Empty(SuccessMessage) && Empty(FailureMessage))
						FailureMessage = Language.Phrase("NoRecord"); // Set no record message
					if (IsApi()) {
						if (!Empty(SuccessMessage))
							return new JsonBoolResult(new { success = true, message = SuccessMessage, version = Config.ProductVersion }, true);
						else
							return new JsonBoolResult(new { success = false, error = FailureMessage, version = Config.ProductVersion }, false);
					} else {
						return Terminate("Transactionslist"); // Return to list page
					}
				} else if (loadByPosition) { // Load record by position
					SetupStartRecord(); // Set up start record position

					// Point to current record
					if (StartRecord <= TotalRecords) {
						for (int i = 1; i <= StartRecord; i++)
							await Recordset.ReadAsync();
						loaded = true;
					}
				} else { // Match key values
					if (TransactionID.CurrentValue != null) {
						while (await Recordset.ReadAsync()) {
							if (SameString(TransactionID.CurrentValue, Recordset["TransactionID"])) {
								StartRecordNumber = StartRecord; // Save record position
								loaded = true;
							break;
						} else {
							StartRecord++;
						}
					}
				}
			}

			// Load current row values
			if (loaded)
				await LoadRowValues(Recordset);

			// Process form if post back
			if (postBack) {
				await LoadFormValues(); // Get form values
				if (IsApi() && RouteValues.TryGetValue("key", out object k)) {
					var keyValues = k.ToString().Split('/');
					TransactionID.FormValue = Convert.ToString(keyValues[0]);
				}
			}

			// Validate form if post back
			if (postBack) {
				if (!await ValidateForm()) {
					FailureMessage = FormError;
					EventCancelled = true; // Event cancelled
					RestoreFormValues();
					if (IsApi())
						return Terminate();
					else
						CurrentAction = ""; // Form error, reset action
				}
			}

			// Perform current action
			switch (CurrentAction) {
					case "show": // Get a record to display
						if (!loaded) {
							if (Empty(SuccessMessage) && Empty(FailureMessage))
								FailureMessage = Language.Phrase("NoRecord"); // Set no record message
							if (IsApi()) {
								if (!Empty(SuccessMessage))
									return new JsonBoolResult(new { success = true, message = SuccessMessage, version = Config.ProductVersion }, true);
								else
									return new JsonBoolResult(new { success = false, error = FailureMessage, version = Config.ProductVersion }, false);
							} else {
								return Terminate("Transactionslist"); // Return to list page
							}
						} else {
						}
						break;
					case "update": // Update // DN
						CloseRecordset(); // DN
						string returnUrl = ReturnUrl;
						if (GetPageName(returnUrl) == "Transactionslist")
							returnUrl = AddMasterUrl(ListUrl); // List page, return to List page with correct master key if necessary
						SendEmail = true; // Send email on update success
						var res = await EditRow();
						if (res) { // Update record based on key
							if (Empty(SuccessMessage))
								SuccessMessage = Language.Phrase("UpdateSuccess"); // Update success
							if (IsApi()) {
								return res;
							} else {
								return Terminate(returnUrl); // Return to caller
							}
						} else if (IsApi()) { // API request, return
							return Terminate();
						} else if (FailureMessage == Language.Phrase("NoRecord")) {
							return Terminate(returnUrl); // Return to caller
						} else {
							EventCancelled = true; // Event cancelled
							RestoreFormValues(); // Restore form values if update failed
						}
						break;
				}

				// Set up Breadcrumb
				SetupBreadcrumb();

				// Render the record
				RowType = Config.RowTypeEdit; // Render as Edit
				ResetAttributes();
				await RenderRow();
				return PageResult();
			}
			#pragma warning restore 219

			// Confirm page
			public bool ConfirmPage = false; // DN
			#pragma warning disable 1998

			// Get upload files
			public async Task GetUploadFiles()
			{

				// Get upload data
			}
			#pragma warning restore 1998
			#pragma warning disable 1998

			// Load form values
			protected async Task LoadFormValues() {
				string val;

				// Check field name 'TransactionID' first before field var 'x_TransactionID'
				val = CurrentForm.GetValue("TransactionID", "x_TransactionID");
				if (!TransactionID.IsDetailKey)
					TransactionID.FormValue = val;

				// Check field name 'TransactionDate' first before field var 'x_TransactionDate'
				val = CurrentForm.GetValue("TransactionDate", "x_TransactionDate");
				if (!TransactionDate.IsDetailKey) {
					if (IsApi() && !CurrentForm.HasValue("TransactionDate", "x_TransactionDate")) // DN
						TransactionDate.Visible = false; // Disable update for API request
					else
						TransactionDate.FormValue = val;
					TransactionDate.CurrentValue = UnformatDateTime(TransactionDate.CurrentValue, 0);
				}

				// Check field name 'AccountID' first before field var 'x_AccountID'
				val = CurrentForm.GetValue("AccountID", "x_AccountID");
				if (!AccountID.IsDetailKey) {
					if (IsApi() && !CurrentForm.HasValue("AccountID", "x_AccountID")) // DN
						AccountID.Visible = false; // Disable update for API request
					else
						AccountID.FormValue = val;
				}

				// Check field name 'Description' first before field var 'x_Description'
				val = CurrentForm.GetValue("Description", "x_Description");
				if (!Description.IsDetailKey) {
					if (IsApi() && !CurrentForm.HasValue("Description", "x_Description")) // DN
						Description.Visible = false; // Disable update for API request
					else
						Description.FormValue = val;
				}

				// Check field name 'Debit' first before field var 'x_Debit'
				val = CurrentForm.GetValue("Debit", "x_Debit");
				if (!Debit.IsDetailKey) {
					if (IsApi() && !CurrentForm.HasValue("Debit", "x_Debit")) // DN
						Debit.Visible = false; // Disable update for API request
					else
						Debit.FormValue = val;
				}

				// Check field name 'Credit' first before field var 'x_Credit'
				val = CurrentForm.GetValue("Credit", "x_Credit");
				if (!Credit.IsDetailKey) {
					if (IsApi() && !CurrentForm.HasValue("Credit", "x_Credit")) // DN
						Credit.Visible = false; // Disable update for API request
					else
						Credit.FormValue = val;
				}
			}
			#pragma warning restore 1998

			// Restore form values
			public void RestoreFormValues() {
				TransactionID.CurrentValue = TransactionID.FormValue;
				TransactionDate.CurrentValue = TransactionDate.FormValue;
				TransactionDate.CurrentValue = UnformatDateTime(TransactionDate.CurrentValue, 0);
				AccountID.CurrentValue = AccountID.FormValue;
				Description.CurrentValue = Description.FormValue;
				Debit.CurrentValue = Debit.FormValue;
				Credit.CurrentValue = Credit.FormValue;
			}

			// Load recordset // DN
			public async Task<DbDataReader> LoadRecordset(int offset = -1, int rowcnt = -1) {

				// Load list page SQL
				string sql = ListSql;

				// Load recordset (Recordset_Selected event not supported) // DN
				return await Connection.SelectLimit(sql, rowcnt, offset, !Empty(OrderBy) || !Empty(SessionOrderBy));
			}

			// Load row based on key values
			public async Task<bool> LoadRow() {
				string filter = GetRecordFilter();

				// Call Row Selecting event
				Row_Selecting(ref filter);

				// Load SQL based on filter
				CurrentFilter = filter;
				string sql = CurrentSql;
				bool res = false;
				try {
					using var rsrow = await Connection.OpenDataReaderAsync(sql);
					if (rsrow != null && await rsrow.ReadAsync()) {
						await LoadRowValues(rsrow);
						res = true;
					} else {
						return false;
					}
				} catch {
					if (Config.Debug)
						throw;
				}
				return res;
			}
			#pragma warning disable 162, 168, 1998

			// Load row values from recordset
			public async Task LoadRowValues(DbDataReader dr = null) {
				Dictionary<string, object> row;
				object v;
				if (dr != null && dr.HasRows)
					row = Connection.GetRow(dr); // DN
				else
					row = NewRow();

				// Call Row Selected event
				Row_Selected(row);
				if (dr == null || !dr.HasRows)
					return;
				TransactionID.SetDbValue(row["TransactionID"]);
				TransactionDate.SetDbValue(row["TransactionDate"]);
				AccountID.SetDbValue(row["AccountID"]);
				Description.SetDbValue(row["Description"]);
				Debit.SetDbValue(row["Debit"]);
				Credit.SetDbValue(row["Credit"]);
			}
			#pragma warning restore 162, 168, 1998

			// Return a row with default values
			protected Dictionary<string, object> NewRow() {
				var row = new Dictionary<string, object>();
				row.Add("TransactionID", System.DBNull.Value);
				row.Add("TransactionDate", System.DBNull.Value);
				row.Add("AccountID", System.DBNull.Value);
				row.Add("Description", System.DBNull.Value);
				row.Add("Debit", System.DBNull.Value);
				row.Add("Credit", System.DBNull.Value);
				return row;
			}
			#pragma warning disable 618, 1998

			// Load old record
			protected async Task<bool> LoadOldRecord(DatabaseConnectionBase<SqlConnection, SqlCommand, SqlDataReader, SqlDbType> cnn = null) {
				bool validKey = true;
				if (!Empty(GetKey("TransactionID")))
					TransactionID.OldValue = GetKey("TransactionID"); // TransactionID
				else
					validKey = false;

				// Load old record
				OldRecordset = null;
				if (validKey) {
					CurrentFilter = GetRecordFilter();
					string sql = CurrentSql;
					try {
						if (cnn != null) {
							OldRecordset = await cnn.OpenDataReaderAsync(sql);
						 } else {
							OldRecordset = await Connection.OpenDataReaderAsync(sql);
						 }
						if (OldRecordset != null)
							await OldRecordset.ReadAsync();
					} catch {
						OldRecordset = null;
					}
				}
				await LoadRowValues(OldRecordset); // Load row values
				return validKey;
			}
			#pragma warning restore 618, 1998
			#pragma warning disable 1998

			// Render row values based on field settings
			public async Task RenderRow() {

				// Convert decimal values if posted back
				if (SameString(Debit.FormValue, Debit.CurrentValue) && IsNumeric(ConvertToFloatString(Debit.CurrentValue)))
					Debit.CurrentValue = ConvertToFloatString(Debit.CurrentValue);

				// Convert decimal values if posted back
				if (SameString(Credit.FormValue, Credit.CurrentValue) && IsNumeric(ConvertToFloatString(Credit.CurrentValue)))
					Credit.CurrentValue = ConvertToFloatString(Credit.CurrentValue);

				// Call Row_Rendering event
				Row_Rendering();

				// Common render codes for all row types
				// TransactionID
				// TransactionDate
				// AccountID
				// Description
				// Debit
				// Credit

				if (RowType == Config.RowTypeView) { // View row

					// TransactionID
					TransactionID.ViewValue = TransactionID.CurrentValue;
					TransactionID.ViewCustomAttributes = "";

					// TransactionDate
					TransactionDate.ViewValue = Convert.ToString(TransactionDate.CurrentValue); // DN
					TransactionDate.ViewValue = FormatDateTime(TransactionDate.ViewValue, 0);
					TransactionDate.ViewCustomAttributes = "";

					// AccountID
					curVal = Convert.ToString(AccountID.CurrentValue);
					if (!Empty(curVal)) {
						AccountID.ViewValue = AccountID.LookupCacheOption(curVal);
						if (AccountID.ViewValue == null) { // Lookup from database
							filterWrk = "[AccountID]" + SearchString("=", curVal.Trim(), Config.DataTypeNumber, "");
							sqlWrk = AccountID.Lookup.GetSql(false, filterWrk, null, this);
							rswrk = await Connection.GetRowsAsync(sqlWrk);
							if (rswrk != null && rswrk.Count > 0) { // Lookup values found
								var listwrk = rswrk[0].Values.ToList();
								listwrk[1] = Convert.ToString(listwrk[1]);
								AccountID.ViewValue = AccountID.DisplayValue(listwrk);
							} else {
								AccountID.ViewValue = AccountID.CurrentValue;
							}
						}
					} else {
						AccountID.ViewValue = System.DBNull.Value;
					}
					AccountID.ViewCustomAttributes = "";

					// Description
					Description.ViewValue = Description.CurrentValue;
					Description.ViewCustomAttributes = "";

					// Debit
					Debit.ViewValue = Convert.ToString(Debit.CurrentValue); // DN
					Debit.ViewValue = FormatNumber(Debit.ViewValue, 2, -2, -2, -2);
					Debit.ViewCustomAttributes = "";

					// Credit
					Credit.ViewValue = Convert.ToString(Credit.CurrentValue); // DN
					Credit.ViewValue = FormatNumber(Credit.ViewValue, 2, -2, -2, -2);
					Credit.ViewCustomAttributes = "";

					// TransactionID
					TransactionID.HrefValue = "";
					TransactionID.TooltipValue = "";

					// TransactionDate
					TransactionDate.HrefValue = "";
					TransactionDate.TooltipValue = "";

					// AccountID
					AccountID.HrefValue = "";
					AccountID.TooltipValue = "";

					// Description
					Description.HrefValue = "";
					Description.TooltipValue = "";

					// Debit
					Debit.HrefValue = "";
					Debit.TooltipValue = "";

					// Credit
					Credit.HrefValue = "";
					Credit.TooltipValue = "";
				} else if (RowType == Config.RowTypeEdit) { // Edit row

					// TransactionID
					TransactionID.EditAttrs["class"] = "form-control";
					TransactionID.EditValue = TransactionID.CurrentValue;
					TransactionID.ViewCustomAttributes = "";

					// TransactionDate
					TransactionDate.EditAttrs["class"] = "form-control";
					TransactionDate.EditValue = FormatDateTime(TransactionDate.CurrentValue, 8); // DN
					TransactionDate.PlaceHolder = RemoveHtml(TransactionDate.Caption);

					// AccountID
					curVal = Convert.ToString(AccountID.CurrentValue)?.Trim() ?? "";
					if (curVal != "")
						AccountID.ViewValue = AccountID.LookupCacheOption(curVal);
					else
						AccountID.ViewValue = AccountID.Lookup != null && IsList(AccountID.Lookup.Options) ? curVal : null;
					if (AccountID.ViewValue != null) { // Load from cache
						AccountID.EditValue = AccountID.Lookup.Options.Values.ToList();
						if (SameString(AccountID.ViewValue, ""))
							AccountID.ViewValue = Language.Phrase("PleaseSelect");
					} else { // Lookup from database
						if (curVal == "") {
							filterWrk = "0=1";
						} else {
							filterWrk = "[AccountID]" + SearchString("=", Convert.ToString(AccountID.CurrentValue), Config.DataTypeNumber, "");
						}
						sqlWrk = AccountID.Lookup.GetSql(true, filterWrk, null, this);
						rswrk = await Connection.GetRowsAsync(sqlWrk);
						if (rswrk != null && rswrk.Count > 0) { // Lookup values found
							var listwrk = rswrk[0].Values.ToList();
							listwrk[1] = Convert.ToString(HtmlEncode(listwrk[1]));
							AccountID.ViewValue = AccountID.DisplayValue(listwrk);
						} else {
							AccountID.ViewValue = AccountID.PleaseSelectText;
						}
						AccountID.EditValue = rswrk;
					}

					// Description
					Description.EditAttrs["class"] = "form-control";
					Description.EditValue = Description.CurrentValue; // DN
					Description.PlaceHolder = RemoveHtml(Description.Caption);

					// Debit
					Debit.EditAttrs["class"] = "form-control";
					Debit.EditValue = Debit.CurrentValue; // DN
					Debit.PlaceHolder = RemoveHtml(Debit.Caption);
					if (!Empty(Debit.EditValue) && IsNumeric(Debit.EditValue))
						Debit.EditValue = FormatNumber(Debit.EditValue, -2, -2, -2, -2);
					

					// Credit
					Credit.EditAttrs["class"] = "form-control";
					Credit.EditValue = Credit.CurrentValue; // DN
					Credit.PlaceHolder = RemoveHtml(Credit.Caption);
					if (!Empty(Credit.EditValue) && IsNumeric(Credit.EditValue))
						Credit.EditValue = FormatNumber(Credit.EditValue, -2, -2, -2, -2);
					

					// Edit refer script
					// TransactionID

					TransactionID.HrefValue = "";

					// TransactionDate
					TransactionDate.HrefValue = "";

					// AccountID
					AccountID.HrefValue = "";

					// Description
					Description.HrefValue = "";

					// Debit
					Debit.HrefValue = "";

					// Credit
					Credit.HrefValue = "";
				}
				if (RowType == Config.RowTypeAdd || RowType == Config.RowTypeEdit || RowType == Config.RowTypeSearch) // Add/Edit/Search row
					SetupFieldTitles();

				// Call Row Rendered event
				if (RowType != Config.RowTypeAggregateInit)
					Row_Rendered();
			}
			#pragma warning restore 1998
			#pragma warning disable 1998

			// Validate form
			protected async Task<bool> ValidateForm() {

				// Initialize form error message
				FormError = "";

				// Check if validation required
				if (!Config.ServerValidate)
					return (FormError == "");
				if (TransactionID.Required) {
					if (!TransactionID.IsDetailKey && Empty(TransactionID.FormValue)) {
						FormError = AddMessage(FormError, Convert.ToString(TransactionID.RequiredErrorMessage).Replace("%s", TransactionID.Caption));
					}
				}
				if (TransactionDate.Required) {
					if (!TransactionDate.IsDetailKey && Empty(TransactionDate.FormValue)) {
						FormError = AddMessage(FormError, Convert.ToString(TransactionDate.RequiredErrorMessage).Replace("%s", TransactionDate.Caption));
					}
				}
				if (!CheckDate(TransactionDate.FormValue)) {
					FormError = AddMessage(FormError, TransactionDate.ErrorMessage);
				}
				if (AccountID.Required) {
					if (!AccountID.IsDetailKey && Empty(AccountID.FormValue)) {
						FormError = AddMessage(FormError, Convert.ToString(AccountID.RequiredErrorMessage).Replace("%s", AccountID.Caption));
					}
				}
				if (Description.Required) {
					if (!Description.IsDetailKey && Empty(Description.FormValue)) {
						FormError = AddMessage(FormError, Convert.ToString(Description.RequiredErrorMessage).Replace("%s", Description.Caption));
					}
				}
				if (Debit.Required) {
					if (!Debit.IsDetailKey && Empty(Debit.FormValue)) {
						FormError = AddMessage(FormError, Convert.ToString(Debit.RequiredErrorMessage).Replace("%s", Debit.Caption));
					}
				}
				if (!CheckNumber(Debit.FormValue)) {
					FormError = AddMessage(FormError, Debit.ErrorMessage);
				}
				if (Credit.Required) {
					if (!Credit.IsDetailKey && Empty(Credit.FormValue)) {
						FormError = AddMessage(FormError, Convert.ToString(Credit.RequiredErrorMessage).Replace("%s", Credit.Caption));
					}
				}
				if (!CheckNumber(Credit.FormValue)) {
					FormError = AddMessage(FormError, Credit.ErrorMessage);
				}

				// Return validate result
				bool valid = Empty(FormError);

				// Call Form_CustomValidate event
				string formCustomError = "";
				valid = valid && Form_CustomValidate(ref formCustomError);
				FormError = AddMessage(FormError, formCustomError);
				return valid;
			}
			#pragma warning restore 1998

			// Update record based on key values
			#pragma warning disable 168, 219
			protected async Task<JsonBoolResult> EditRow() { // DN
				bool result = false;
				Dictionary<string, object> rsold = null;
				var rsnew = new Dictionary<string, object>();
				string oldKeyFilter = GetRecordFilter();
				string filter = ApplyUserIDFilters(oldKeyFilter);
				CurrentFilter = filter;
				string sql = CurrentSql;
				try {
					using var rsedit = await Connection.GetDataReaderAsync(sql);
					if (rsedit == null || !await rsedit.ReadAsync()) {
						FailureMessage = Language.Phrase("NoRecord"); // Set no record message
						return JsonBoolResult.FalseResult;
					}
					rsold = Connection.GetRow(rsedit);
					LoadDbValues(rsold);
				} catch (Exception e) {
					if (Config.Debug)
						throw;
					FailureMessage = e.Message;
					return JsonBoolResult.FalseResult;
				}

				// TransactionDate
				TransactionDate.SetDbValue(rsnew, UnformatDateTime(TransactionDate.CurrentValue, 0), DateTime.Now, TransactionDate.ReadOnly);

				// AccountID
				AccountID.SetDbValue(rsnew, AccountID.CurrentValue, 0, AccountID.ReadOnly);

				// Description
				Description.SetDbValue(rsnew, Description.CurrentValue, "", Description.ReadOnly);

				// Debit
				Debit.SetDbValue(rsnew, Debit.CurrentValue, 0, Debit.ReadOnly);

				// Credit
				Credit.SetDbValue(rsnew, Credit.CurrentValue, 0, Credit.ReadOnly);

				// Call Row Updating event
				bool updateRow = Row_Updating(rsold, rsnew);

				// Check for duplicate key when key changed
				if (updateRow) {
					string newKeyFilter = GetRecordFilter(rsnew);
					if (newKeyFilter != oldKeyFilter) {
						using var rsChk = await LoadRs(newKeyFilter);
						if (rsChk != null && await rsChk.ReadAsync()) {
							FailureMessage = Language.Phrase("DupKey").Replace("%f", newKeyFilter);
							updateRow = false;
						}
					}
				}
				if (updateRow) {
					try {
						if (rsnew.Count > 0)
							result = await UpdateAsync(rsnew, "", rsold) > 0;
						else
							result = true;
						if (result) {
						}
					} catch (Exception e) {
						if (Config.Debug)
							throw;
						FailureMessage = e.Message;
						return JsonBoolResult.FalseResult;
					}
				} else {
					if (!Empty(SuccessMessage) || !Empty(FailureMessage)) {

						// Use the message, do nothing
					} else if (!Empty(CancelMessage)) {
						FailureMessage = CancelMessage;
						CancelMessage = "";
					} else {
						FailureMessage = Language.Phrase("UpdateCancelled");
					}
					result = false;
				}

				// Call Row_Updated event
				if (result)
					Row_Updated(rsold, rsnew);

				// Write JSON for API request
				var d = new Dictionary<string, object>();
				d.Add("success", result);
				if (IsApi() && result) {
					var row = GetRecordFromDictionary(rsnew);
					d.Add(TableVar, row);
					d.Add("version", Config.ProductVersion);
					return new JsonBoolResult(d, true);
				}
				return new JsonBoolResult(d, result);
			}

			// Save data to memory cache
			public void SetCache<T>(string key, T value, int span) => Cache.Set<T>(key, value, new MemoryCacheEntryOptions()
				.SetSlidingExpiration(TimeSpan.FromMilliseconds(span))); // Keep in cache for this time, reset time if accessed

			// Gete data from memory cache
			public void GetCache<T>(string key) => Cache.Get<T>(key);

			// Set up Breadcrumb
			protected void SetupBreadcrumb() {
				var breadcrumb = new Breadcrumb();
				string url = CurrentUrl();
				breadcrumb.Add("list", TableVar, AppPath(AddMasterUrl("Transactionslist")), "", TableVar, true);
				string pageId = "edit";
				breadcrumb.Add("edit", pageId, url);
				CurrentBreadcrumb = breadcrumb;
			}

			// Setup lookup options
			public async Task SetupLookupOptions(DbField fld)
			{
				Func<string> lookupFilter = null;
				var conn = Connection;
				if (!Empty(fld.Lookup) && fld.Lookup.Options.Count == 0) {

					// Set up lookup SQL
					// Always call to Lookup.GetSql so that user can setup Lookup.Options in Lookup_Selecting server event

					var sql = fld.Lookup.GetSql(false, "", lookupFilter, this);

					// Set up lookup cache
					if (fld.UseLookupCache && !Empty(sql) && fld.Lookup.ParentFields.Count == 0 && fld.Lookup.Options.Count == 0) {
						int totalCnt = await TryGetRecordCount(sql, conn);
						if (totalCnt > fld.LookupCacheCount) // Total count > cache count, do not cache
							return;
						var ar = new Dictionary<string, Dictionary<string, object>>();
						var values = new List<object>();
						List<Dictionary<string, object>> rs = await conn.GetRowsAsync(sql);
						if (rs != null) {
							foreach (var row in rs) {

								// Format the field values
								switch (fld.FieldVar) {
									case "x_AccountID":
									break;
								}
								string key = row.Values.First()?.ToString() ?? string.Empty;
								if (!ar.ContainsKey(key))
									ar.Add(key, row);
							}
						}
						fld.Lookup.Options = ar;
					}
				}
			}

			// Close recordset
			public void CloseRecordset() {
				using (Recordset) {} // Dispose
			}

			// Set up starting record parameters
			public void SetupStartRecord() {
				int pageNo;

				// Exit if DisplayRecords = 0
				if (DisplayRecords == 0)
					return;
				if (IsPageRequest) { // Validate request
					if (IsNumeric(Get(Config.TablePageNumber))) { // Check for "pageno" parameter first
						pageNo = Get<int>(Config.TablePageNumber);
						StartRecord = (pageNo - 1) * DisplayRecords + 1;
						if (StartRecord <= 0) {
							StartRecord = 1;
						} else if (StartRecord >= ((TotalRecords - 1) / DisplayRecords) * DisplayRecords + 1) {
							StartRecord = ((TotalRecords - 1) / DisplayRecords) * DisplayRecords + 1;
						}
						StartRecordNumber = StartRecord;
					} else if (IsNumeric(Get(Config.TableStartRec))) { // Check for a "start" parameter
						StartRecord = Get<int>(Config.TableStartRec);
						StartRecordNumber = StartRecord;
					}
				}
				StartRecord = StartRecordNumber;

				// Check if correct start record counter
				if (StartRecord <= 0) { // Avoid invalid start record counter
					StartRecord = 1; // Reset start record counter
					StartRecordNumber = StartRecord;
				} else if (StartRecord > TotalRecords) { // Avoid starting record > total records
					StartRecord = ((TotalRecords - 1) / DisplayRecords) * DisplayRecords + 1; // Point to last page first record
					StartRecordNumber = StartRecord;
				} else if ((StartRecord - 1) % DisplayRecords != 0) {
					StartRecord = ((StartRecord - 1) / DisplayRecords) * DisplayRecords + 1; // Point to page boundary
					StartRecordNumber = StartRecord;
				}
			}

			// Page Load event
			public virtual void Page_Load() {

				//Log("Page Load");
			}

			// Page Unload event
			public virtual void Page_Unload() {

				//Log("Page Unload");
			}

			// Page Redirecting event
			public virtual void Page_Redirecting(ref string url) {

				//url = newurl;
			}

			// Message Showing event
			// type = ""|"success"|"failure"|"warning"
			public virtual void Message_Showing(ref string msg, string type) {

				// Note: Do not change msg outside the following 4 cases.
				if (type == "success") {

					//msg = "your success message";
				} else if (type == "failure") {

					//msg = "your failure message";
				} else if (type == "warning") {

					//msg = "your warning message";
				} else {

					//msg = "your message";
				}
			}

			// Page Load event
			public virtual void Page_Render() {

				//Log("Page Render");
			}

			// Page Data Rendering event
			public virtual void Page_DataRendering(ref string header) {

				// Example:
				//header = "your header";

			}

			// Page Data Rendered event
			public virtual void Page_DataRendered(ref string footer) {

				// Example:
				//footer = "your footer";

			}

			// Form Custom Validate event
			public virtual bool Form_CustomValidate(ref string customError) {

				//Return error message in customError
				return true;
			}
		} // End page class
	} // End Partial class
} // End namespace