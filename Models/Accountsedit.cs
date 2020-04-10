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
		/// Accounts_Edit
		/// </summary>
		public static _Accounts_Edit Accounts_Edit {
			get => HttpData.Get<_Accounts_Edit>("Accounts_Edit");
			set => HttpData["Accounts_Edit"] = value;
		}

		/// <summary>
		/// Page class for Accounts
		/// </summary>
		public class _Accounts_Edit : _Accounts_EditBase
		{

			// Construtor
			public _Accounts_Edit(Controller controller = null) : base(controller) {
			}
		}

		/// <summary>
		/// Page base class
		/// </summary>
		public class _Accounts_EditBase : _Accounts, IAspNetMakerPage
		{

			// Page ID
			public string PageID = "edit";

			// Project ID
			public string ProjectID = "{31239A93-3DBA-4D73-A306-C1D3BFE7959E}";

			// Table name
			public string TableName { get; set; } = "Accounts";

			// Page object name
			public string PageObjName = "Accounts_Edit";

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
			public _Accounts_EditBase(Controller controller = null) { // DN
				if (controller != null)
					Controller = controller;

				// Initialize
				CurrentPage = this;

				// Language object
				Language ??= new Lang();

				// Table object (Accounts)
				if (Accounts == null || Accounts is _Accounts)
					Accounts = this;

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
					dynamic doc = CreateInstance(classname, new object[] { Accounts, "" }); // DN
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
								if (pageName == "Accountsview")
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
				key += UrlEncode(Convert.ToString(ar["AccountID"]));
				return key;
			}

			// Hide fields for Add/Edit
			protected void HideFieldsForAddEdit() {
				if (IsAdd || IsCopy || IsGridAdd)
					AccountID.Visible = false;
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
				AccountID.SetVisibility();
				AccountNumber.SetVisibility();
				FirstName.SetVisibility();
				OtherNames.SetVisibility();
				LastName.SetVisibility();
				AccountTypeID.SetVisibility();
				BankVerificationNumber.SetVisibility();
				DateOfBirth.SetVisibility();
				Photo.SetVisibility();
				_Email.SetVisibility();
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
				await SetupLookupOptions(AccountTypeID);

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
					if (RouteValues.TryGetValue("AccountID", out rv)) { // DN
						AccountID.FormValue = Convert.ToString(rv);
						RecordKeys["AccountID"] = AccountID.FormValue;
					} else if (CurrentForm.HasValue("x_AccountID")) {
						AccountID.FormValue = CurrentForm.GetValue("x_AccountID");
						RecordKeys["AccountID"] = AccountID.FormValue;
					} else if (IsApi() && !Empty(keyValues)) {
						RecordKeys["AccountID"] = Convert.ToString(keyValues[0]);
					}
				} else {
					CurrentAction = "show"; // Default action is display

					// Load key from QueryString
					bool loadByQuery = false;
					string[] keyValues = null;
					object rv;
					if (IsApi() && RouteValues.TryGetValue("key", out object k))
						keyValues = k.ToString().Split('/');
					if (RouteValues.TryGetValue("AccountID", out rv)) { // DN
						AccountID.QueryValue = Convert.ToString(rv);
						RecordKeys["AccountID"] = AccountID.QueryValue;
						loadByQuery = true;
					} else if (Get("AccountID", out sv)) {
						AccountID.QueryValue = sv;
						RecordKeys["AccountID"] = AccountID.QueryValue;
						loadByQuery = true;
					} else if (IsApi() && !Empty(keyValues)) {
						AccountID.QueryValue = Convert.ToString(keyValues[0]);
						RecordKeys["AccountID"] = AccountID.QueryValue;
						loadByQuery = true;
					} else {
						AccountID.CurrentValue = System.DBNull.Value;
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
						return Terminate("Accountslist"); // Return to list page
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
					if (AccountID.CurrentValue != null) {
						while (await Recordset.ReadAsync()) {
							if (SameString(AccountID.CurrentValue, Recordset["AccountID"])) {
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
					AccountID.FormValue = Convert.ToString(keyValues[0]);
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
								return Terminate("Accountslist"); // Return to list page
							}
						} else {
						}
						break;
					case "update": // Update // DN
						CloseRecordset(); // DN
						string returnUrl = ReturnUrl;
						if (GetPageName(returnUrl) == "Accountslist")
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
				Photo.Upload.Index = CurrentForm.Index;
				if (!await Photo.Upload.UploadFile()) // DN
					End(Photo.Upload.Message);
			}
			#pragma warning restore 1998
			#pragma warning disable 1998

			// Load form values
			protected async Task LoadFormValues() {
				await GetUploadFiles(); // Get upload files
				string val;

				// Check field name 'AccountID' first before field var 'x_AccountID'
				val = CurrentForm.GetValue("AccountID", "x_AccountID");
				if (!AccountID.IsDetailKey)
					AccountID.FormValue = val;

				// Check field name 'AccountNumber' first before field var 'x_AccountNumber'
				val = CurrentForm.GetValue("AccountNumber", "x_AccountNumber");
				if (!AccountNumber.IsDetailKey) {
					if (IsApi() && !CurrentForm.HasValue("AccountNumber", "x_AccountNumber")) // DN
						AccountNumber.Visible = false; // Disable update for API request
					else
						AccountNumber.FormValue = val;
				}

				// Check field name 'FirstName' first before field var 'x_FirstName'
				val = CurrentForm.GetValue("FirstName", "x_FirstName");
				if (!FirstName.IsDetailKey) {
					if (IsApi() && !CurrentForm.HasValue("FirstName", "x_FirstName")) // DN
						FirstName.Visible = false; // Disable update for API request
					else
						FirstName.FormValue = val;
				}

				// Check field name 'OtherNames' first before field var 'x_OtherNames'
				val = CurrentForm.GetValue("OtherNames", "x_OtherNames");
				if (!OtherNames.IsDetailKey) {
					if (IsApi() && !CurrentForm.HasValue("OtherNames", "x_OtherNames")) // DN
						OtherNames.Visible = false; // Disable update for API request
					else
						OtherNames.FormValue = val;
				}

				// Check field name 'LastName' first before field var 'x_LastName'
				val = CurrentForm.GetValue("LastName", "x_LastName");
				if (!LastName.IsDetailKey) {
					if (IsApi() && !CurrentForm.HasValue("LastName", "x_LastName")) // DN
						LastName.Visible = false; // Disable update for API request
					else
						LastName.FormValue = val;
				}

				// Check field name 'AccountTypeID' first before field var 'x_AccountTypeID'
				val = CurrentForm.GetValue("AccountTypeID", "x_AccountTypeID");
				if (!AccountTypeID.IsDetailKey) {
					if (IsApi() && !CurrentForm.HasValue("AccountTypeID", "x_AccountTypeID")) // DN
						AccountTypeID.Visible = false; // Disable update for API request
					else
						AccountTypeID.FormValue = val;
				}

				// Check field name 'BankVerificationNumber' first before field var 'x_BankVerificationNumber'
				val = CurrentForm.GetValue("BankVerificationNumber", "x_BankVerificationNumber");
				if (!BankVerificationNumber.IsDetailKey) {
					if (IsApi() && !CurrentForm.HasValue("BankVerificationNumber", "x_BankVerificationNumber")) // DN
						BankVerificationNumber.Visible = false; // Disable update for API request
					else
						BankVerificationNumber.FormValue = val;
				}

				// Check field name 'DateOfBirth' first before field var 'x_DateOfBirth'
				val = CurrentForm.GetValue("DateOfBirth", "x_DateOfBirth");
				if (!DateOfBirth.IsDetailKey) {
					if (IsApi() && !CurrentForm.HasValue("DateOfBirth", "x_DateOfBirth")) // DN
						DateOfBirth.Visible = false; // Disable update for API request
					else
						DateOfBirth.FormValue = val;
					DateOfBirth.CurrentValue = UnformatDateTime(DateOfBirth.CurrentValue, 0);
				}

				// Check field name 'Email' first before field var 'x__Email'
				val = CurrentForm.GetValue("Email", "x__Email");
				if (!_Email.IsDetailKey) {
					if (IsApi() && !CurrentForm.HasValue("Email", "x__Email")) // DN
						_Email.Visible = false; // Disable update for API request
					else
						_Email.FormValue = val;
				}
			}
			#pragma warning restore 1998

			// Restore form values
			public void RestoreFormValues() {
				AccountID.CurrentValue = AccountID.FormValue;
				AccountNumber.CurrentValue = AccountNumber.FormValue;
				FirstName.CurrentValue = FirstName.FormValue;
				OtherNames.CurrentValue = OtherNames.FormValue;
				LastName.CurrentValue = LastName.FormValue;
				AccountTypeID.CurrentValue = AccountTypeID.FormValue;
				BankVerificationNumber.CurrentValue = BankVerificationNumber.FormValue;
				DateOfBirth.CurrentValue = DateOfBirth.FormValue;
				DateOfBirth.CurrentValue = UnformatDateTime(DateOfBirth.CurrentValue, 0);
				_Email.CurrentValue = _Email.FormValue;
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
				AccountID.SetDbValue(row["AccountID"]);
				AccountNumber.SetDbValue(row["AccountNumber"]);
				FirstName.SetDbValue(row["FirstName"]);
				OtherNames.SetDbValue(row["OtherNames"]);
				LastName.SetDbValue(row["LastName"]);
				AccountTypeID.SetDbValue(row["AccountTypeID"]);
				BankVerificationNumber.SetDbValue(row["BankVerificationNumber"]);
				DateOfBirth.SetDbValue(row["DateOfBirth"]);
				Photo.Upload.DbValue = row["Photo"];
				_Email.SetDbValue(row["Email"]);
			}
			#pragma warning restore 162, 168, 1998

			// Return a row with default values
			protected Dictionary<string, object> NewRow() {
				var row = new Dictionary<string, object>();
				row.Add("AccountID", System.DBNull.Value);
				row.Add("AccountNumber", System.DBNull.Value);
				row.Add("FirstName", System.DBNull.Value);
				row.Add("OtherNames", System.DBNull.Value);
				row.Add("LastName", System.DBNull.Value);
				row.Add("AccountTypeID", System.DBNull.Value);
				row.Add("BankVerificationNumber", System.DBNull.Value);
				row.Add("DateOfBirth", System.DBNull.Value);
				row.Add("Photo", System.DBNull.Value);
				row.Add("Email", System.DBNull.Value);
				return row;
			}
			#pragma warning disable 618, 1998

			// Load old record
			protected async Task<bool> LoadOldRecord(DatabaseConnectionBase<SqlConnection, SqlCommand, SqlDataReader, SqlDbType> cnn = null) {
				bool validKey = true;
				if (!Empty(GetKey("AccountID")))
					AccountID.OldValue = GetKey("AccountID"); // AccountID
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

				// Call Row_Rendering event
				Row_Rendering();

				// Common render codes for all row types
				// AccountID
				// AccountNumber
				// FirstName
				// OtherNames
				// LastName
				// AccountTypeID
				// BankVerificationNumber
				// DateOfBirth
				// Photo
				// Email

				if (RowType == Config.RowTypeView) { // View row

					// AccountID
					AccountID.ViewValue = AccountID.CurrentValue;
					AccountID.ViewCustomAttributes = "";

					// AccountNumber
					AccountNumber.ViewValue = Convert.ToString(AccountNumber.CurrentValue); // DN
					AccountNumber.ViewCustomAttributes = "";

					// FirstName
					FirstName.ViewValue = Convert.ToString(FirstName.CurrentValue); // DN
					FirstName.ViewCustomAttributes = "";

					// OtherNames
					OtherNames.ViewValue = Convert.ToString(OtherNames.CurrentValue); // DN
					OtherNames.ViewCustomAttributes = "";

					// LastName
					LastName.ViewValue = Convert.ToString(LastName.CurrentValue); // DN
					LastName.ViewCustomAttributes = "";

					// AccountTypeID
					curVal = Convert.ToString(AccountTypeID.CurrentValue);
					if (!Empty(curVal)) {
						AccountTypeID.ViewValue = AccountTypeID.LookupCacheOption(curVal);
						if (AccountTypeID.ViewValue == null) { // Lookup from database
							filterWrk = "[AccountTypeID]" + SearchString("=", curVal.Trim(), Config.DataTypeNumber, "");
							sqlWrk = AccountTypeID.Lookup.GetSql(false, filterWrk, null, this);
							rswrk = await Connection.GetRowsAsync(sqlWrk);
							if (rswrk != null && rswrk.Count > 0) { // Lookup values found
								var listwrk = rswrk[0].Values.ToList();
								listwrk[1] = Convert.ToString(listwrk[1]);
								AccountTypeID.ViewValue = AccountTypeID.DisplayValue(listwrk);
							} else {
								AccountTypeID.ViewValue = AccountTypeID.CurrentValue;
							}
						}
					} else {
						AccountTypeID.ViewValue = System.DBNull.Value;
					}
					AccountTypeID.ViewCustomAttributes = "";

					// BankVerificationNumber
					BankVerificationNumber.ViewValue = Convert.ToString(BankVerificationNumber.CurrentValue); // DN
					BankVerificationNumber.ViewCustomAttributes = "";

					// DateOfBirth
					DateOfBirth.ViewValue = Convert.ToString(DateOfBirth.CurrentValue); // DN
					DateOfBirth.ViewValue = FormatDateTime(DateOfBirth.ViewValue, 0);
					DateOfBirth.ViewCustomAttributes = "";

					// Photo
					if (!IsDBNull(Photo.Upload.DbValue)) {
						Photo.ViewValue = AccountID.CurrentValue;
						Photo.IsBlobImage = IsImageFile(ContentExtension((byte[])Photo.Upload.DbValue));
					} else {
						Photo.ViewValue = "";
					}
					Photo.ViewCustomAttributes = "";

					// Email
					_Email.ViewValue = Convert.ToString(_Email.CurrentValue); // DN
					_Email.ViewCustomAttributes = "";

					// AccountID
					AccountID.HrefValue = "";
					AccountID.TooltipValue = "";

					// AccountNumber
					AccountNumber.HrefValue = "";
					AccountNumber.TooltipValue = "";

					// FirstName
					FirstName.HrefValue = "";
					FirstName.TooltipValue = "";

					// OtherNames
					OtherNames.HrefValue = "";
					OtherNames.TooltipValue = "";

					// LastName
					LastName.HrefValue = "";
					LastName.TooltipValue = "";

					// AccountTypeID
					AccountTypeID.HrefValue = "";
					AccountTypeID.TooltipValue = "";

					// BankVerificationNumber
					BankVerificationNumber.HrefValue = "";
					BankVerificationNumber.TooltipValue = "";

					// DateOfBirth
					DateOfBirth.HrefValue = "";
					DateOfBirth.TooltipValue = "";

					// Photo
					if (!IsDBNull(Photo.Upload.DbValue)) {
						Photo.HrefValue = AppPath(GetFileUploadUrl(Photo, Convert.ToString(AccountID.CurrentValue))); // DN
						Photo.LinkAttrs["target"] = "";
						if (Photo.IsBlobImage && Empty(Photo.LinkAttrs["target"]))
							Photo.LinkAttrs["target"] = "_blank";
						if (IsExport())
							Photo.HrefValue = FullUrl(Convert.ToString(Photo.HrefValue), "href");
					} else {
						Photo.HrefValue = "";
					}
					Photo.ExportHrefValue = GetFileUploadUrl(Photo, Convert.ToString(AccountID.CurrentValue));
					Photo.TooltipValue = "";

					// Email
					_Email.HrefValue = "";
					_Email.TooltipValue = "";
				} else if (RowType == Config.RowTypeEdit) { // Edit row

					// AccountID
					AccountID.EditAttrs["class"] = "form-control";
					AccountID.EditValue = AccountID.CurrentValue;
					AccountID.ViewCustomAttributes = "";

					// AccountNumber
					AccountNumber.EditAttrs["class"] = "form-control";
					if (!AccountNumber.Raw)
						AccountNumber.CurrentValue = HtmlDecode(AccountNumber.CurrentValue);
					AccountNumber.EditValue = AccountNumber.CurrentValue; // DN
					AccountNumber.PlaceHolder = RemoveHtml(AccountNumber.Caption);

					// FirstName
					FirstName.EditAttrs["class"] = "form-control";
					if (!FirstName.Raw)
						FirstName.CurrentValue = HtmlDecode(FirstName.CurrentValue);
					FirstName.EditValue = FirstName.CurrentValue; // DN
					FirstName.PlaceHolder = RemoveHtml(FirstName.Caption);

					// OtherNames
					OtherNames.EditAttrs["class"] = "form-control";
					if (!OtherNames.Raw)
						OtherNames.CurrentValue = HtmlDecode(OtherNames.CurrentValue);
					OtherNames.EditValue = OtherNames.CurrentValue; // DN
					OtherNames.PlaceHolder = RemoveHtml(OtherNames.Caption);

					// LastName
					LastName.EditAttrs["class"] = "form-control";
					if (!LastName.Raw)
						LastName.CurrentValue = HtmlDecode(LastName.CurrentValue);
					LastName.EditValue = LastName.CurrentValue; // DN
					LastName.PlaceHolder = RemoveHtml(LastName.Caption);

					// AccountTypeID
					curVal = Convert.ToString(AccountTypeID.CurrentValue)?.Trim() ?? "";
					if (curVal != "")
						AccountTypeID.ViewValue = AccountTypeID.LookupCacheOption(curVal);
					else
						AccountTypeID.ViewValue = AccountTypeID.Lookup != null && IsList(AccountTypeID.Lookup.Options) ? curVal : null;
					if (AccountTypeID.ViewValue != null) { // Load from cache
						AccountTypeID.EditValue = AccountTypeID.Lookup.Options.Values.ToList();
						if (SameString(AccountTypeID.ViewValue, ""))
							AccountTypeID.ViewValue = Language.Phrase("PleaseSelect");
					} else { // Lookup from database
						if (curVal == "") {
							filterWrk = "0=1";
						} else {
							filterWrk = "[AccountTypeID]" + SearchString("=", Convert.ToString(AccountTypeID.CurrentValue), Config.DataTypeNumber, "");
						}
						sqlWrk = AccountTypeID.Lookup.GetSql(true, filterWrk, null, this);
						rswrk = await Connection.GetRowsAsync(sqlWrk);
						if (rswrk != null && rswrk.Count > 0) { // Lookup values found
							var listwrk = rswrk[0].Values.ToList();
							listwrk[1] = Convert.ToString(HtmlEncode(listwrk[1]));
							AccountTypeID.ViewValue = AccountTypeID.DisplayValue(listwrk);
						} else {
							AccountTypeID.ViewValue = AccountTypeID.PleaseSelectText;
						}
						AccountTypeID.EditValue = rswrk;
					}

					// BankVerificationNumber
					BankVerificationNumber.EditAttrs["class"] = "form-control";
					if (!BankVerificationNumber.Raw)
						BankVerificationNumber.CurrentValue = HtmlDecode(BankVerificationNumber.CurrentValue);
					BankVerificationNumber.EditValue = BankVerificationNumber.CurrentValue; // DN
					BankVerificationNumber.PlaceHolder = RemoveHtml(BankVerificationNumber.Caption);

					// DateOfBirth
					DateOfBirth.EditAttrs["class"] = "form-control";
					DateOfBirth.EditValue = FormatDateTime(DateOfBirth.CurrentValue, 8); // DN
					DateOfBirth.PlaceHolder = RemoveHtml(DateOfBirth.Caption);

					// Photo
					Photo.EditAttrs["class"] = "form-control";
					if (!IsDBNull(Photo.Upload.DbValue)) {
						Photo.EditValue = AccountID.CurrentValue;
						Photo.IsBlobImage = IsImageFile(ContentExtension((byte[])Photo.Upload.DbValue));
					} else {
						Photo.EditValue = "";
					}
					if (IsShow && !EventCancelled)
						await RenderUploadField(Photo);

					// Email
					_Email.EditAttrs["class"] = "form-control";
					if (!_Email.Raw)
						_Email.CurrentValue = HtmlDecode(_Email.CurrentValue);
					_Email.EditValue = _Email.CurrentValue; // DN
					_Email.PlaceHolder = RemoveHtml(_Email.Caption);

					// Edit refer script
					// AccountID

					AccountID.HrefValue = "";

					// AccountNumber
					AccountNumber.HrefValue = "";

					// FirstName
					FirstName.HrefValue = "";

					// OtherNames
					OtherNames.HrefValue = "";

					// LastName
					LastName.HrefValue = "";

					// AccountTypeID
					AccountTypeID.HrefValue = "";

					// BankVerificationNumber
					BankVerificationNumber.HrefValue = "";

					// DateOfBirth
					DateOfBirth.HrefValue = "";

					// Photo
					if (!IsDBNull(Photo.Upload.DbValue)) {
						Photo.HrefValue = AppPath(GetFileUploadUrl(Photo, Convert.ToString(AccountID.CurrentValue))); // DN
						Photo.LinkAttrs["target"] = "";
						if (Photo.IsBlobImage && Empty(Photo.LinkAttrs["target"]))
							Photo.LinkAttrs["target"] = "_blank";
						if (IsExport())
							Photo.HrefValue = FullUrl(Convert.ToString(Photo.HrefValue), "href");
					} else {
						Photo.HrefValue = "";
					}
					Photo.ExportHrefValue = GetFileUploadUrl(Photo, Convert.ToString(AccountID.CurrentValue));

					// Email
					_Email.HrefValue = "";
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
				if (AccountID.Required) {
					if (!AccountID.IsDetailKey && Empty(AccountID.FormValue)) {
						FormError = AddMessage(FormError, Convert.ToString(AccountID.RequiredErrorMessage).Replace("%s", AccountID.Caption));
					}
				}
				if (AccountNumber.Required) {
					if (!AccountNumber.IsDetailKey && Empty(AccountNumber.FormValue)) {
						FormError = AddMessage(FormError, Convert.ToString(AccountNumber.RequiredErrorMessage).Replace("%s", AccountNumber.Caption));
					}
				}
				if (FirstName.Required) {
					if (!FirstName.IsDetailKey && Empty(FirstName.FormValue)) {
						FormError = AddMessage(FormError, Convert.ToString(FirstName.RequiredErrorMessage).Replace("%s", FirstName.Caption));
					}
				}
				if (OtherNames.Required) {
					if (!OtherNames.IsDetailKey && Empty(OtherNames.FormValue)) {
						FormError = AddMessage(FormError, Convert.ToString(OtherNames.RequiredErrorMessage).Replace("%s", OtherNames.Caption));
					}
				}
				if (LastName.Required) {
					if (!LastName.IsDetailKey && Empty(LastName.FormValue)) {
						FormError = AddMessage(FormError, Convert.ToString(LastName.RequiredErrorMessage).Replace("%s", LastName.Caption));
					}
				}
				if (AccountTypeID.Required) {
					if (!AccountTypeID.IsDetailKey && Empty(AccountTypeID.FormValue)) {
						FormError = AddMessage(FormError, Convert.ToString(AccountTypeID.RequiredErrorMessage).Replace("%s", AccountTypeID.Caption));
					}
				}
				if (BankVerificationNumber.Required) {
					if (!BankVerificationNumber.IsDetailKey && Empty(BankVerificationNumber.FormValue)) {
						FormError = AddMessage(FormError, Convert.ToString(BankVerificationNumber.RequiredErrorMessage).Replace("%s", BankVerificationNumber.Caption));
					}
				}
				if (DateOfBirth.Required) {
					if (!DateOfBirth.IsDetailKey && Empty(DateOfBirth.FormValue)) {
						FormError = AddMessage(FormError, Convert.ToString(DateOfBirth.RequiredErrorMessage).Replace("%s", DateOfBirth.Caption));
					}
				}
				if (!CheckDate(DateOfBirth.FormValue)) {
					FormError = AddMessage(FormError, DateOfBirth.ErrorMessage);
				}
				if (Photo.Required) {
					if (Photo.Upload.FileName == "" && !Photo.Upload.KeepFile) {
						FormError = AddMessage(FormError, Convert.ToString(Photo.RequiredErrorMessage).Replace("%s", Photo.Caption));
					}
				}
				if (_Email.Required) {
					if (!_Email.IsDetailKey && Empty(_Email.FormValue)) {
						FormError = AddMessage(FormError, Convert.ToString(_Email.RequiredErrorMessage).Replace("%s", _Email.Caption));
					}
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
				if (!Empty(AccountNumber.CurrentValue)) { // Check field with unique index
					string filterChk = "([AccountNumber] = '" + AdjustSql(AccountNumber.CurrentValue, DbId) + "')";
					filterChk = filterChk + " AND NOT (" + filter + ")";
					CurrentFilter = filterChk;
					string sqlchk = CurrentSql;
					try {
						using var rschk = await Connection.GetDataReaderAsync(sqlchk);
						if (rschk != null && await rschk.ReadAsync()) {
							var idxErrMsg = Language.Phrase("DupIndex").Replace("%f", AccountNumber.Caption);
							idxErrMsg = idxErrMsg.Replace("%v", Convert.ToString(AccountNumber.CurrentValue));
							FailureMessage = idxErrMsg;
							return JsonBoolResult.FalseResult;
						}
					} catch (Exception e) {
						if (Config.Debug)
							throw;
						FailureMessage = e.Message;
						return JsonBoolResult.FalseResult;
					}
				}
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

				// AccountNumber
				AccountNumber.SetDbValue(rsnew, AccountNumber.CurrentValue, "", AccountNumber.ReadOnly);

				// FirstName
				FirstName.SetDbValue(rsnew, FirstName.CurrentValue, "", FirstName.ReadOnly);

				// OtherNames
				OtherNames.SetDbValue(rsnew, OtherNames.CurrentValue, System.DBNull.Value, OtherNames.ReadOnly);

				// LastName
				LastName.SetDbValue(rsnew, LastName.CurrentValue, "", LastName.ReadOnly);

				// AccountTypeID
				AccountTypeID.SetDbValue(rsnew, AccountTypeID.CurrentValue, 0, AccountTypeID.ReadOnly);

				// BankVerificationNumber
				BankVerificationNumber.SetDbValue(rsnew, BankVerificationNumber.CurrentValue, System.DBNull.Value, BankVerificationNumber.ReadOnly);

				// DateOfBirth
				DateOfBirth.SetDbValue(rsnew, UnformatDateTime(DateOfBirth.CurrentValue, 0), System.DBNull.Value, DateOfBirth.ReadOnly);

				// Photo
				if (Photo.Visible && !Photo.ReadOnly && !Photo.Upload.KeepFile) {
					if (IsDBNull(Photo.Upload.Value)) {
						rsnew["Photo"] = System.DBNull.Value;
					} else {
						rsnew["Photo"] = Photo.Upload.Value;
					}
				}

				// Email
				_Email.SetDbValue(rsnew, _Email.CurrentValue, System.DBNull.Value, _Email.ReadOnly);

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

				// Photo
				if (!Empty(Photo.Upload.FileToken))
					CleanUploadTempPath(Photo.Upload.FileToken);
				else
					CleanUploadTempPath(Photo, Photo.Upload.Index);

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
				breadcrumb.Add("list", TableVar, AppPath(AddMasterUrl("Accountslist")), "", TableVar, true);
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
									case "x_AccountTypeID":
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