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
		/// Accounts_View
		/// </summary>
		public static _Accounts_View Accounts_View {
			get => HttpData.Get<_Accounts_View>("Accounts_View");
			set => HttpData["Accounts_View"] = value;
		}

		/// <summary>
		/// Page class for Accounts
		/// </summary>
		public class _Accounts_View : _Accounts_ViewBase
		{

			// Construtor
			public _Accounts_View(Controller controller = null) : base(controller) {
			}
		}

		/// <summary>
		/// Page base class
		/// </summary>
		public class _Accounts_ViewBase : _Accounts, IAspNetMakerPage
		{

			// Page ID
			public string PageID = "view";

			// Project ID
			public string ProjectID = "{31239A93-3DBA-4D73-A306-C1D3BFE7959E}";

			// Table name
			public string TableName { get; set; } = "Accounts";

			// Page object name
			public string PageObjName = "Accounts_View";

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

			// Export URLs
			public string ExportPrintUrl = "";

			public string ExportHtmlUrl = "";

			public string ExportExcelUrl = "";

			public string ExportWordUrl = "";

			public string ExportXmlUrl = "";

			public string ExportCsvUrl = "";

			public string ExportPdfUrl = "";

			// Custom export
			public bool ExportExcelCustom = false;

			public bool ExportWordCustom = false;

			public bool ExportPdfCustom = false;

			public bool ExportEmailCustom = false;

			// Update URLs
			public string InlineAddUrl = "";

			public string GridAddUrl = "";

			public string GridEditUrl = "";

			public string MultiDeleteUrl = "";

			public string MultiUpdateUrl = "";

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
			public _Accounts_ViewBase(Controller controller = null) { // DN
				if (controller != null)
					Controller = controller;

				// Initialize
				CurrentPage = this;

				// Language object
				Language ??= new Lang();

				// Table object (Accounts)
				if (Accounts == null || Accounts is _Accounts)
					Accounts = this;

				// DN
				string keyUrl = "";
				string[] keys = new string[0];
				StringValues str = "";
				object obj = null;
				string currentPageName = CurrentPageName();
				string currentUrl = AppPath(currentPageName); // DN
				if (IsApi()) {
					if (RouteValues.TryGetValue("key", out object k) && !Empty(k))
						keys = k.ToString().Split('/');
					if (keys.Length > 0)
						RecordKeys["AccountID"] = keys[0];
				} else {
					RecordKeys["AccountID"] = RouteValues.TryGetValue("AccountID", out obj) ? Convert.ToString(obj) : Get("AccountID");
					keyUrl += "/" + UrlEncode(RecordKeys["AccountID"]);
				}
				ExportPrintUrl = currentUrl + keyUrl + "?export=print";
				ExportHtmlUrl = currentUrl + keyUrl + "?export=html";
				ExportExcelUrl = currentUrl + keyUrl + "?export=excel";
				ExportWordUrl = currentUrl + keyUrl + "?export=word";
				ExportXmlUrl = currentUrl + keyUrl + "?export=xml";
				ExportCsvUrl = currentUrl + keyUrl + "?export=csv";
				ExportPdfUrl = currentUrl + keyUrl + "?export=pdf";

				// Start time
				StartTime = Environment.TickCount;

				// Debug message
				LoadDebugMessage();

				// Open connection
				Conn = Connection; // DN

				// Export options
				ExportOptions = new ListOptions { Tag = "div", TagClassName = "ew-export-option" };

				// Other options
				OtherOptions["action"] = new ListOptions { Tag = "div", TagClassName = "ew-action-option" };
				OtherOptions["detail"] = new ListOptions { Tag = "div", TagClassName = "ew-detail-option" };
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
					if (IsExport("email")) {
						result = Controller.Content(await ExportEmail(doc), "text/html");
					} else {
						result = doc.Export();
					}
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

			public bool IsModal = false;

			public string SearchWhere = "";

			public string DbMasterFilter;

			public string DbDetailFilter;

			public bool MasterRecordExists;

			public ListOptions ExportOptions; // Export options

			public ListOptionsDictionary OtherOptions = new ListOptionsDictionary(); // Other options

			public DbDataReader Recordset = null;

			public Pager Pager {
				get {
					_pager ??= new PrevNextPager(StartRecord, DisplayRecords, TotalRecords, "", RecordRange, AutoHidePager);
					return _pager;
				}
			}
			#pragma warning disable 168, 219

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

				// Get export parameters
				string custom = "";
				if (!Empty(Param("export"))) {
					Export = Param("export");
					custom = Param("custom");
				} else if (IsPost()) {
					if (Post("exporttype", out StringValues et))
						Export = et;
					custom = Post("custom");
				} else if (Get("cmd") == "json") {
					Export = "json";
				} else {
					ExportReturnUrl = CurrentUrl();
				}
				ExportFileName = TableVar; // Get export file, used in header
				StringValues sve;
				if (Get("AccountID", out sve)) {
					if (!Empty(ExportFileName))
						ExportFileName += "_";
					ExportFileName += sve;
				}

				// Get custom export parameters
				if (IsExport() && !Empty(custom)) {
					CustomExport = Export;
					Export = "print";
				}
				CustomExportType = CustomExport;
				ExportType = Export; // Get export parameter, used in header

				// Update Export URLs
				if (Config.UseExcelExtension)
					ExportExcelCustom = false;
				if (ExportExcelCustom)
					ExportExcelUrl += "&amp;custom=1";
				if (ExportWordCustom)
					ExportWordUrl += "&amp;custom=1";
				if (ExportPdfCustom)
					ExportPdfUrl += "&amp;custom=1";
				CurrentAction = Param("action"); // Set up current action

				// Setup export options
				SetupExportOptions();
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

				// Load current record
				bool loadCurrentRecord = false;
				string returnUrl = "";
				bool matchRecord = false;
				if (IsPageRequest) { // Validate request
					string[] keyValues = null;
					object v;
					StringValues sv;
					if (IsApi() && RouteValues.TryGetValue("key", out object k))
						if (!Empty(k))
							keyValues = k.ToString().Split('/');
						else
							return new JsonBoolResult(new { success = false, error = Language.Phrase("NoRecord"), version = Config.ProductVersion }, false);
					if (RouteValues.TryGetValue("AccountID", out v) && !Empty(v)) { // DN
						AccountID.QueryValue = Convert.ToString(v);
						RecordKeys["AccountID"] = AccountID.QueryValue;
					} else if (Get("AccountID", out sv)) {
						AccountID.QueryValue = sv;
						RecordKeys["AccountID"] = AccountID.QueryValue;
					} else if (IsApi() && !Empty(keyValues)) {
						AccountID.QueryValue = Convert.ToString(keyValues[0]);
						RecordKeys["AccountID"] = AccountID.QueryValue;
					} else {
						loadCurrentRecord = true;
					}

					// Get action
					CurrentAction = "show"; // Display form
					switch (CurrentAction) {
						case "show": // Get a record to display
							StartRecord = 1; // Initialize start position
							Recordset = await LoadRecordset(); // Load records
							TotalRecords = await ListRecordCount(); // Get record count // DN
							if (TotalRecords <= 0) { // No record found // DN
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
							} else if (loadCurrentRecord) { // Load current record position
								SetupStartRecord(); // Set up start record position

								// Point to current record
								if (StartRecord <= TotalRecords) {
									matchRecord = true;
									for (int i = 1; i <= StartRecord; i++)
										await Recordset.ReadAsync();
								}
							} else { // Match key values
								while (await Recordset.ReadAsync()) {
									if (SameString(AccountID.CurrentValue, Recordset["AccountID"])) {
										StartRecordNumber = StartRecord; // Save record position
										matchRecord = true;
										break;
									} else {
										StartRecord++;
									}
								}
							}
							if (!matchRecord) {
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
								await LoadRowValues(Recordset); // Load row values
							}
							break;
					}
				} else {
					returnUrl = "Accountslist"; // Not page request, return to list
				}
				if (!Empty(returnUrl))
					return Terminate(returnUrl);

				// Render row
				RowType = Config.RowTypeView;
				ResetAttributes();
				await RenderRow();

				// Export data only
				if (Empty(CustomExport) && Config.Export.ContainsKey(Export)) {
					return await ExportData();
				} else if (!Empty(CustomExport) && CustomExport == Export && Config.Export.ContainsKey(CustomExport)) {
					return await ExportView();
				}

				// Set up Breadcrumb
				if (!IsExport())
					SetupBreadcrumb();

				// Normal return
				if (IsApi()) {
					var rows = await GetRecordFromRecordset(Recordset); // Get current record only
					return Controller.Json(new Dictionary<string, object> { {"success", true}, {TableVar, rows}, {"version", Config.ProductVersion} });
				}
				return PageResult();
			}
			#pragma warning restore 168, 219

			// Set up other options
			#pragma warning disable 168, 219 

			public void SetupOtherOptions() 
			{
				var options = OtherOptions;
				var option = options["action"];
				ListOption item;
				string links = "";

				// Add
				item = option.Add("add");
				string addcaption = HtmlTitle(Language.Phrase("ViewPageAddLink"));
				if (IsModal) // Modal
					item.Body = "<a class=\"ew-action ew-add\" title=\"" + addcaption + "\" data-caption=\"" + addcaption + "\" href=\"#\" onclick=\"return ew.modalDialogShow({lnk:this,url:'" + HtmlEncode(AppPath(AddUrl)) + "'});\">" + Language.Phrase("ViewPageAddLink") + "</a>";
				else
					item.Body = "<a class=\"ew-action ew-add\" title=\"" + addcaption + "\" data-caption=\"" + addcaption + "\" href=\"" + HtmlEncode(AppPath(AddUrl)) + "\">" + Language.Phrase("ViewPageAddLink") + "</a>";
					item.Visible = (AddUrl != "");

				// Edit
				item = option.Add("edit");
				var editcaption = HtmlTitle(Language.Phrase("ViewPageEditLink"));
				if (IsModal) // Modal
					item.Body = "<a class=\"ew-action ew-edit\" title=\"" + editcaption + "\" data-caption=\"" + editcaption + "\" href=\"#\" onclick=\"return ew.modalDialogShow({lnk:this,url:'" + HtmlEncode(AppPath(EditUrl)) + "'});\">" + Language.Phrase("ViewPageEditLink") + "</a>";
				else
					item.Body = "<a class=\"ew-action ew-edit\" title=\"" + editcaption + "\" data-caption=\"" + editcaption + "\" href=\"" + HtmlEncode(AppPath(EditUrl)) + "\">" + Language.Phrase("ViewPageEditLink") + "</a>";
					item.Visible = (EditUrl != "");

				// Copy
				item = option.Add("copy");
				var copycaption = HtmlTitle(Language.Phrase("ViewPageCopyLink"));
				if (IsModal) // Modal
					item.Body = "<a class=\"ew-action ew-copy\" title=\"" + copycaption + "\" data-caption=\"" + copycaption + "\" href=\"#\" onclick=\"return ew.modalDialogShow({lnk:this,url:'" + HtmlEncode(AppPath(CopyUrl)) + "'});\">" + Language.Phrase("ViewPageCopyLink") + "</a>";
				else
					item.Body = "<a class=\"ew-action ew-copy\" title=\"" + copycaption + "\" data-caption=\"" + copycaption + "\" href=\"" + HtmlEncode(AppPath(CopyUrl)) + "\">" + Language.Phrase("ViewPageCopyLink") + "</a>";
					item.Visible = (CopyUrl != "");

				// Delete
				item = option.Add("delete");
				if (IsModal) // Handle as inline delete
					item.Body = "<a onclick=\"return ew.confirmDelete(this);\" class=\"ew-action ew-delete\" title=\"" + HtmlTitle(Language.Phrase("ViewPageDeleteLink")) + "\" data-caption=\"" + HtmlTitle(Language.Phrase("ViewPageDeleteLink")) + "\" href=\"" + HtmlEncode(UrlAddQuery(AppPath(DeleteUrl), "action=1")) + "\">" + Language.Phrase("ViewPageDeleteLink") + "</a>";
				else
					item.Body = "<a class=\"ew-action ew-delete\" title=\"" + HtmlTitle(Language.Phrase("ViewPageDeleteLink")) + "\" data-caption=\"" + HtmlTitle(Language.Phrase("ViewPageDeleteLink")) + "\" href=\"" + HtmlEncode(AppPath(DeleteUrl)) + "\">" + Language.Phrase("ViewPageDeleteLink") + "</a>";
				item.Visible = (DeleteUrl != "");

				// Set up action default
				option = options["action"];
				option.DropDownButtonPhrase = Language.Phrase("ButtonActions");
				option.UseDropDownButton = true;
				option.UseButtonGroup = true;
				item = option.Add(option.GroupOptionName);
				item.Body = "";
				item.Visible = false;
			}
			#pragma warning restore 168, 219

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
			#pragma warning disable 1998

			// Render row values based on field settings
			public async Task RenderRow() {
				SetupOtherOptions();

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
				}

				// Call Row Rendered event
				if (RowType != Config.RowTypeAggregateInit)
					Row_Rendered();
			}
			#pragma warning restore 1998

			// Save data to memory cache
			public void SetCache<T>(string key, T value, int span) => Cache.Set<T>(key, value, new MemoryCacheEntryOptions()
				.SetSlidingExpiration(TimeSpan.FromMilliseconds(span))); // Keep in cache for this time, reset time if accessed

			// Gete data from memory cache
			public void GetCache<T>(string key) => Cache.Get<T>(key);

			// Get export HTML tag
			protected string GetExportTag(string type, bool custom = false) {
				if (SameText(type, "excel")) {
					if (custom)
						return "<a href=\"#\" class=\"ew-export-link ew-excel\" title=\"" + HtmlEncode(Language.Phrase("ExportToExcelText")) + "\" data-caption=\"" + HtmlEncode(Language.Phrase("ExportToExcelText")) + "\" onclick=\"return ew.export(document.fAccountsview, '" + ExportExcelUrl + "', 'excel', true);\">" + Language.Phrase("ExportToExcel") + "</a>";
					else
						return "<a href=\"" + ExportExcelUrl + "\" class=\"ew-export-link ew-excel\" title=\"" + HtmlEncode(Language.Phrase("ExportToExcelText")) + "\" data-caption=\"" + HtmlEncode(Language.Phrase("ExportToExcelText")) + "\">" + Language.Phrase("ExportToExcel") + "</a>";
				} else if (SameText(type, "word")) {
					if (custom)
						return "<a href=\"#\" class=\"ew-export-link ew-word\" title=\"" + HtmlEncode(Language.Phrase("ExportToWordText")) + "\" data-caption=\"" + HtmlEncode(Language.Phrase("ExportToWordText")) + "\" onclick=\"return ew.export(document.fAccountsview, '" + ExportWordUrl + "', 'word', true);\">" + Language.Phrase("ExportToWord") + "</a>";
					else
						return "<a href=\"" + ExportWordUrl + "\" class=\"ew-export-link ew-word\" title=\"" + HtmlEncode(Language.Phrase("ExportToWordText")) + "\" data-caption=\"" + HtmlEncode(Language.Phrase("ExportToWordText")) + "\">" + Language.Phrase("ExportToWord") + "</a>";
				} else if (SameText(type, "pdf")) {
					if (custom)
						return "<a href=\"#\" class=\"ew-export-link ew-pdf\" title=\"" + HtmlEncode(Language.Phrase("ExportToPDFText")) + "\" data-caption=\"" + HtmlEncode(Language.Phrase("ExportToPDFText")) + "\" onclick=\"return ew.export(document.fAccountsview, '" + ExportPdfUrl + "', 'pdf', true);\">" + Language.Phrase("ExportToPDF") + "</a>";
					else
						return "<a href=\"" + ExportPdfUrl + "\" class=\"ew-export-link ew-pdf\" title=\"" + HtmlEncode(Language.Phrase("ExportToPDFText")) + "\" data-caption=\"" + HtmlEncode(Language.Phrase("ExportToPDFText")) + "\">" + Language.Phrase("ExportToPDF") + "</a>";
				} else if (SameText(type, "html")) {
					return "<a href=\"" + ExportHtmlUrl + "\" class=\"ew-export-link ew-html\" title=\"" + HtmlEncode(Language.Phrase("ExportToHtmlText")) + "\" data-caption=\"" + HtmlEncode(Language.Phrase("ExportToHtmlText")) + "\">" + Language.Phrase("ExportToHtml") + "</a>";
				} else if (SameText(type, "xml")) {
					return "<a href=\"" + ExportXmlUrl + "\" class=\"ew-export-link ew-xml\" title=\"" + HtmlEncode(Language.Phrase("ExportToXmlText")) + "\" data-caption=\"" + HtmlEncode(Language.Phrase("ExportToXmlText")) + "\">" + Language.Phrase("ExportToXml") + "</a>";
				} else if (SameText(type, "csv")) {
					return "<a href=\"" + ExportCsvUrl + "\" class=\"ew-export-link ew-csv\" title=\"" + HtmlEncode(Language.Phrase("ExportToCsvText")) + "\" data-caption=\"" + HtmlEncode(Language.Phrase("ExportToCsvText")) + "\">" + Language.Phrase("ExportToCsv") + "</a>";
				} else if (SameText(type, "email")) {
					string url = custom ? ",url:'" + AppPath(PageUrl) + "export=email&custom=1'" : "";
					return "<button id=\"emf_Accounts\" class=\"ew-export-link ew-email\" title=\"" + Language.Phrase("ExportToEmailText") + "\" data-caption=\"" + Language.Phrase("ExportToEmailText") + "\" onclick=\"ew.emailDialogShow({lnk:'emf_Accounts', hdr:ew.language.phrase('ExportToEmailText'), f:document.fAccountsview, key:" + ConvertToJsonAttribute(RecordKeys) + ", sel:false" + url + "});\">" + Language.Phrase("ExportToEmail") + "</button>";
				} else if (SameText(type, "print")) {
					return "<a href=\"" + ExportPrintUrl + "\" class=\"ew-export-link ew-print\" title=\"" + HtmlEncode(Language.Phrase("PrinterFriendlyText")) + "\" data-caption=\"" + HtmlEncode(Language.Phrase("PrinterFriendlyText")) + "\">" + Language.Phrase("PrinterFriendly") + "</a>";
				}
				return "";
			}

			// Set up export options
			protected void SetupExportOptions() {
				ListOption item;

				// Printer friendly
				item = ExportOptions.Add("print");
				item.Body = GetExportTag("print");
				item.Visible = true;

				// Export to Excel
				item = ExportOptions.Add("excel");
				item.Body = GetExportTag("excel");
				item.Visible = true;

				// Export to Word
				item = ExportOptions.Add("word");
				item.Body = GetExportTag("word");
				item.Visible = true;

				// Export to HTML
				item = ExportOptions.Add("html");
				item.Body = GetExportTag("html");
				item.Visible = true;

				// Export to XML
				item = ExportOptions.Add("xml");
				item.Body = GetExportTag("xml");
				item.Visible = true;

				// Export to CSV
				item = ExportOptions.Add("csv");
				item.Body = GetExportTag("csv");
				item.Visible = true;

				// Export to PDF
				item = ExportOptions.Add("pdf");
				item.Body = GetExportTag("pdf");
				item.Visible = true;

				// Export to Email
				item = ExportOptions.Add("email");
				item.Body = GetExportTag("email");
				item.Visible = true;

				// Drop down button for export
				ExportOptions.UseButtonGroup = true;
				ExportOptions.UseDropDownButton = true;
				if (ExportOptions.UseButtonGroup && IsMobile())
					ExportOptions.UseDropDownButton = true;
				ExportOptions.DropDownButtonPhrase = Language.Phrase("ButtonExport");

				// Add group option item
				item = ExportOptions.Add(ExportOptions.GroupOptionName);
				item.Body = "";
				item.Visible = false;

				// Hide options for export
				if (IsExport())
					ExportOptions.HideAllOptions();
			}
			#pragma warning disable 168

			/// <summary>
			/// Export data
			/// </summary>
			public async Task<IActionResult> ExportData() {
				var selectLimit = false; // View page

				// Load recordset // DN
				DbDataReader rs = null;
				if (!selectLimit) { // View page
					if (Recordset == null) {
						Recordset = await LoadRecordset();
						await Recordset.ReadAsync(); // Move to the start record
					}
					rs = Recordset;
				}
				if (TotalRecords < 0)
					TotalRecords = await ListRecordCount();
				StartRecord = 1;
				SetupStartRecord(); // Set up start record position

				// Set the last record to display
				if (DisplayRecords < 0) {
					StopRecord = TotalRecords;
				} else {
					StopRecord = StartRecord + DisplayRecords - 1;
				}
				var doc = CreateExportDocument(this, "v");
				ExportDoc = doc;
				if (doc == null) { // DN
					FailureMessage = Language.Phrase("ExportClassNotFound"); // Export class not found
					return Controller.Content(GetMessage(), "text/html");
				}

				// Call Page Exporting server event
				ExportDoc.ExportCustom = !Page_Exporting();

				// Page header
				string header = PageHeader;
				Page_DataRendering(ref header);
				doc.Text.Append(header);

				// Export
				await ExportDocument(doc, rs, StartRecord, StopRecord, "view");

				// Page footer
				string footer = PageFooter;
				Page_DataRendered(ref footer);
				doc.Text.Append(footer);

				// Close recordset
				using (rs) {} // Dispose

				// Call Page Exported server event
				Page_Exported();

				// Export header and footer
				await doc.ExportHeaderAndFooter();

				// Log debug message if enabled // DN
				if (Config.Debug)
					Log(GetDebugMessage());

				// Clean output buffer
				Response.Clear();

				// Output data
				if (IsExport("email")) {
					return Controller.Content(await ExportEmail(doc), "text/html");
				}
				return doc.Export();
			}
			#pragma warning restore 168

			// Export email
			protected async Task<string> ExportEmail(object content) {
				string emailContent = Convert.ToString(content);
				string sender = Post("sender");
				string recipient = Post("recipient");
				string cc = Post("cc");
				string bcc = Post("bcc");
				string subject = Post("subject");
				string emailSubject = RemoveXss(subject);
				string emailMessage = Post("message");

				// Check sender
				if (sender == "")
					return "<p class=\"text-danger\">" + Language.Phrase("EnterSenderEmail") + "</p>";
				if (!CheckEmail(sender))
					return "<p class=\"text-danger\">" + Language.Phrase("EnterProperSenderEmail") + "</p>";

				// Check recipient
				if (!CheckEmail(recipient, Config.MaxEmailRecipient))
					return "<p class=\"text-danger\">" + Language.Phrase("EnterProperRecipientEmail") + "</p>";

				// Check cc
				if (!CheckEmail(cc, Config.MaxEmailRecipient))
					return "<p class=\"text-danger\">" + Language.Phrase("EnterProperCcEmail") + "</p>";

				// Check bcc
				if (!CheckEmail(bcc, Config.MaxEmailRecipient))
					return "<p class=\"text-danger\">" + Language.Phrase("EnterProperBccEmail") + "</p>";

				// Check email sent count
				if (Session[Config.ExportEmailCounter] == null)
					Session.SetInt(Config.ExportEmailCounter, 0); // DN
				if (Session.GetInt(Config.ExportEmailCounter) > Config.MaxEmailSentCount)
					return "<p class=\"text-danger\">" + Language.Phrase("ExceedMaxEmailExport") + "</p>";

				// Send email
				var email = new Email();
				email.Sender = sender; // Sender
				email.Recipient = recipient; // Recipient
				email.Cc = cc; // cc
				email.Bcc = bcc; // bcc
				email.Subject = emailSubject; // Subject
				email.Format = "html";
				email.Charset = Config.EmailCharset;
				if (!Empty(emailMessage))
					emailMessage = RemoveXss(emailMessage) + "<br><br>";
				foreach (string tmpimage in TempImages)
					email.AddEmbeddedImage(tmpimage);
				email.Content = emailMessage + await CleanEmailContent(emailContent); // Content
				bool emailSent = false;
				if (Email_Sending(email, new Dictionary<string, dynamic>(StringComparer.OrdinalIgnoreCase)))
					emailSent = await email.SendAsync();
				DeleteTempImages();

				// Check email sent status
				if (emailSent) {

					// Update email sent count
					Session.SetInt(Config.ExportEmailCounter, Session.GetInt(Config.ExportEmailCounter) + 1);

					// Sent email success
					return "<p class=\"text-success\">" + Language.Phrase("SendEmailSuccess") + "</p>"; // Set up success message
				} else {

					// Sent email failure
					return "<p class=\"text-danger\">" + email.SendError + "</p>";
				}
			}

			// Set up Breadcrumb
			protected void SetupBreadcrumb() {
				var breadcrumb = new Breadcrumb();
				string url = CurrentUrl();
				breadcrumb.Add("list", TableVar, AppPath(AddMasterUrl("Accountslist")), "", TableVar, true);
				string pageId = "view";
				breadcrumb.Add("view", pageId, url);
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

			// Page Exporting event
			// ExportDoc = export document object
			public virtual bool Page_Exporting() {

				//ExportDoc.Text.Append("<p>" + "my header" + "</p>"); // Export header
				//return false; // Return false to skip default export and use Row_Export event

				return true; // Return true to use default export and skip Row_Export event
			}

			// Row Export event
			// ExportDoc = export document object
			public virtual void Row_Export(DbDataReader rs) {

				//ExportDoc.Text.Append("<div>" + MyField.ViewValue +"</div>"); // Build HTML with field value: rs["MyField"] or MyField.ViewValue
			}

			// Page Exported event
			// ExportDoc = export document object
			public virtual void Page_Exported() {

				//ExportDoc.Text.Append("my footer"); // Export footer
				//Log("Text: {Text}", ExportDoc.Text);

			}
		} // End page class
	} // End Partial class
} // End namespace