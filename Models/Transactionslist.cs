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
		/// Transactions_List
		/// </summary>
		public static _Transactions_List Transactions_List {
			get => HttpData.Get<_Transactions_List>("Transactions_List");
			set => HttpData["Transactions_List"] = value;
		}

		/// <summary>
		/// Page class for Transactions
		/// </summary>
		public class _Transactions_List : _Transactions_ListBase
		{

			// Construtor
			public _Transactions_List(Controller controller = null) : base(controller) {
			}
		}

		/// <summary>
		/// Page base class
		/// </summary>
		public class _Transactions_ListBase : _Transactions, IAspNetMakerPage
		{

			// Page ID
			public string PageID = "list";

			// Project ID
			public string ProjectID = "{31239A93-3DBA-4D73-A306-C1D3BFE7959E}";

			// Table name
			public string TableName { get; set; } = "Transactions";

			// Page object name
			public string PageObjName = "Transactions_List";

			// Grid form hidden field names
			public string FormName = "fTransactionslist";

			public string FormActionName = "k_action";

			public string FormKeyName = "k_key";

			public string FormOldKeyName = "k_oldkey";

			public string FormBlankRowName = "k_blankrow";

			public string FormKeyCountName = "key_count";

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
			public _Transactions_ListBase(Controller controller = null) { // DN
				if (controller != null)
					Controller = controller;

				// Initialize
				CurrentPage = this;

				// Language object
				Language ??= new Lang();

				// Table object (Transactions)
				if (Transactions == null || Transactions is _Transactions)
					Transactions = this;

				// Initialize URLs
				ExportPrintUrl = PageUrl + "export=print";
				ExportExcelUrl = PageUrl + "export=excel";
				ExportWordUrl = PageUrl + "export=word";
				ExportPdfUrl = PageUrl + "export=pdf";
				ExportHtmlUrl = PageUrl + "export=html";
				ExportXmlUrl = PageUrl + "export=xml";
				ExportCsvUrl = PageUrl + "export=csv";
				AddUrl = "Transactionsadd";
				InlineAddUrl = PageUrl + "action=add";
				GridAddUrl = PageUrl + "action=gridadd";
				GridEditUrl = PageUrl + "action=gridedit";
				MultiDeleteUrl = "Transactionsdelete";
				MultiUpdateUrl = "Transactionsupdate";

				// Start time
				StartTime = Environment.TickCount;

				// Debug message
				LoadDebugMessage();

				// Open connection
				Conn = Connection; // DN

				// List options
				ListOptions = new ListOptions { TableVar = TableVar };

				// Export options
				ExportOptions = new ListOptions { Tag = "div", TagClassName = "ew-export-option" };

				// Import options
				ImportOptions = new ListOptions { Tag = "div", TagClassName = "ew-import-option" };

				// Other options
				OtherOptions["addedit"] = new ListOptions { Tag = "div", TagClassName = "ew-add-edit-option" };

				// Other options
				OtherOptions["detail"] = new ListOptions { Tag = "div", TagClassName = "ew-detail-option" };
				OtherOptions["action"] = new ListOptions { Tag = "div", TagClassName = "ew-action-option" };

				// Filter options
				FilterOptions = new ListOptions { Tag = "div", TagClassName = "ew-filter-option fTransactionslistsrch" };

				// List actions
				ListActions = new ListActions();
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
						SaveDebugMessage();
						return Controller.LocalRedirect(AppPath(url));
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

			// Class properties
			private Pager _pager; // DN

			public ListOptions ListOptions; // List options

			public ListOptions ExportOptions; // Export options

			public ListOptions SearchOptions; // Search options

			public ListOptionsDictionary OtherOptions = new ListOptionsDictionary(); // Other options

			public ListOptions FilterOptions; // Filter options

			public ListOptions ImportOptions; // Import options

			public ListActions ListActions; // List actions

			public int SelectedCount = 0;

			public int SelectedIndex = 0;

			public int DisplayRecords = 10; // Number of display records

			public int StartRecord;

			public int StopRecord;

			public int TotalRecords = -1;

			public int RecordRange = 10;

			public string PageSizes = "10,20,50,-1"; // Page sizes (comma separated)

			public string DefaultSearchWhere = ""; // Default search WHERE clause

			public string SearchWhere = ""; // Search WHERE clause

			public string SearchPanelClass = "ew-search-panel collapse show"; // Search panel class

			public int SearchRowCount = 0; // For extended search

			public int SearchColumnCount = 0; // For extended search

			public int SearchFieldsPerRow = 1; // For extended search

			public int RecordCount = 0; // Record count

			public int EditRowCount;

			public int StartRowCount = 1;

			public List<dynamic> Attributes = new List<dynamic>(); // Row attributes and cell attributes

			public object RowIndex = 0; // Row index

			public int KeyCount = 0; // Key count

			public string RowAction = ""; // Row action

			public string RowOldKey = ""; // Row old key (for copy)

			public string MultiColumnClass = "col-sm";

			public string MultiColumnEditClass = "w-100";

			public int MultiColumnCount = 12;

			public int MultiColumnEditCount = 12;

			public string DbMasterFilter = ""; // Master filter

			public string DbDetailFilter = ""; // Detail filter

			public bool MasterRecordExists;

			public string MultiSelectKey = "";

			public bool RestoreSearch = false;

			public SubPages DetailPages;

			public DbDataReader Recordset;

			public DbDataReader OldRecordset;

			// Pager
			public Pager Pager {
				get {
					_pager ??= new PrevNextPager(StartRecord, RecordsPerPage, TotalRecords, PageSizes, RecordRange, AutoHidePager, AutoHidePageSizeSelector);
					return _pager;
				}
			}

			/// <summary>
			/// Page run
			/// </summary>
			/// <returns>Page result</returns>
			public async Task<IActionResult> Run() {

				// Header
				Header(Config.Cache);

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

				// Get grid add count
				int gridaddcnt = Get<int>(Config.TableGridAddRowCount);
				if (gridaddcnt > 0)
					GridAddRowCount = gridaddcnt;

				// Set up list options
				await SetupListOptions();

				// Setup export options
				SetupExportOptions();
				TransactionID.SetVisibility();
				TransactionDate.SetVisibility();
				AccountID.SetVisibility();
				Description.Visible = false;
				Debit.SetVisibility();
				Credit.SetVisibility();
				HideFieldsForAddEdit();

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

				// Setup other options
				SetupOtherOptions();

				// Set up custom action (compatible with old version)
				ListActions.Add(CustomActions);

				// Show checkbox column if multiple action
				if (ListActions.Items.Any(kvp => kvp.Value.Select == Config.ActionMultiple && kvp.Value.Allowed))
					ListOptions["checkbox"].Visible = true;

				// Set up lookup cache
				await SetupLookupOptions(AccountID);

				// Search filters
				string filter = "";

				// Get command
				Command = Get("cmd").ToLower();
				if (IsPageRequest) { // Validate request

					// Process list action first
					var result = await ProcessListAction();
					if (result != null) // Ajax request
						return result;

					// Set up records per page
					SetupDisplayRecs();

					// Handle reset command
					ResetCommand();

					// Set up Breadcrumb
					if (!IsExport())
						SetupBreadcrumb();

					// Hide list options
					if (IsExport()) {
						ListOptions.HideAllOptions(new List<string> {"sequence"});
						ListOptions.UseDropDownButton = false; // Disable drop down button
						ListOptions.UseButtonGroup = false; // Disable button group
					} else if (IsGridAdd || IsGridEdit) {
						ListOptions.HideAllOptions();
						ListOptions.UseDropDownButton = false; // Disable drop down button
						ListOptions.UseButtonGroup = false; // Disable button group
					}

					// Hide options
					if (IsExport() || !Empty(CurrentAction)) {
						ExportOptions.HideAllOptions();
						FilterOptions.HideAllOptions();
						ImportOptions.HideAllOptions();
					}

					// Hide other options
					if (IsExport()) {
						foreach (var (key, value) in OtherOptions)
							value.HideAllOptions();
					}

					// Set up sorting order
					SetupSortOrder();
				}

				// Restore display records
				if (Command != "json" && (RecordsPerPage == -1 || RecordsPerPage > 0)) {
					DisplayRecords = RecordsPerPage; // Restore from Session
				} else {
					DisplayRecords = 10; // Load default
					RecordsPerPage = DisplayRecords; // Save default to session
				}

				// Load Sorting Order
				if (Command != "json")
					LoadSortOrder();

				// Build filter
				filter = "";
				AddFilter(ref filter, DbDetailFilter);
				AddFilter(ref filter, SearchWhere);

				// Set up filter
				if (Command == "json") {
					UseSessionForListSql = false; // Do not use session for ListSql
					CurrentFilter = filter;
				} else {
					SessionWhere = filter;
					CurrentFilter = "";
				}

				// Export data only // DN
				if (Empty(CustomExport) && Config.Export.ContainsKey(Export)) {
					return await ExportData();
				} else if (!Empty(CustomExport) && CustomExport == Export && Config.Export.ContainsKey(CustomExport)) {
					return await ExportView();
				}
				if (IsGridAdd) {
					CurrentFilter = "0=1";
					StartRecord = 1;
					DisplayRecords = GridAddRowCount;
					TotalRecords = DisplayRecords;
					StopRecord = DisplayRecords;
				} else {
					TotalRecords = await ListRecordCount();
					StopRecord = DisplayRecords;
					StartRecord = 1;
				if (DisplayRecords <= 0 || (IsExport() && ExportAll)) // Display all records
					DisplayRecords = TotalRecords;
				if (!(IsExport() && ExportAll)) // Set up start record position
					SetupStartRecord();

				// Recordset
				bool selectLimit = UseSelectLimit;
				if (selectLimit)
					Recordset = await LoadRecordset(StartRecord - 1, DisplayRecords);

				// Set no record found message
				if (Empty(CurrentAction) && TotalRecords == 0) {
					if (SearchWhere == "0=101")
						WarningMessage = Language.Phrase("EnterSearchCriteria");
					else
						WarningMessage = Language.Phrase("NoRecord");
				}
				}

				// Search options
				SetupSearchOptions();

				// Normal return
				if (IsApi()) {
					if (!Connection.SelectOffset) // DN
						for (var i = 1; i <= StartRecord - 1; i++) // Move to first record
							await Recordset.ReadAsync();
					using (Recordset) {
						return Controller.Json(new Dictionary<string, object> { {"success", true}, {TableVar, await GetRecordsFromRecordset(Recordset)}, {"totalRecordCount", TotalRecords}, {"version", Config.ProductVersion} });
					}
				}
				return PageResult();
			}

			// Set up number of records displayed per page
			protected void SetupDisplayRecs() {
				string wrk = Get(Config.TableRecordsPerPage);
				if (!Empty(wrk)) {
					if (IsNumeric(wrk)) {
						DisplayRecords = ConvertToInt(wrk);
					} else {
						if (SameText(wrk, "all")) { // Display all records
							DisplayRecords = -1;
						} else {
							DisplayRecords = 10; // Non-numeric, load default
						}
					}
					RecordsPerPage = DisplayRecords; // Save to Session

					// Reset start position
					StartRecord = 1;
					StartRecordNumber = StartRecord;
				}
			}

			// Build filter for all keys
			protected string BuildKeyFilter() {
				string wrkFilter = "";

				// Update row index and get row key
				int rowindex = 1;
				CurrentForm.Index = rowindex;
				string thisKey = CurrentForm.GetValue(FormKeyName);
				while (!Empty(thisKey)) {
					if (SetupKeyValues(thisKey)) {
						string filter = GetRecordFilter();
						if (!Empty(wrkFilter))
							wrkFilter += " OR ";
						wrkFilter += filter;
					} else {
						wrkFilter = "0=1";
						break;
					}

					// Update row index and get row key
					rowindex++; // next row
					CurrentForm.Index = rowindex;
					thisKey = CurrentForm.GetValue(FormKeyName);
				}
				return wrkFilter;
			}

			// Set up key values
			protected bool SetupKeyValues(string key) {
				var keyFields = key.Split(Convert.ToChar(Config.CompositeKeySeparator));
				if (keyFields.Length >= 1) {
					TransactionID.OldValue = keyFields[0];
					if (!IsNumeric(TransactionID.OldValue))
						return false;
				}
				return true;
			}

			// Check if empty row
			public bool EmptyRow() => false;

			// Set up sort parameters
			protected void SetupSortOrder() {

				// Check for "order" parameter
				if (Get("order", out StringValues sv)) {
					CurrentOrder = sv;
					CurrentOrderType = Get("ordertype");
					UpdateSort(TransactionID); // TransactionID
					UpdateSort(TransactionDate); // TransactionDate
					UpdateSort(AccountID); // AccountID
					UpdateSort(Debit); // Debit
					UpdateSort(Credit); // Credit
					StartRecordNumber = 1; // Reset start position
				}
			}

			// Load sort order parameters
			protected void LoadSortOrder() {
				string orderBy = SessionOrderBy; // Get Order By from Session
				if (Empty(orderBy)) {
					if (!Empty(SqlOrderBy)) {
						orderBy = SqlOrderBy;
						SessionOrderBy = orderBy;
					}
				}
			}

			// Reset command
			// cmd=reset (Reset search parameters)
			// cmd=resetall (Reset search and master/detail parameters)
			// cmd=resetsort (Reset sort parameters)

			protected void ResetCommand() {

				// Get reset cmd
				if (Command.ToLower().StartsWith("reset")) {

					// Reset sorting order
					if (SameText(Command, "resetsort")) {
						string orderBy = "";
						SessionOrderBy = orderBy;
						TransactionID.Sort = "";
						TransactionDate.Sort = "";
						AccountID.Sort = "";
						Debit.Sort = "";
						Credit.Sort = "";
					}

					// Reset start position
					StartRecord = 1;
					StartRecordNumber = StartRecord;
				}
			}
			#pragma warning disable 1998

			// Set up list options
			protected async Task SetupListOptions() {
				ListOption item;

				// Add group option item
				item = ListOptions.Add(ListOptions.GroupOptionName);
				item.Body = "";
				item.OnLeft = true;
				item.Visible = false;

				// "view"
				item = ListOptions.Add("view");
				item.CssClass = "text-nowrap";
				item.Visible = true;
				item.OnLeft = true;

				// "edit"
				item = ListOptions.Add("edit");
				item.CssClass = "text-nowrap";
				item.Visible = true;
				item.OnLeft = true;

				// "copy"
				item = ListOptions.Add("copy");
				item.CssClass = "text-nowrap";
				item.Visible = true;
				item.OnLeft = true;

				// List actions
				item = ListOptions.Add("listactions");
				item.CssClass = "text-nowrap";
				item.OnLeft = true;
				item.Visible = false;
				item.ShowInButtonGroup = false;
				item.ShowInDropDown = false;

				// "checkbox"
				item = ListOptions.Add("checkbox");
				item.CssStyle = "white-space: nowrap; text-align: center; vertical-align: middle; margin: 0px;";
				item.Visible = true;
				item.OnLeft = true;
				item.Header = "<div class=\"custom-control custom-checkbox d-inline-block\"><input type=\"checkbox\" name=\"key\" id=\"key\" class=\"custom-control-input\" onclick=\"ew.selectAllKey(this);\"><label class=\"custom-control-label\" for=\"key\"></label></div>";
				item.MoveTo(0);
				item.ShowInDropDown = false;
				item.ShowInButtonGroup = false;

				// Drop down button for ListOptions
				ListOptions.UseDropDownButton = true;
				ListOptions.DropDownButtonPhrase = Language.Phrase("ButtonListOptions");
				ListOptions.UseButtonGroup = false;
				if (ListOptions.UseButtonGroup && IsMobile())
					ListOptions.UseDropDownButton = true;
				ListOptions.ButtonClass = ""; // Class for button group

				// Call ListOptions_Load event
				ListOptions_Load();
				SetupListOptionsExt();
				item = ListOptions[ListOptions.GroupOptionName];
				item.Visible = ListOptions.GroupOptionVisible;
			}
			#pragma warning restore 1998

			// Render list options
			#pragma warning disable 168, 219, 1998

			public async Task RenderListOptions() {
				ListOption listOption;
				var isVisible = false; // DN
				ListOptions.LoadDefault();

				// Call ListOptions_Rendering event
				ListOptions_Rendering();

				// "view"
				listOption = ListOptions["view"];
				string viewcaption = HtmlTitle(Language.Phrase("ViewLink"));
				isVisible = true;
				if (isVisible) {
					listOption.Body = "<a class=\"ew-row-link ew-view\" title=\"" + viewcaption + "\" data-caption=\"" + viewcaption + "\" href=\"" + HtmlEncode(AppPath(ViewUrl)) + "\">" + Language.Phrase("ViewLink") + "</a>";
				} else {
					listOption.Body = "";
				}

				// "edit"
				listOption = ListOptions["edit"];
				string editcaption = HtmlTitle(Language.Phrase("EditLink"));
				isVisible = true;
				if (isVisible) {
					listOption.Body = "<a class=\"ew-row-link ew-edit\" title=\"" + editcaption + "\" data-caption=\"" + editcaption + "\" href=\"" + HtmlEncode(AppPath(EditUrl)) + "\">" + Language.Phrase("EditLink") + "</a>";
				} else {
					listOption.Body = "";
				}

				// "copy"
				listOption = ListOptions["copy"];
				string copycaption = HtmlTitle(Language.Phrase("CopyLink"));
				isVisible = true;
				if (isVisible) {
					listOption.Body = "<a class=\"ew-row-link ew-copy\" title=\"" + copycaption + "\" data-caption=\"" + copycaption + "\" href=\"" + HtmlEncode(AppPath(CopyUrl)) + "\">" + Language.Phrase("CopyLink") + "</a>";
				} else {
					listOption.Body = "";
				}

				// Set up list action buttons
				listOption = ListOptions["listactions"];
				if (listOption != null && !IsExport() && CurrentAction == "") {
					string body = "";
					var links = new List<string>();
					foreach (var (key, act) in ListActions.Items) {
						if (act.Select == Config.ActionSingle && act.Allowed) {
							var action = act.Action;
							string caption = act.Caption;
							var icon = (act.Icon != "") ? "<i class=\"" + HtmlEncode(act.Icon.Replace(" ew-icon", "")) + "\" data-caption=\"" + HtmlTitle(caption) + "\"></i> " : "";
							links.Add("<li><a class=\"dropdown-item ew-action ew-list-action\" data-action=\"" + HtmlEncode(action) + "\" data-caption=\"" + HtmlTitle(caption) + "\" href=\"#\" onclick=\"return ew.submitAction(event,jQuery.extend({key:" + KeyToJson() + "}," + act.ToJson(true) + "));\">" + icon + act.Caption + "</a></li>");
							if (links.Count == 1) // Single button
								body = "<a class=\"ew-action ew-list-action\" data-action=\"" + HtmlEncode(action) + "\" title=\"" + HtmlTitle(caption) + "\" data-caption=\"" + HtmlTitle(caption) + "\" href=\"#\" onclick=\"return ew.submitAction(event,jQuery.extend({key:" + KeyToJson() + "}," + act.ToJson(true) + "));\">" + Language.Phrase("ListActionButton") + "</a>";
						}
					}
					if (links.Count > 1) { // More than one buttons, use dropdown
						body = "<button class=\"dropdown-toggle btn btn-default ew-actions\" title=\"" + HtmlTitle(Language.Phrase("ListActionButton")) + "\" data-toggle=\"dropdown\">" + Language.Phrase("ListActionButton") + "</button>";
						string content = links.Aggregate("", (result, link) => result + "<li>" + link + "</li>");
						body += "<ul class=\"dropdown-menu" + (listOption.OnLeft ? "" : " dropdown-menu-right") + "\">" + content + "</ul>";
						body = "<div class=\"btn-group btn-group-sm\">" + body + "</div>";
					}
					if (links.Count > 0) {
						listOption.Body = body;
						listOption.Visible = true;
					}
				}

				// "checkbox"
				listOption = ListOptions["checkbox"];
				listOption.Body = "<div class=\"custom-control custom-checkbox d-inline-block\"><input type=\"checkbox\" id=\"key_m_" + RowCount + "\" name=\"key_m[]\" class=\"custom-control-input ew-multi-select\" value=\"" + HtmlEncode(TransactionID.CurrentValue) + "\" onclick=\"ew.clickMultiCheckbox(event);\"><label class=\"custom-control-label\" for=\"key_m_" + RowCount + "\"></label></div>";
				RenderListOptionsExt();

				// Call ListOptions_Rendered event
				ListOptions_Rendered();
			}

			// Set up other options
			protected void SetupOtherOptions() {
				ListOptions option;
				ListOption item;
				var options = OtherOptions;
				option = options["addedit"];

				// Add
				item = option.Add("add");
				string addcaption = HtmlTitle(Language.Phrase("AddLink"));
				item.Body = "<a class=\"ew-add-edit ew-add\" title=\"" + addcaption + "\" data-caption=\"" + addcaption + "\" href=\"" + HtmlEncode(AppPath(AddUrl)) + "\">" + Language.Phrase("AddLink") + "</a>";
				item.Visible = (AddUrl != "");
				option = options["action"];

				// Add multi delete
				item = option.Add("multidelete");
				item.Body = "<a class=\"ew-action ew-multi-delete\" title=\"" + HtmlTitle(Language.Phrase("DeleteSelectedLink")) + "\" data-caption=\"" + HtmlTitle(Language.Phrase("DeleteSelectedLink")) + "\" href=\"#\" onclick=\"return ew.submitAction(event, {f:document.fTransactionslist, url:'" + AppPath(MultiDeleteUrl) + "', data:{action:'show'}});return false;\">" + Language.Phrase("DeleteSelectedLink") + "</a>";
				item.Visible = (true);

				// Set up options default
				foreach (var (key, opt) in options) {
					opt.UseDropDownButton = true;
					opt.UseButtonGroup = true;
					opt.ButtonClass = ""; // Class for button group
					item = opt.Add(opt.GroupOptionName);
					item.Body = "";
					item.Visible = false;
				}
				options["addedit"].DropDownButtonPhrase = Language.Phrase("ButtonAddEdit");
				options["detail"].DropDownButtonPhrase = Language.Phrase("ButtonDetails");
				options["action"].DropDownButtonPhrase = Language.Phrase("ButtonActions");

				// Filter button
				item = FilterOptions.Add("savecurrentfilter");
				item.Body = "<a class=\"ew-save-filter\" data-form=\"fTransactionslistsrch\" href=\"#\">" + Language.Phrase("SaveCurrentFilter") + "</a>";
				item.Visible = false;
				item = FilterOptions.Add("deletefilter");
				item.Body = "<a class=\"ew-delete-filter\" data-form=\"fTransactionslistsrch\" href=\"#\">" + Language.Phrase("DeleteFilter") + "</a>";
				item.Visible = false;
				FilterOptions.UseDropDownButton = true;
				FilterOptions.UseButtonGroup = !FilterOptions.UseDropDownButton;
				FilterOptions.DropDownButtonPhrase = Language.Phrase("Filters");

				// Add group option item
				item = FilterOptions.Add(FilterOptions.GroupOptionName);
				item.Body = "";
				item.Visible = false;
			}

			// Render other options
			public void RenderOtherOptions() {
				ListOptions option;
				ListOption item;
				var options = OtherOptions;
					option = options["action"];

					// Set up list action buttons
					foreach (var (key, act) in ListActions.Items.Where(kvp => kvp.Value.Select == Config.ActionMultiple)) {
						item = option.Add("custom_" + act.Action);
						string caption = act.Caption;
						var icon = (act.Icon != "") ? "<i class=\"" + HtmlEncode(act.Icon) + "\" data-caption=\"" + HtmlEncode(caption) + "\"></i> " + caption : caption;
						item.Body = "<a class=\"ew-action ew-list-action\" title=\"" + HtmlEncode(caption) + "\" data-caption=\"" + HtmlEncode(caption) + "\" href=\"#\" onclick=\"return ew.submitAction(event,jQuery.extend({f:document.fTransactionslist}," + act.ToJson(true) + "));\">" + icon + "</a>";
						item.Visible = act.Allowed;
					}

					// Hide grid edit and other options
					if (TotalRecords <= 0) {
						option = options["addedit"];
						item = option["gridedit"];
						if (item != null)
							item.Visible = false;
						option = options["action"];
						option.HideAllOptions();
					}
			}

			// Process list action
			public async Task<IActionResult> ProcessListAction() {
				string filter = GetFilterFromRecordKeys();
				string userAction = Post("useraction");
				if (filter != "" && userAction != "") {

					// Check permission first
					var actionCaption = userAction;
					foreach (var (key, act) in ListActions.Items) {
						if (SameString(key, userAction)) {
							actionCaption = act.Caption;
							if (!act.Allowed) {
								string errmsg = Language.Phrase("CustomActionNotAllowed").Replace("%s", actionCaption);
								if (Post("ajax") == userAction) // Ajax
									return Controller.Content("<p class=\"text-danger\">" + errmsg + "</p>", "text/plain", Encoding.UTF8);
								else
									FailureMessage = errmsg;
								return null;
							}
						}
					}
					CurrentFilter = filter;
					string sql = CurrentSql;
					var rsuser = await Connection.GetRowsAsync(sql);
					CurrentAction = userAction;

					// Call row custom action event
					if (rsuser != null) {
						Connection.BeginTrans();
						bool processed = true;
						SelectedCount = rsuser.Count();
						SelectedIndex = 0;
						foreach (var row in rsuser) {
							SelectedIndex++;
							processed = Row_CustomAction(userAction, row);
							if (!processed)
								break;
						}
						if (processed) {
							Connection.CommitTrans(); // Commit the changes
							if (Empty(SuccessMessage))
								SuccessMessage = Language.Phrase("CustomActionCompleted").Replace("%s", actionCaption); // Set up success message
							} else {
								Connection.RollbackTrans(); // Rollback changes

							// Set up error message
							if (!Empty(SuccessMessage) || !Empty(FailureMessage)) {

								// Use the message, do nothing
							} else if (!Empty(CancelMessage)) {
								FailureMessage = CancelMessage;
								CancelMessage = "";
							} else {
								FailureMessage = Language.Phrase("CustomActionFailed").Replace("%s", actionCaption);
							}
						}
					}
					CurrentAction = ""; // Clear action
					if (Post("ajax") == userAction) { // Ajax
						if (ActionResult != null) // Action result set by Row_CustomAction // DN
							return ActionResult;
						string msg = "";
						if (SuccessMessage != "") {
							msg = "<p class=\"text-success\">" + SuccessMessage + "</p>";
							ClearSuccessMessage(); // Clear message
						}
						if (FailureMessage != "") {
							msg = "<p class=\"text-danger\">" + FailureMessage + "</p>";
							ClearFailureMessage(); // Clear message
						}
						if (!Empty(msg))
							return Controller.Content(msg, "text/plain", Encoding.UTF8);
					}
				}
				return null; // Not ajax request
			}

			// Set up list options (extended codes)
			protected void SetupListOptionsExt() {}

			// Render list options (extended codes)
			protected void RenderListOptionsExt() {}

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

					// Debit
					Debit.HrefValue = "";
					Debit.TooltipValue = "";

					// Credit
					Credit.HrefValue = "";
					Credit.TooltipValue = "";
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
						return "<a href=\"#\" class=\"ew-export-link ew-excel\" title=\"" + HtmlEncode(Language.Phrase("ExportToExcelText")) + "\" data-caption=\"" + HtmlEncode(Language.Phrase("ExportToExcelText")) + "\" onclick=\"return ew.export(document.fTransactionslist, '" + ExportExcelUrl + "', 'excel', true);\">" + Language.Phrase("ExportToExcel") + "</a>";
					else
						return "<a href=\"" + ExportExcelUrl + "\" class=\"ew-export-link ew-excel\" title=\"" + HtmlEncode(Language.Phrase("ExportToExcelText")) + "\" data-caption=\"" + HtmlEncode(Language.Phrase("ExportToExcelText")) + "\">" + Language.Phrase("ExportToExcel") + "</a>";
				} else if (SameText(type, "word")) {
					if (custom)
						return "<a href=\"#\" class=\"ew-export-link ew-word\" title=\"" + HtmlEncode(Language.Phrase("ExportToWordText")) + "\" data-caption=\"" + HtmlEncode(Language.Phrase("ExportToWordText")) + "\" onclick=\"return ew.export(document.fTransactionslist, '" + ExportWordUrl + "', 'word', true);\">" + Language.Phrase("ExportToWord") + "</a>";
					else
						return "<a href=\"" + ExportWordUrl + "\" class=\"ew-export-link ew-word\" title=\"" + HtmlEncode(Language.Phrase("ExportToWordText")) + "\" data-caption=\"" + HtmlEncode(Language.Phrase("ExportToWordText")) + "\">" + Language.Phrase("ExportToWord") + "</a>";
				} else if (SameText(type, "pdf")) {
					if (custom)
						return "<a href=\"#\" class=\"ew-export-link ew-pdf\" title=\"" + HtmlEncode(Language.Phrase("ExportToPDFText")) + "\" data-caption=\"" + HtmlEncode(Language.Phrase("ExportToPDFText")) + "\" onclick=\"return ew.export(document.fTransactionslist, '" + ExportPdfUrl + "', 'pdf', true);\">" + Language.Phrase("ExportToPDF") + "</a>";
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
					return "<button id=\"emf_Transactions\" class=\"ew-export-link ew-email\" title=\"" + Language.Phrase("ExportToEmailText") + "\" data-caption=\"" + Language.Phrase("ExportToEmailText") + "\" onclick=\"ew.emailDialogShow({lnk:'emf_Transactions', hdr:ew.language.phrase('ExportToEmailText'), f:document.fTransactionslist, sel:false" + url + "});\">" + Language.Phrase("ExportToEmail") + "</button>";
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
				item.Visible = false;

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
			}

			// Set up search options
			protected void SetupSearchOptions() {
				ListOption item;
				SearchOptions = new ListOptions();
				SearchOptions.Tag = "div";
				SearchOptions.TagClassName = "ew-search-option";

				// Button group for search
				SearchOptions.UseDropDownButton = false;
				SearchOptions.UseButtonGroup = true;
				SearchOptions.DropDownButtonPhrase = Language.Phrase("ButtonSearch");

				// Add group option item
				item = SearchOptions.Add(SearchOptions.GroupOptionName);
				item.Body = "";
				item.Visible = false;

				// Hide search options
				if (IsExport() || !Empty(CurrentAction))
					SearchOptions.HideAllOptions();
			}
			#pragma warning disable 168

			/// <summary>
			/// Export data
			/// </summary>
			public async Task<IActionResult> ExportData() {
				var selectLimit = true; // List page

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

				// Export all
				if (ExportAll) {
					DisplayRecords = TotalRecords;
					StopRecord = TotalRecords;
				} else { // Export one page only
					SetupStartRecord(); // Set up start record position

					// Set the last record to display
					if (DisplayRecords < 0) {
						StopRecord = TotalRecords;
					} else {
						StopRecord = StartRecord + DisplayRecords - 1;
					}
				}
				rs = await LoadRecordset(StartRecord - 1, (DisplayRecords <= 0) ? TotalRecords : DisplayRecords); // DN
				var doc = CreateExportDocument(this, "h");
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
				await ExportDocument(doc, rs, StartRecord, StopRecord, "");

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
				url = Regex.Replace(url, @"\?cmd=reset(all)?$", ""); // Remove cmd=reset / cmd=resetall
				breadcrumb.Add("list", TableVar, url, "", TableVar, true);
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

			// ListOptions Load event
			public virtual void ListOptions_Load() {

				// Example:
				//var opt = ListOptions.Add("new");
				//opt.Header = "xxx";
				//opt.OnLeft = true; // Link on left
				//opt.MoveTo(0); // Move to first column

			}

			// ListOptions Rendering event
			public virtual void ListOptions_Rendering() {

				//xxxGrid.DetailAdd = (...condition...); // Set to true or false conditionally
				//xxxGrid.DetailEdit = (...condition...); // Set to true or false conditionally
				//xxxGrid.DetailView = (...condition...); // Set to true or false conditionally

			}

			// ListOptions Rendered event
			public virtual void ListOptions_Rendered() {

				//Example:
				//ListOptions["new"].Body = "xxx";

			}

			// Row Custom Action event
			public virtual bool Row_CustomAction(string action, Dictionary<string, object> row) {

				// Return false to abort
				return true;
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

			// Grid Inserting event
			public virtual bool Grid_Inserting() {

				// Enter your code here
				// To reject grid insert, set return value to false

				return true;
			}

			// Grid Inserted event
			public virtual void Grid_Inserted(List<Dictionary<string, object>> rsnew) {

				//Log("Grid Inserted");
			}

			// Grid Updating event
			public virtual bool Grid_Updating(List<Dictionary<string, object>> rsold) {

				// Enter your code here
				// To reject grid update, set return value to false

				return true;
			}

			// Grid Updated event
			public virtual void Grid_Updated(List<Dictionary<string, object>> rsold, List<Dictionary<string, object>> rsnew) {

				//Log("Grid Updated");
			}
		} // End page class
	} // End Partial class
} // End namespace