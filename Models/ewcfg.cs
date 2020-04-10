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

		// Configuration
		public static partial class Config {

			/// <summary>
			/// Static constructor
			/// </summary>

			static Config()
			{

				// Config Init event
				Config_Init();
			}

			// Config Init
			// Config Init event
			public static void Config_Init() {

				// Enter your code here
			}

			// Debug
			public static bool Debug { get; set; } = false;

			// Product version
			public const string ProductVersion = "17.0.7";

			// Project
			public const string ProjectNamespace = "SMART";

			public const string ProjectClassName = "SMART.Models.SMARTBANK"; // DN

			public static string PathDelimiter = Convert.ToString(Path.DirectorySeparatorChar); // Physical path delimiter // DN

			public static short UnformatYear = 50; // Unformat year

			public const string ProjectName = "SMARTBANK"; // Project name

			public static string AreaName { get; set; } = ""; // Area name // DN

			public static string ControllerName { get; set; } = "Home"; // Controller name // DN

			public const string ProjectId = "{31239A93-3DBA-4D73-A306-C1D3BFE7959E}"; // Project ID (GUID)

			public static string RandomKey = "Fiq7MeMaAJ9K8kE9"; // Random key for encryption

			public static string EncryptionKey = ""; // Encryption key for data protection

			public static string ProjectStylesheetFilename = "css/SMARTBANK.css"; // Project stylesheet file name (relative to wwwroot)

			public static string Charset = "utf-8"; // Project charset

			public static string EmailCharset = Charset; // Email charset

			public static string EmailKeywordSeparator = ""; // Email keyword separator

			public static string CompositeKeySeparator = ","; // Composite key separator

			public static bool HighlightCompare { get; set; } = true; // Case-insensitive

			public static int FontSize = 14;

			public static bool UseFontAwesome4 = false;

			public static bool Cache = false; // Cache // DN

			public static bool LazyLoad = true; // Lazy loading of images

			public static string RelatedProjectId = "";

			public static bool DeleteUploadFiles = true; // Delete uploaded file on deleting record

			public static string FileNotFound = "/9j/4AAQSkZJRgABAQAAAQABAAD/7QAuUGhvdG9zaG9wIDMuMAA4QklNBAQAAAAAABIcAigADEZpbGVOb3RGb3VuZAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wgARCAABAAEDAREAAhEBAxEB/8QAFAABAAAAAAAAAAAAAAAAAAAACP/EABQBAQAAAAAAAAAAAAAAAAAAAAD/2gAMAwEAAhADEAAAAD+f/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPwB//8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAgBAgEBPwB//8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAgBAwEBPwB//9k="; // 1x1 jpeg with IPTC data "2#040"="FileNotFound"

			public static string BodyClass = "hold-transition layout-fixed";

			public static string SidebarClass = "main-sidebar sidebar-dark-danger";

			public static string NavbarClass = "main-header navbar navbar-expand navbar-danger navbar-dark";

			// External JavaScripts
			public static List<string> JavaScriptFiles = new List<string> {
			};

			// External StyleSheets
			public static List<string> StylesheetFiles = new List<string> {
			};

			// Authentication configuration for Google/Facebook
			public static Dictionary<string, AuthenticationProvider> Authentications = new Dictionary<string, AuthenticationProvider> {
				{"Google", new AuthenticationProvider {
					Enabled = false,
					Id = Configuration["Google:Id"],
					Color = "danger",
					Secret = Configuration["Google:Secret"]
				}},
				{"Facebook", new AuthenticationProvider {
					Enabled = false,
					Id = Configuration["Facebook:Id"],
					Color = "primary",
					Secret = Configuration["Facebook:Secret"]
				}}
			}; // DN

			// Database time zone
			// Difference to Greenwich time (GMT) with colon between hours and minutes, e.g. +02:00
			public static string DbTimeZone = "";

			// Password (hashed and case-sensitivity)
			// Note: If you enable hashed password, make sure that the passwords in your
			// user table are stored as hash of the clear text password. If you also use
			// case-insensitive password, convert the clear text passwords to lower case
			// first before calculating hash. Otherwise, existing users will not be able
			// to login. Hashed password is irreversible, it will be reset during password recovery.
			public static bool EncryptedPassword { get; set; } = false; // Encrypted password

			public static bool CaseSensitivePassword { get; set; } = false; // Case Sensitive password

			// Remove XSS use HtmlSanitizer
			// Note: If you want to allow these keywords, remove them from the following array at your own risks.
			public static bool RemoveXss { get; set; } = true;

			// Check Token
			public static bool CheckToken = true; // Check post token by AntiforgeryToken // DN

			// Session timeout time
			public static int SessionTimeout = 20; // Session timeout time (minutes)

			// Session keep alive interval
			public static int SessionKeepAliveInterval = 0; // Session keep alive interval (seconds)

			public static int SessionTimeoutCountdown = 60; // Session timeout count down interval (seconds)

			// Session names
			public const string SessionStatus = ProjectName + "_Status"; // Login status

			public const string SessionUserName = SessionStatus + "_UserName"; // User name

			public const string SessionUserLoginType = SessionStatus + "_UserLoginType"; // User login type

			public const string SessionUserId = SessionStatus + "_UserID"; // User ID

			public const string SessionUserProfile = SessionStatus + "_UserProfile"; // User Profile

			public const string SessionUserProfileUserName = SessionUserProfile + "_UserName";

			public const string SessionUserProfilePassword = SessionUserProfile + "_Password";

			public const string SessionUserProfileLoginType = SessionUserProfile + "_LoginType";

			public const string SessionUserLevelId = SessionStatus + "_UserLevel"; // User level ID

			public const string SessionUserLevelList = SessionStatus + "_UserLevelList"; // User Level List

			public const string SessionUserLevelListLoaded = SessionStatus + "_UserLevelListLoaded"; // User Level List Loaded

			public const string SessionUserLevel = SessionStatus + "_UserLevelValue"; // User level

			public const string SessionParentUserId = SessionStatus + "_ParentUserID"; // Parent user ID

			public const string SessionSysAdmin = ProjectName + "_SysAdmin"; // System admin

			public const string SessionProjectId = ProjectName + "_ProjectID"; // User Level project ID

			public const string SessionUserLevelArrays = ProjectName + "_UserLevelArrays"; // User level List // DN

			public const string SessionUserLevelPrivArrays = ProjectName + "_UserLevelPrivArrays"; // User level privilege List // DN

			public const string SessionUserLevelMessage = ProjectName + "_UserLevelMessage"; // User Level messsage

			public const string SessionMessage = ProjectName + "_Message"; // System message

			public const string SessionFailureMessage = ProjectName + "_Failure_Message"; // System error message

			public const string SessionSuccessMessage = ProjectName + "_Success_Message"; // System message

			public const string SessionWarningMessage = ProjectName + "_Warning_Message"; // Warning message

			public const string SessionInlineMode = ProjectName + "_InlineMode"; // Inline mode

			public const string SessionBreadcrumb = ProjectName + "_Breadcrumb"; // Breadcrumb

			public const string SessionTempImages = ProjectName + "_TempImages"; // Temp images

			public const string SessionDebugMessage = ProjectName + "_DebugMessage"; // Debug message

			public const string SessionLastRefreshTime = ProjectName + "_LastRefreshTime"; // Last refresh time

			public const string SessionExternalLoginInfo = ProjectName + "_ExternalLoginInfo"; // External login info

			// Language settings
			public static string LanguageFolder = "lang/";

			public static List<dynamic> LanguageFile = new List<dynamic> {
				new { Id = "en", File = "english.xml" }
			};

			public static string LanguageDefaultId = "en";

			public const string SessionLanguageId = ProjectName + "_LanguageId"; // Language ID

			public static string LocaleFolder = "locale/";

			// Page token
			public const string TokenName = "__RequestVerificationToken"; // DO NOT CHANGE!

			public const string SessionToken = ProjectName + "_Token";

			// Data types
			public const int DataTypeNumber = 1;

			public const int DataTypeDate = 2;

			public const int DataTypeString = 3;

			public const int DataTypeBoolean = 4;

			public const int DataTypeMemo = 5;

			public const int DataTypeBlob = 6;

			public const int DataTypeTime = 7;

			public const int DataTypeGuid = 8;

			public const int DataTypeXml = 9;

			public const int DataTypeBit = 10; // DN

			public const int DataTypeOther = 11;

			public static List<int> CustomTemplateDataTypes = new List<int> { DataTypeNumber, DataTypeDate, DataTypeString, DataTypeBoolean, DataTypeTime }; // Data to be passed to Custom Template

			public static int DataStringMaxLength = 512;

			// Row types
			public const short RowTypeHeader = 0; // Row type view

			public const short RowTypeView = 1; // Row type view

			public const short RowTypeAdd = 2; // Row type add

			public const short RowTypeEdit = 3; // Row type edit

			public const short RowTypeSearch = 4; // Row type search

			public const short RowTypeMaster = 5; // Row type master record

			public const short RowTypeAggregateInit = 6; // Row type aggregate init

			public const short RowTypeAggregate = 7; // Row type aggregate

			public const short RowTypeDetail = 8; // Row type detail

			public const short RowTypeTotal = 9; // Row type group summary

			public const short RowTypePreview = 10; // Preview record

			// Row total types
			public const short RowTotalGroup = 1; // Page summary

			public const short RowTotalPage = 2; // Page summary

			public const short RowTotalGrand = 3; // Grand summary

			// Row total sub types
			public const short RowTotalHeader = 0; // Header

			public const short RowTotalFooter = 1; // Footer

			public const short RowTotalSum = 2; // SUM

			public const short RowTotalAvg = 3; // AVG

			public const short RowTotalMin = 4; // MIN

			public const short RowTotalMax = 5; // MAX

			public const short RowTotalCnt = 6; // CNT

			// Empty/Null/Not Null/Init/all values
			public const string EmptyValue = "##empty##";

			public const string InitValue = "##init##";

			public const string AllValue = "##all##";

			// Boolean values for ENUM('Y'/'N') or ENUM(1/0)
			public const string TrueString = "'Y'";

			public const string FalseString = "'N'";

			// List actions
			public const string ActionPostback = "P"; // Post back

			public const string ActionAjax = "A"; // Ajax

			public const string ActionMultiple = "M"; // Multiple records

			public const string ActionSingle = "S"; // Single record

			// Table parameters
			public const string TablePrefix = "||ASPNETReportMaker||"; // For backward compatibility only

			public const string TableRecordsPerPage = "recperpage"; // Records per page

			public const string TableStartRec = "start"; // Start record

			public const string TablePageNumber = "pageno"; // Page number

			public const string TableBasicSearch = "psearch"; // Basic search keyword

			public const string TableBasicSearchType = "psearchtype"; // Basic search type

			public const string TableAdvancedSearch = "advsrch"; // Advanced search

			public const string TableSearchWhere = "searchwhere"; // Search where clause

			public const string TableWhere = "where"; // Table where

			public const string TableWhereList = "where_list"; // Table where (list page)

			public const string TableOrderBy = "orderby"; // Table order by

			public const string TableOrderByList = "orderby_list"; // Table order by (list page)

			public const string TableDetailOrderBy = "detailorderby"; // Table detail order by (report page)

			public const string TableSort = "sort"; // Table sort

			public const string TableKey = "key"; // Table key

			public const string TableShowMaster = "showmaster"; // Table show master

			public const string TableMaster = "master"; // Table show master (alternate key)

			public const string TableShowDetail = "showdetail"; // Table show detail

			public const string TableMasterTable = "mastertable"; // Master table

			public const string TableDetailTable = "detailtable"; // Detail table

			public const string TableReturnUrl = "return"; // Return URL

			public const string TableExportReturnUrl = "exportreturn"; // Export return URL

			public const string TableGridAddRowCount = "gridaddcnt"; // Grid add row count

			// Audit Trail
			public static bool AuditTrailToDatabase { get; set; } = false; // Write audit trail to DB

			public static string AuditTrailDbId = "DB"; // Audit trail DBID

			public static string AuditTrailTableName = ""; // Audit trail table name

			public static string AuditTrailTableVar = ""; // Audit trail table var

			public static string AuditTrailFieldNameDateTime = ""; // Audit trail DateTime field name

			public static string AuditTrailFieldNameScript = ""; // Audit trail Script field name

			public static string AuditTrailFieldNameUser = ""; // Audit trail User field name

			public static string AuditTrailFieldNameAction = ""; // Audit trail Action field name

			public static string AuditTrailFieldNameTable = ""; // Audit trail Table field name

			public static string AuditTrailFieldNameField = ""; // Audit trail Field field name

			public static string AuditTrailFieldNameKeyvalue = ""; // Audit trail Key Value field name

			public static string AuditTrailFieldNameOldvalue = ""; // Audit trail Old Value field name

			public static string AuditTrailFieldNameNewvalue = ""; // Audit trail New Value field name

			// Security
			public static bool EncryptionEnabled = false; // Encryption enabled

			public static string AdminUserName = ""; // Administrator user name

			public static string AdminPassword = ""; // Administrator password

			public static bool UseCustomLogin { get; set; } = true; // Use custom login

			public static bool AllowLoginByUrl { get; set; } = false; // Allow login by URL

			public static bool AllowLoginBySession { get; set; } = false; // Allow login by session variables

			public static bool PasswordHash { get; set; } = false; // Use BCrypt.Net-Next password hashing functions

			// User level constants
			public const int AllowAdd = 1; // Add

			public const int AllowDelete = 2; // Delete

			public const int AllowEdit = 4; // Edit

			public const int AllowList = 8; // List

			public const int AllowReport = 8; // Report

			public const int AllowAdmin = 16; // Admin

			public const int AllowView = 32; // View

			public const int AllowSearch = 64; // Search

			public const int AllowImport = 128; // Import

			public const int AllowLookup = 256; // Lookup

			public const int AllowAll = 511; // All (1 + 2 + 4 + 8 + 16 +32 + 64 + 128 + 256)

			// Hierarchical User ID
			public static bool UserIdIsHierarchical { get; set; } = true; // True to show all level / False to show 1 level

			// Use subquery for master/detail
			public static bool UseSubqueryForMasterUserId { get; set; } = false; // True to use subquery / False to skip

			public static int UserIdAllow = 104;

			// User table/field names
			public static string UserTableName = "";

			public static string LoginUsernameFieldName = "";

			public static string LoginPasswordFieldName = "";

			public static string UserIdFieldName = "null";

			public static string ParentUserIdFieldName = "null";

			public static string UserLevelFieldName = "null";

			public static string UserProfileFieldName = "null";

			public static string RegisterActivateFieldName = "";

			public static string UserEmailFieldName = "";

			// User Profile Constants
			public static string UserProfileSessionId = "SessionId";

			public static string UserProfileLastAccessedDateTime = "LastAccessedDateTime";

			public static int UserProfileConcurrentSessionCount = 1; // Maximum sessions allowed

			public static int UserProfileSessionTimeout = 20;

			public static string UserProfileLoginRetryCount = "LoginRetryCount";

			public static string UserProfileLastBadLoginDateTime = "LastBadLoginDateTime";

			public static int UserProfileMaxRetry = 3;

			public static int UserProfileRetryLockout = 20;

			public static string UserProfileLastPasswordChangedDate = "LastPasswordChangedDate";

			public static int UserProfilePasswordExpire = 90;

			public static string UserProfileLanguageId = "LanguageId";

			public static string UserProfileSearchFilters = "SearchFilters";

			public static string SearchFilterOption = "Client";

			// Auto hide pager
			public static bool AutoHidePager = true;

			public static bool AutoHidePageSizeSelector = false;

			// Email
			public static string SmtpServer = Configuration["Smtp:Server"]; // SMTP server

			public static int SmtpServerPort = ConvertToInt(Configuration["Smtp:Port"]); // SMTP server port

			public static string SmtpSecureOption = Configuration["Smtp:SecureOption"];

			public static string SmtpServerUsername = Configuration["Smtp:Username"]; // SMTP server user name

			public static string SmtpServerPassword = Configuration["Smtp:Password"]; // SMTP server password

			public static string SenderEmail = ""; // Sender email

			public static string RecipientEmail = ""; // Recipient email

			public static int MaxEmailRecipient = 3;

			public static int MaxEmailSentCount = 3;

			public static string ExportEmailCounter = SessionStatus + "_EmailCounter";

			public static string EmailChangePasswordTemplate = "changepwd.html";

			public static string EmailForgotPasswordTemplate = "forgotpwd.html";

			public static string EmailNotifyTemplate = "notify.html";

			public static string EmailRegisterTemplate = "register.html";

			public static string EmailResetPasswordTemplate = "resetpwd.html";

			public static string EmailTemplatePath = "html"; // Template path // DN

			// Remote file
			public static string RemoteFilePattern = @"^((https?\:)?|ftps?\:|s3:)\/\/";

			// File upload
			public static string UploadType = "POST"; // HTTP request method for the file uploads, e.g. "POST", "PUT

			// File handler // DN
			public static string FileUrl = "FileViewer";

			// File upload
			public static string UploadTempPath = ""; // Upload temp path (absolute local physical path)

			public static string UploadTempHrefPath = ""; // Upload temp href path (absolute URL path for download)

			public static bool DownloadViaScript = false; // Download uploaded temp file via ewupload.cs (DN)

			public static string UploadDestPath = "files/"; // Upload destination path

			public static string UploadHrefPath = ""; // Upload file href path (for download)

			public static string UploadTempFolderPrefix = "temp__"; // Upload temp folders prefix

			public static int UploadTempFolderTimeLimit = 1440; // Upload temp folder time limit (minutes)

			public static string UploadThumbnailFolder = "thumbnail"; // Temporary thumbnail folder

			public static int UploadThumbnailWidth = 200; // Temporary thumbnail max width

			public static int UploadThumbnailHeight = 0; // Temporary thumbnail max height

			public static int MaxFileCount = 0; // Max file count

			public static string UploadAllowedFileExtensions = "gif,jpg,jpeg,bmp,png,doc,docx,xls,xlsx,pdf,zip"; // Allowed file extensions

			public static List<string> ImageAllowedFileExtensions = new List<string> { "gif","jpe","jpeg","jpg","png","bmp" }; // Allowed file extensions for images

			public static List<string> DownloadAllowedFileExtensions = new List<string> {"csv","pdf","xls","doc","xlsx","docx"}; // Allowed file extensions for download (non-image)

			public static bool EncryptFilePath = true; // Encrypt file path

			public static int MaxFileSize = 2000000; // Max file size

			public static int ThumbnailDefaultWidth = 0; // Thumbnail default width

			public static int ThumbnailDefaultHeight = 0; // Thumbnail default height

			public static bool UploadConvertAccentedChars { get; set; } = false; // Convert accented chars in upload file name

			public static bool UseColorbox { get; set; } = true; // Use Colorbox

			public static char MultipleUploadSeparator = ','; // Multiple upload separator

			// Image resize
			public static bool ResizeIgnoreAspectRatio { get; set; } = false;

			public static bool ResizeLess { get; set; } = false;

			// API
			public static string ApiUrl = "api/"; // API URL

			public static string ApiActionName = "action"; // API action name

			public static string ApiObjectName = "table"; // API object name

			public static string ApiFieldName = "field"; // API field name

			public static string ApiKeyName = "key"; // API key name

			public static string ApiListAction = "list"; // API list action

			public static string ApiViewAction = "view"; // API view action

			public static string ApiAddAction = "add"; // API add action

			public static string ApiEditAction = "edit"; // API edit action

			public static string ApiDeleteAction = "delete"; // API delete action

			public static string ApiLoginAction = "login"; // API login action

			public static string ApiFileAction = "file"; // API file action

			public static string ApiUploadAction = "upload"; // API upload action

			public static string ApiFileTokenName = "filetoken"; // API upload file token name

			public static string ApiJqueryUploadAction = "jupload"; // API jQuery upload action

			public static string ApiSessionAction = "session"; // API get session action

			public static string ApiLookupAction = "lookup"; // API lookup action

			public static string ApiLoginUsername = "username"; // API login user name

			public static string ApiLoginPassword = "password"; // API login password

			public static string ApiLookupPage = "page"; // API lookup page name

			public static string ApiProgressAction = "progress"; // API progress action

			public static string ApiExportChartAction = "chart"; // API export chart action

			public static List<string> ApiPageActions = new List<string> { ApiListAction, ApiViewAction, ApiAddAction, ApiEditAction, ApiDeleteAction };

			// Import records
			public static Encoding ImportCsvEncoding = Encoding.UTF8; // Import CSV encoding

			public static CultureInfo ImportCsvCulture = CultureInfo.InvariantCulture; // Import CSV culture

			public static char ImportCsvDelimiter = ','; // Import CSV delimiter character

			public static char ImportCsvTextQualifier = '"'; // Import CSV text qualifier character

			public static string ImportCsvEol = "\r\n"; // Import CSV end of line, default CRLF

			public static string ImportFileExtensions = "csv,xlsx"; // Import file allowed extensions

			public static bool ImportInsertOnly = true; // Import by insert only

			public static bool ImportUseTransaction = false; // Import use transaction

			// Audit trail
			public static string AuditTrailPath = ""; // Audit trail path (relative to wwwroot)

			// Export records
			public static bool ExportAll = true; // Export all records

			public static bool ExportOriginalValue { get; set; } = false; // True to export original value

			public static bool ExportFieldCaption { get; set; } = false; // True to export field caption

			public static bool ExportFieldImage { get; set; } = true; // True to export field image

			public static bool ExportCssStyles { get; set; } = true; // True to export css styles

			public static bool ExportMasterRecord { get; set; } = true; // True to export master record

			public static bool ExportMasterRecordForCsv { get; set; } = false; // True to export master record for CSV

			public static bool ExportDetailRecords { get; set; } = true; // True to export detail records

			public static bool ExportDetailRecordsForCsv { get; set; } = false; // True to export detail records for CSV

			// Export classes
			public static Dictionary<string, string> Export = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
				{"email", "ExportEmail"},
				{"html", "ExportHtml"},
				{"word", "ExportWord"},
				{"excel", "ExportExcel"},
				{"pdf", "ExportPdf"},
				{"csv", "ExportCsv"},
				{"xml", "ExportXml"},
				{"json", "ExportJson"}
			};

			// Full URL protocols ("http" or "https")
			public static Dictionary<string, string> FullUrlProtocols = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
				{"href", null},
				{"upload", null},
				{"resetpwd", null},
				{"activate", null},
				{"tmpfile", null},
				{"auth", null},
			};

			// Table class names
			public static Dictionary<string, string> TableClassNames = new Dictionary<string, string> {
				{"Accounts", "_Accounts"},
				{"AccountTypes", "_AccountTypes"},
				{"sysdiagrams", "_sysdiagrams"},
				{"Transactions", "_Transactions"},
			};

			// Boolean html attributes
			public static List<string> BooleanHtmlAttributes = new List<string> {
				"allowfullscreen",
				"allowpaymentrequest",
				"async",
				"autofocus",
				"autoplay",
				"checked",
				"controls",
				"default",
				"defer",
				"disabled",
				"formnovalidate",
				"hidden",
				"ismap",
				"itemscope",
				"loop",
				"multiple",
				"muted",
				"nomodule",
				"novalidate",
				"open",
				"readonly",
				"required",
				"reversed",
				"selected",
				"typemustmatch"
			};

			// HTML singleton tags
			public static List<string> HtmlSingletonTags = new List<string> {
				"area",
				"base",
				"br",
				"col",
				"command",
				"embed",
				"hr",
				"img",
				"input",
				"keygen",
				"link",
				"meta",
				"param",
				"source",
				"track",
				"wbr"
			};

			// Use ILIKE for PostgreSQL
			public static bool UseIlikeForPostgresql { get; set; } = true;

			// Use collation for MySQL
			public static string LikeCollationForMysql = "";

			// Use collation for MsSQL
			public static string LikeCollationForMssql = "";

			// Use collation for MsSQL
			public static string LikeCollationForSqlite = "";

			// Null / Not Null values
			public const string NullValue = "##null##";

			public const string NotNullValue = "##notnull##";

			// Search multi value option
			// 1 - no multi value
			// 2 - AND all multi values
			// 3 - OR all multi values
			public static short SearchMultiValueOption { get; set; } = 3;

			// Quick search
			public static string BasicSearchIgnorePattern = @"[\?,\^\*\(\)\[\]\""]"; // Ignore special characters

			public static bool BasicSearchAnyFields { get; set; } = false; // Search "All keywords" in any selected fields

			// Validate option
			public static bool ClientValidate { get; set; } = true;

			public static bool ServerValidate { get; set; } = true;

			// Blob field byte count for hash value calculation
			public static int BlobFieldByteCount { get; set; } = 256;

			// Auto suggest max entries
			public static int AutoSuggestMaxEntries = 10;

			// Auto suggest for all display fields
			public static bool AutoSuggestForAllFields = false;

			// Auto fill original value
			public static bool AutoFillOriginalValue = false;

			// Lookup filter value separator
			public static char MultipleOptionSeparator = ',';

			public static bool UseLookupCache = true;

			public static int LookupCacheCount = 100;

			// Page Title Style
			public static string PageTitleStyle = "Breadcrumb";

			// Responsive tables
			public static bool UseResponsiveTable = true;

			public static string ResponsiveTableClass = "table-responsive";

			// Use css-flip
			public static bool CssFlip { get; set; } = false;

			public static List<string> RtlLanguages = new List<string> { "ar", "fa", "he", "iw", "ug", "ur" };

			// Date/Time without seconds
			public static bool DateTimeWithoutSeconds = false;

			// Mulitple selection
			public static string OptionHtmlTemplate = "<span class=\"ew-option\">{value}</span>"; // Note: class="ew-option" must match CSS style in project stylesheet

			public static string OptionSeparator = ", ";

			// Cookies
			public static DateTime CookieExpiryTime = DateTime.Today.AddDays(365);

			public static string CookieSameSite = "Unspecified";

			public static bool CookieHttpOnly = true;

			public static bool CookieSecure = false;

			public static string CookieConsentClass = "toast-body bg-secondary"; // CSS class name for cookie consent

			public static string CookieConsentButtonClass = "btn btn-dark btn-sm"; // CSS class name for cookie consent buttons

			// Mime type // DN
			public static string DefaultMimeType = "application/octet-stream";

			/**
			 * Reports
			 */
			// Chart
			public static int ChartWidth = 600;

			public static int ChartHeight = 500;

			public static bool ChartShowBlankSeries { get; set; } = false; // Show blank series

			public static bool ChartShowZeroInStackChart { get; set; } = false; // Show zero in stack chart

			// Drill down setting
			public static bool UseDrilldownPanel { get; set; } = true; // Use popup panel for drill down

			// Filter
			public static bool ShowCurrentFilter { get; set; } = false; // True to show current filter

			public static bool ShowDrilldownFilter { get; set; } = true; // True to show drill down filter

			// Table level constants
			public static string TableGroupPerPage = "recperpage";

			public static string TableStartGroup = "start";

			public static string TableSortChart = "sortc"; // Table sort chart

			// Page break
			public static string PageBreakHtml = "<div style=\"page-break-after:always;\"></div>";

			// Export report methods
			public static Dictionary<string, string> ExportReport = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
				{ "email", "ExportReportEmail" },
				{ "word", "ExportReportWord" },
				{ "excel", "ExportReportExcel" },
				{ "pdf", "ExportReportPdf" }
			};

			// Embed PDF documents
			public static bool EmbedPdf = true;

			// Advanced Filters
			public static Dictionary<string, Dictionary<string, string>> ReportAdvancedFilters = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase) {
				{ "PastFuture", new Dictionary<string, string> { { "Past", "IsPast" }, { "Future", "IsFuture" } } },
				{ "RelativeDayPeriods", new Dictionary<string, string> { { "Last30Days", "IsLast30Days" }, { "Last14Days", "IsLast14Days" }, { "Last7Days", "IsLast7Days" }, { "Next7Days", "IsNext7Days" }, { "Next14Days", "IsNext14Days" }, { "Next30Days", "IsNext30Days" } } },
				{ "RelativeDays", new Dictionary<string, string> { { "Yesterday", "IsYesterday" }, { "Today", "IsToday" }, { "Tomorrow", "IsTomorrow" } } },
				{ "RelativeWeeks", new Dictionary<string, string> { { "LastTwoWeeks", "IsLast2Weeks" }, { "LastWeek", "IsLastWeek" }, { "ThisWeek", "IsThisWeek" }, { "NextWeek", "IsNextWeek" }, { "NextTwoWeeks", "IsNext2Weeks" } } },
				{ "RelativeMonths", new Dictionary<string, string> { { "LastMonth", "IsLastMonth" }, { "ThisMonth", "IsThisMonth" }, { "NextMonth", "IsNextMonth" } } },
				{ "RelativeYears", new Dictionary<string, string> { { "LastYear", "IsLastYear" }, { "ThisYear", "IsThisYear" }, { "NextYear", "IsNextYear" } } }
			};

			// Float fields default decimal position
			public static int DefaultDecimalPrecision = 2;

			// Chart
			public static string DefaultChartRenderer => "";

			// Captcha class // DN
			public static string CaptchaClass { get; set; } = "CaptchaBase";

			/// <summary>
			/// Get property by name
			/// </summary>
			/// <param name="name"></param>
			public static object Get(string name) =>
				typeof(Config).GetProperty(name, BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy)?.GetValue(null);
		}
	} // End Partial class
} // End namespace