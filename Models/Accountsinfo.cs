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
		/// Accounts
		/// </summary>
		public static _Accounts Accounts {
			get => HttpData.GetOrCreate<_Accounts>("Accounts");
			set => HttpData["Accounts"] = value;
		}

		/// <summary>
		/// Table class for Accounts
		/// </summary>
		public class _Accounts: DbTable {

			public int RowCount = 0; // DN

			public bool UseSessionForListSql = true;

			// Column CSS classes
			public string LeftColumnClass = "col-sm-2 col-form-label ew-label";

			public string RightColumnClass = "col-sm-10";

			public string OffsetColumnClass = "col-sm-10 offset-sm-2";

			public string TableLeftColumnClass = "w-col-2";

			public readonly DbField<SqlDbType> AccountID;

			public readonly DbField<SqlDbType> AccountNumber;

			public readonly DbField<SqlDbType> FirstName;

			public readonly DbField<SqlDbType> OtherNames;

			public readonly DbField<SqlDbType> LastName;

			public readonly DbField<SqlDbType> AccountTypeID;

			public readonly DbField<SqlDbType> BankVerificationNumber;

			public readonly DbField<SqlDbType> DateOfBirth;

			public readonly DbField<SqlDbType> Photo;

			public readonly DbField<SqlDbType> _Email;

			// Constructor
			public _Accounts() {

				// Language object // DN
				Language ??= new Lang();
				TableVar = "Accounts";
				Name = "Accounts";
				Type = "TABLE";

				// Update Table
				UpdateTable = "[dbo].[Accounts]";
				DbId = "DB"; // DN
				ExportAll = true;
				ExportPageBreakCount = 0; // Page break per every n record (PDF only)
				ExportPageOrientation = "portrait"; // Page orientation (PDF only)
				ExportPageSize = "a4"; // Page size (PDF only)
				ExportExcelPageOrientation = ""; // Page orientation (EPPlus only)
				ExportExcelPageSize = ""; // Page size (EPPlus only)
				ExportColumnWidths = new float[] {  }; // Column widths (PDF only) // DN
				DetailAdd = false; // Allow detail add
				DetailEdit = false; // Allow detail edit
				DetailView = false; // Allow detail view
				ShowMultipleDetails = false; // Show multiple details
				GridAddRowCount = 5;
				AllowAddDeleteRow = true; // Allow add/delete row
				UserIdAllowSecurity = 0; // User ID Allow
				BasicSearch = new BasicSearch(TableVar);

				// AccountID
				AccountID = new DbField<SqlDbType> {
					TableVar = "Accounts",
					TableName = "Accounts",
					FieldVar = "x_AccountID",
					Name = "AccountID",
					Expression = "[AccountID]",
					BasicSearchExpression = "CAST([AccountID] AS NVARCHAR)",
					Type = 20,
					DbType = SqlDbType.BigInt,
					DateTimeFormat = -1,
					VirtualExpression = "[AccountID]",
					IsVirtual = false,
					ForceSelection = false,
					SelectMultiple = false,
					VirtualSearch = false,
					ViewTag = "FORMATTED TEXT",
					HtmlTag = "NO",
					IsAutoIncrement = true, // Autoincrement field
					IsPrimaryKey = true, // Primary key field
					Nullable = false, // NOT NULL field
					Sortable = true, // Allow sort
					DefaultErrorMessage = Language.Phrase("IncorrectInteger"),
					IsUpload = false
				};
				AccountID.Init(this); // DN
				Fields.Add("AccountID", AccountID);

				// AccountNumber
				AccountNumber = new DbField<SqlDbType> {
					TableVar = "Accounts",
					TableName = "Accounts",
					FieldVar = "x_AccountNumber",
					Name = "AccountNumber",
					Expression = "[AccountNumber]",
					BasicSearchExpression = "[AccountNumber]",
					Type = 202,
					DbType = SqlDbType.NVarChar,
					DateTimeFormat = -1,
					VirtualExpression = "[AccountNumber]",
					IsVirtual = false,
					ForceSelection = false,
					SelectMultiple = false,
					VirtualSearch = false,
					ViewTag = "FORMATTED TEXT",
					HtmlTag = "TEXT",
					Nullable = false, // NOT NULL field
					Required = true, // Required field
					Sortable = true, // Allow sort
					IsUpload = false
				};
				AccountNumber.Init(this); // DN
				Fields.Add("AccountNumber", AccountNumber);

				// FirstName
				FirstName = new DbField<SqlDbType> {
					TableVar = "Accounts",
					TableName = "Accounts",
					FieldVar = "x_FirstName",
					Name = "FirstName",
					Expression = "[FirstName]",
					BasicSearchExpression = "[FirstName]",
					Type = 202,
					DbType = SqlDbType.NVarChar,
					DateTimeFormat = -1,
					VirtualExpression = "[FirstName]",
					IsVirtual = false,
					ForceSelection = false,
					SelectMultiple = false,
					VirtualSearch = false,
					ViewTag = "FORMATTED TEXT",
					HtmlTag = "TEXT",
					Nullable = false, // NOT NULL field
					Required = true, // Required field
					Sortable = true, // Allow sort
					IsUpload = false
				};
				FirstName.Init(this); // DN
				Fields.Add("FirstName", FirstName);

				// OtherNames
				OtherNames = new DbField<SqlDbType> {
					TableVar = "Accounts",
					TableName = "Accounts",
					FieldVar = "x_OtherNames",
					Name = "OtherNames",
					Expression = "[OtherNames]",
					BasicSearchExpression = "[OtherNames]",
					Type = 202,
					DbType = SqlDbType.NVarChar,
					DateTimeFormat = -1,
					VirtualExpression = "[OtherNames]",
					IsVirtual = false,
					ForceSelection = false,
					SelectMultiple = false,
					VirtualSearch = false,
					ViewTag = "FORMATTED TEXT",
					HtmlTag = "TEXT",
					Sortable = true, // Allow sort
					IsUpload = false
				};
				OtherNames.Init(this); // DN
				Fields.Add("OtherNames", OtherNames);

				// LastName
				LastName = new DbField<SqlDbType> {
					TableVar = "Accounts",
					TableName = "Accounts",
					FieldVar = "x_LastName",
					Name = "LastName",
					Expression = "[LastName]",
					BasicSearchExpression = "[LastName]",
					Type = 202,
					DbType = SqlDbType.NVarChar,
					DateTimeFormat = -1,
					VirtualExpression = "[LastName]",
					IsVirtual = false,
					ForceSelection = false,
					SelectMultiple = false,
					VirtualSearch = false,
					ViewTag = "FORMATTED TEXT",
					HtmlTag = "TEXT",
					Nullable = false, // NOT NULL field
					Required = true, // Required field
					Sortable = true, // Allow sort
					IsUpload = false
				};
				LastName.Init(this); // DN
				Fields.Add("LastName", LastName);

				// AccountTypeID
				AccountTypeID = new DbField<SqlDbType> {
					TableVar = "Accounts",
					TableName = "Accounts",
					FieldVar = "x_AccountTypeID",
					Name = "AccountTypeID",
					Expression = "[AccountTypeID]",
					BasicSearchExpression = "CAST([AccountTypeID] AS NVARCHAR)",
					Type = 3,
					DbType = SqlDbType.Int,
					DateTimeFormat = -1,
					VirtualExpression = "[AccountTypeID]",
					IsVirtual = false,
					ForceSelection = false,
					SelectMultiple = false,
					VirtualSearch = false,
					ViewTag = "FORMATTED TEXT",
					HtmlTag = "SELECT",
					Nullable = false, // NOT NULL field
					Required = true, // Required field
					Sortable = true, // Allow sort
					UsePleaseSelect = true, // Use PleaseSelect by default
					PleaseSelectText = Language.Phrase("PleaseSelect"), // PleaseSelect text
					DefaultErrorMessage = Language.Phrase("IncorrectInteger"),
					IsUpload = false
				};
				AccountTypeID.Init(this); // DN
				AccountTypeID.Lookup = new Lookup<DbField>("AccountTypeID", "AccountTypes", false, "AccountTypeID", new List<string> {"AccountTypeName", "", "", ""}, new List<string> {}, new List<string> {}, new List<string> {}, new List<string> {}, new List<string> {}, new List<string> {}, "", "");
				Fields.Add("AccountTypeID", AccountTypeID);

				// BankVerificationNumber
				BankVerificationNumber = new DbField<SqlDbType> {
					TableVar = "Accounts",
					TableName = "Accounts",
					FieldVar = "x_BankVerificationNumber",
					Name = "BankVerificationNumber",
					Expression = "[BankVerificationNumber]",
					BasicSearchExpression = "[BankVerificationNumber]",
					Type = 202,
					DbType = SqlDbType.NVarChar,
					DateTimeFormat = -1,
					VirtualExpression = "[BankVerificationNumber]",
					IsVirtual = false,
					ForceSelection = false,
					SelectMultiple = false,
					VirtualSearch = false,
					ViewTag = "FORMATTED TEXT",
					HtmlTag = "TEXT",
					Sortable = true, // Allow sort
					IsUpload = false
				};
				BankVerificationNumber.Init(this); // DN
				Fields.Add("BankVerificationNumber", BankVerificationNumber);

				// DateOfBirth
				DateOfBirth = new DbField<SqlDbType> {
					TableVar = "Accounts",
					TableName = "Accounts",
					FieldVar = "x_DateOfBirth",
					Name = "DateOfBirth",
					Expression = "[DateOfBirth]",
					BasicSearchExpression = CastDateFieldForLike("[DateOfBirth]", 0, "DB"),
					Type = 133,
					DbType = SqlDbType.DateTime,
					DateTimeFormat = 0,
					VirtualExpression = "[DateOfBirth]",
					IsVirtual = false,
					ForceSelection = false,
					SelectMultiple = false,
					VirtualSearch = false,
					ViewTag = "FORMATTED TEXT",
					HtmlTag = "TEXT",
					Sortable = true, // Allow sort
					DefaultErrorMessage = Convert.ToString(Language.Phrase("IncorrectDate")).Replace("%s", DateFormat),
					IsUpload = false
				};
				DateOfBirth.Init(this); // DN
				Fields.Add("DateOfBirth", DateOfBirth);

				// Photo
				Photo = new DbField<SqlDbType> {
					TableVar = "Accounts",
					TableName = "Accounts",
					FieldVar = "x_Photo",
					Name = "Photo",
					Expression = "[Photo]",
					BasicSearchExpression = "[Photo]",
					Type = 204,
					DbType = SqlDbType.VarBinary,
					DateTimeFormat = -1,
					VirtualExpression = "[Photo]",
					IsVirtual = false,
					ForceSelection = false,
					SelectMultiple = false,
					VirtualSearch = false,
					ViewTag = "FORMATTED TEXT",
					HtmlTag = "FILE",
					Sortable = true, // Allow sort
					IsUpload = true
				};
				Photo.Init(this); // DN
				Fields.Add("Photo", Photo);

				// Email
				_Email = new DbField<SqlDbType> {
					TableVar = "Accounts",
					TableName = "Accounts",
					FieldVar = "x__Email",
					Name = "Email",
					Expression = "[Email]",
					BasicSearchExpression = "[Email]",
					Type = 200,
					DbType = SqlDbType.VarChar,
					DateTimeFormat = -1,
					VirtualExpression = "[Email]",
					IsVirtual = false,
					ForceSelection = false,
					SelectMultiple = false,
					VirtualSearch = false,
					ViewTag = "FORMATTED TEXT",
					HtmlTag = "TEXT",
					Sortable = true, // Allow sort
					IsUpload = false
				};
				_Email.Init(this); // DN
				Fields.Add("Email", _Email);
			}

			// Set Field Visibility
			public override bool GetFieldVisibility(string fldname) {
				var fld = FieldByName(fldname);
				return fld.Visible; // Returns original value
			}

			// Invoke method // DN
			public object Invoke(string name, object[] parameters = null) {
				MethodInfo mi = this.GetType().GetMethod(name);
				if (mi != null) {
					if (IsAsyncMethod(mi)) {
						return InvokeAsync(mi, parameters).GetAwaiter().GetResult();
					} else {
						return mi.Invoke(this, parameters);
					}
				}
				return null;
			}

			// Invoke async method // DN
			public async Task<object> InvokeAsync(MethodInfo mi, object[] parameters = null) {
				if (mi != null) {
					dynamic awaitable = mi.Invoke(this, parameters);
					await awaitable;
					return awaitable.GetAwaiter().GetResult();
				}
				return null;
			}
			#pragma warning disable 1998

			// Invoke async method // DN
			public async Task<object> InvokeAsync(string name, object[] parameters = null) => InvokeAsync(this.GetType().GetMethod(name), parameters);
			#pragma warning restore 1998

			// Check if Invoke async method // DN
			public bool IsAsyncMethod(MethodInfo mi) {
				if (mi != null) {
					Type attType = typeof(AsyncStateMachineAttribute);
					var attrib = (AsyncStateMachineAttribute)mi.GetCustomAttribute(attType);
					return (attrib != null);
				}
				return false;
			}

			// Check if Invoke async method // DN
			public bool IsAsyncMethod(string name) => IsAsyncMethod(this.GetType().GetMethod(name));
			#pragma warning disable 618

			// Connection
			public virtual DatabaseConnectionBase<SqlConnection, SqlCommand, SqlDataReader, SqlDbType> Connection => GetConnection(DbId);
			#pragma warning restore 618

			// Set left column class (must be predefined col-*-* classes of Bootstrap grid system)
			public void SetLeftColumnClass(string columnClass) {
				Match m = Regex.Match(columnClass, @"^col\-(\w+)\-(\d+)$");
				if (m.Success) {
					LeftColumnClass = columnClass + " col-form-label ew-label";
					RightColumnClass = "col-" + m.Groups[1].Value + "-" + Convert.ToString(12 - ConvertToInt(m.Groups[2].Value));
					OffsetColumnClass = RightColumnClass + " " + columnClass.Replace("col-", "offset-");
					TableLeftColumnClass = Regex.Replace(columnClass, @"/^col-\w+-(\d+)$/", "w-col-$1"); // Change to w-col-*
				}
			}

			// Single column sort
			public void UpdateSort(DbField fld) {
				string lastSort, sortField, thisSort;
				if (CurrentOrder == fld.Name) {
					sortField = fld.Expression;
					lastSort = fld.Sort;
					if (CurrentOrderType == "ASC" || CurrentOrderType == "DESC") {
						thisSort = CurrentOrderType;
					} else {
						thisSort = (lastSort == "ASC") ? "DESC" : "ASC";
					}
					fld.Sort = thisSort;
					SessionOrderBy = sortField + " " + thisSort; // Save to Session
				} else {
					fld.Sort = "";
				}
			}

			// Table level SQL
			// FROM
			private string _sqlFrom = null;

			public string SqlFrom {
				get => _sqlFrom ?? "[dbo].[Accounts]";
				set => _sqlFrom = value;
			}

			// SELECT
			private string _sqlSelect = null;

			public string SqlSelect { // Select
				get => _sqlSelect ?? "SELECT * FROM " + SqlFrom;
				set => _sqlSelect = value;
			}

			// WHERE // DN
			private string _sqlWhere = null;

			public string SqlWhere {
				get {
					string where = "";
					return _sqlWhere ?? where;
				}
				set {
					_sqlWhere = value;
				}
			}

			// Group By
			private string _sqlGroupBy = null;

			public string SqlGroupBy {
				get => _sqlGroupBy ?? "";
				set => _sqlGroupBy = value;
			}

			// Having
			private string _sqlHaving = null;

			public string SqlHaving {
				get => _sqlHaving ?? "";
				set => _sqlHaving = value;
			}

			// Order By
			private string _sqlOrderBy = null;

			public string SqlOrderBy {
				get => _sqlOrderBy ?? "";
				set => _sqlOrderBy = value;
			}

			// Apply User ID filters
			public string ApplyUserIDFilters(string filter) {
				return filter;
			}

			// Check if User ID security allows view all
			public bool UserIDAllow(string id = "") {
				int allow = Config.UserIdAllow;
				return id switch {
					"add" => ((allow & 1) == 1),
					"copy" => ((allow & 1) == 1),
					"gridadd" => ((allow & 1) == 1),
					"register" => ((allow & 1) == 1),
					"addopt" => ((allow & 1) == 1),
					"edit" => ((allow & 4) == 4),
					"gridedit" => ((allow & 4) == 4),
					"update" => ((allow & 4) == 4),
					"changepwd" => ((allow & 4) == 4),
					"forgotpwd" => ((allow & 4) == 4),
					"delete" => ((allow & 2) == 2),
					"view" => ((allow & 32) == 32),
					"search" => ((allow & 64) == 64),
					_ => ((allow & 8) == 8)
				};
			}

			// Get record count by reading data reader
			public async Task<int> GetRecordCount(string sql, dynamic c = null) { // use by Lookup // DN
				try {
					var cnt = 0;
					var conn = c ?? Connection;
					using var dr = await conn.OpenDataReaderAsync(sql);
					while (await dr.ReadAsync())
						cnt++;
					return cnt;
				} catch {
					if (Config.Debug)
						throw;
					return -1;
				}
			}

			// Try to get record count by SELECT COUNT(*)
			public async Task<int> TryGetRecordCount(string sql, dynamic c = null) {
				string orderBy = OrderBy;
				var conn = c ?? Connection;
				sql = Regex.Replace(sql, @"/\*BeginOrderBy\*/[\s\S]+/\*EndOrderBy\*/", "", RegexOptions.IgnoreCase).Trim(); // Remove ORDER BY clause (MSSQL)
				if (!string.IsNullOrEmpty(orderBy) && sql.EndsWith(orderBy))
					sql = sql.Substring(0, sql.Length - orderBy.Length); // Remove ORDER BY clause
				try {
					string sqlcnt;
					if ((new List<string> { "TABLE", "VIEW", "LINKTABLE" }).Contains(Type) && sql.StartsWith(SqlSelect)) { // Handle Custom Field
						sqlcnt = "SELECT COUNT(*) FROM " + SqlFrom + sql.Substring(SqlSelect.Length);
					} else {
						sqlcnt = "SELECT COUNT(*) FROM (" + sql + ") EW_COUNT_TABLE";
					}
					return Convert.ToInt32(await conn.ExecuteScalarAsync(sqlcnt));
				} catch {
					return await GetRecordCount(sql, c);
				}
			}

			// Get SQL
			public string GetSql(string where, string orderBy = "") => BuildSelectSql(SqlSelect, SqlWhere, SqlGroupBy, SqlHaving, SqlOrderBy, where, orderBy);

			// Table SQL
			public string CurrentSql {
				get {
					string filter = CurrentFilter;
					filter = ApplyUserIDFilters(filter); // Add User ID filter
					string sort = SessionOrderBy;
					return GetSql(filter, sort);
				}
			}

			// Table SQL with List page filter
			public string ListSql {
				get {
					string sort = "";
					string select = "";
					string filter = UseSessionForListSql ? SessionWhere : "";
					AddFilter(ref filter, CurrentFilter);
					Recordset_Selecting(ref filter);
					filter = ApplyUserIDFilters(filter); // Add User ID filter
					select = SqlSelect;
					sort = UseSessionForListSql ? SessionOrderBy : "";
					return BuildSelectSql(select, SqlWhere, SqlGroupBy, SqlHaving, SqlOrderBy, filter, sort);
				}
			}

			// Get ORDER BY clause
			public string OrderBy {
				get {
					string sort = SessionOrderBy;
					return BuildSelectSql("", "", "", "", SqlOrderBy, "", sort);
				}
			}

			// Get record count based on filter (for detail record count in master table pages)
			public async Task<int> LoadRecordCount(string filter) => await TryGetRecordCount(GetSql(filter));

			// Get record count (for current List page)
			public async Task<int> ListRecordCount() => await TryGetRecordCount(ListSql);

			// Insert
			public async Task<int> InsertAsync(Dictionary<string, object> row) {
				int result;
				var r = row.Where(kvp => {
					var fld = FieldByName(kvp.Key);
					return (fld != null && !fld.IsCustom);
				}).ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
				var fields = r.Select(kvp => Fields[kvp.Key]);
				var names = String.Join(",", fields.Select(fld => fld.Expression));
				var values = String.Join(",", fields.Select(fld => SqlParameter(fld)));
				if (Empty(names))
					return -1;
				string sql = "INSERT INTO " + UpdateTable + " (" + names + ") VALUES (" + values + ")";
				using var command = Connection.GetCommand(sql);
				foreach (var (key, value) in r) {
					var fld = (DbField<SqlDbType>)Fields[key]; // DN
					try {
						command.Parameters.Add(fld.FieldVar, fld.DbType).Value = ParameterValue(fld, value);
					} catch {
						if (Config.Debug)
							throw;
					}
				}
				result = await command.ExecuteNonQueryAsync();
				if (result > 0) {

					// Get insert ID
					AccountID.SetDbValue(await Connection.GetLastInsertIdAsync());
					row["AccountID"] = AccountID.DbValue;
				}
				return result;
			}

			// Insert
			public int Insert(Dictionary<string, object> row) => InsertAsync(row).GetAwaiter().GetResult();

			// Update
			#pragma warning disable 168, 219

			public async Task<int> UpdateAsync(Dictionary<string, object> row, object where = null, Dictionary<string, object> rsold = null, bool curfilter = true) {
				int result;
				var rscascade = new Dictionary<string, object>();
				string whereClause = "";
				row = row.Where(kvp => {
					var fld = FieldByName(kvp.Key);
					return fld != null && !fld.IsCustom;
				}).ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
				var fields = row.Select(kvp => Fields[kvp.Key]);
				var values = String.Join(",", fields.Select(fld => fld.Expression + "=" + SqlParameter(fld)));
				if (Empty(values))
					return -1;
				string sql = "UPDATE " + UpdateTable + " SET " + values;
				string filter = curfilter ? CurrentFilter : "";
				if (IsDictionary(where))
					whereClause = ArrayToFilter((IDictionary<string, object>)where);
				else
					whereClause = (string)where;
				AddFilter(ref filter, whereClause);
				if (!Empty(filter))
					sql += " WHERE " + filter;
				using var command = Connection.GetCommand(sql);
				foreach (var (key, value) in row) {
					var fld = (DbField<SqlDbType>)Fields[key]; // DN
					try {
						command.Parameters.Add(fld.FieldVar, fld.DbType).Value = ParameterValue(fld, value);
					} catch {
						if (Config.Debug)
							throw;
					}
				}
				result = await command.ExecuteNonQueryAsync();
				return result;
			}
			#pragma warning restore 168, 219

			// Update
			public int Update(Dictionary<string, object> row, object where = null, Dictionary<string, object> rsold = null, bool curfilter = true)
				=> UpdateAsync(row, where, rsold, curfilter).GetAwaiter().GetResult();

			// Convert to parameter name for use in SQL
			public string SqlParameter(DbField fld) {
				string symbol = GetSqlParamSymbol(DbId);
				string value = symbol;
				if (symbol != "?")
					value += fld.FieldVar;
				return value;
			}

			// Convert value to object for parameter
			public object ParameterValue(DbField fld, object value) {
				if (((DbField<SqlDbType>)fld).DbType == SqlDbType.Bit) {
					return ConvertToBool(value);
				}
				return value;
			}
			#pragma warning disable 168, 1998

			// Delete
			public async Task<int> DeleteAsync(Dictionary<string, object> row, object where = null, bool curfilter = true) {
				bool delete = true;
				string whereClause = "";
				string sql = "DELETE FROM " + UpdateTable + " WHERE ";
				string filter = curfilter ? CurrentFilter : "";
				if (IsDictionary(where))
					whereClause = ArrayToFilter((IDictionary<string, object>)where);
				else
					whereClause = (string)where;
				AddFilter(ref filter, whereClause);
				if (row != null) {
					DbField fld;
					fld = FieldByName("AccountID");
					AddFilter(ref filter, fld.Expression + "=" + QuotedValue(row["AccountID"], FieldByName("AccountID").DataType, DbId));
				}
				if (!Empty(filter))
					sql += filter;
				else
					sql += "0=1"; // Avoid delete
				int result = -1;
				if (delete)
					result = await Connection.ExecuteAsync(sql, null, null, null, null, true); // Use main connection
				return result;
			}
			#pragma warning restore 168, 1998

			// Delete
			public int Delete(Dictionary<string, object> row, object where = null, bool curfilter = true) =>
				DeleteAsync(row, where, curfilter).GetAwaiter().GetResult();

			// Load DbValue from recordset
			public void LoadDbValues(Dictionary<string, object> row) {
				if (row == null)
					return;
				AccountID.SetDbValue(row["AccountID"], false);
				AccountNumber.SetDbValue(row["AccountNumber"], false);
				FirstName.SetDbValue(row["FirstName"], false);
				OtherNames.SetDbValue(row["OtherNames"], false);
				LastName.SetDbValue(row["LastName"], false);
				AccountTypeID.SetDbValue(row["AccountTypeID"], false);
				BankVerificationNumber.SetDbValue(row["BankVerificationNumber"], false);
				DateOfBirth.SetDbValue(row["DateOfBirth"], false);
				Photo.Upload.DbValue = row["Photo"];
				_Email.SetDbValue(row["Email"], false);
			}

			public void DeleteUploadedFiles(Dictionary<string, object> row) {
				LoadDbValues(row);
			}

			// Record filter WHERE clause
			private string _sqlKeyFilter => "[AccountID] = @AccountID@";
			#pragma warning disable 168

			// Get record filter
			public string GetRecordFilter(Dictionary<string, object> row = null)
			{
				string keyFilter = _sqlKeyFilter;
				object val, result;
				val = !Empty(row) && row.TryGetValue("AccountID", out result) ? result : null;
				val ??= !Empty(AccountID.OldValue) ? AccountID.OldValue : AccountID.CurrentValue; // DN
				if (!IsNumeric(val))
					return "0=1"; // Invalid key
				if (val == null)
					return "0=1"; // Invalid key
				else
					keyFilter = keyFilter.Replace("@AccountID@", AdjustSql(val, DbId)); // Replace key value
				return keyFilter;
			}
			#pragma warning restore 168

			// Return URL
			public string ReturnUrl {
				get {
					string name = Config.ProjectName + "_" + TableVar + "_" + Config.TableReturnUrl;

					// Get referer URL automatically
					if (!Empty(ReferUrl()) && ReferPage() != CurrentPageName() &&
						ReferPage() != "login") {// Referer not same page or login page
							Session[name] = ReferUrl(); // Save to Session
					}
					if (!Empty(Session[name])) {
						return Session.GetString(name);
					} else {
						return "Accountslist";
					}
				}
				set {
					Session[Config.ProjectName + "_" + TableVar + "_" + Config.TableReturnUrl] = value;
				}
			}

			// Get modal caption
			public string GetModalCaption(string pageName) {
				if (SameString(pageName, "Accountsview"))
					return Language.Phrase("View");
				else if (SameString(pageName, "Accountsedit"))
					return Language.Phrase("Edit");
				else if (SameString(pageName, "Accountsadd"))
					return Language.Phrase("Add");
				else
					return "";
			}

			// List URL
			public string ListUrl => "Accountslist";

			// View URL
			public string ViewUrl => GetViewUrl();

			// View URL
			public string GetViewUrl(string parm = "") {
				string url = "";
				if (!Empty(parm))
					url = KeyUrl("Accountsview", UrlParm(parm));
				else
					url = KeyUrl("Accountsview", UrlParm(Config.TableShowDetail + "="));
				return AddMasterUrl(url);
			}

			// Add URL
			public string AddUrl { get; set; } = "Accountsadd";

			// Add URL
			public string GetAddUrl(string parm = "") {
				string url = "";
				if (!Empty(parm))
					url = "Accountsadd?" + UrlParm(parm);
				else
					url = "Accountsadd";
				return AppPath(AddMasterUrl(url));
			}

			// Edit URL
			public string EditUrl => GetEditUrl();

			// Edit URL (with parameter)
			public string GetEditUrl(string parm = "") {
				string url = "";
				url = KeyUrl("Accountsedit", UrlParm(parm));
				return AppPath(AddMasterUrl(url)); // DN
			}

			// Inline edit URL
			public string InlineEditUrl =>
				AppPath(AddMasterUrl(KeyUrl(CurrentPageName(), UrlParm("action=edit")))); // DN

			// Copy URL
			public string CopyUrl => GetCopyUrl();

			// Copy URL
			public string GetCopyUrl(string parm = "") {
				string url = "";
				url = KeyUrl("Accountsadd", UrlParm(parm));
				return AppPath(AddMasterUrl(url)); // DN
			}

			// Inline copy URL
			public string InlineCopyUrl =>
				AppPath(AddMasterUrl(KeyUrl(CurrentPageName(), UrlParm("action=copy")))); // DN

			// Delete URL
			public string DeleteUrl =>
				AppPath(KeyUrl("Accountsdelete", UrlParm())); // DN

			// Add master URL
			public string AddMasterUrl(string url) {
				return url;
			}

			// Get primary key as JSON
			public string KeyToJson() {
				string json = "";
				json += "AccountID:" + ConvertToJson(AccountID.CurrentValue, "number", true);
				return "{" + json + "}";
			}

			// Add key value to URL
			public string KeyUrl(string url, string parm = "") { // DN
				if (!IsDBNull(AccountID.CurrentValue)) {
					url += "/" + AccountID.CurrentValue;
				} else {
					return "javascript:ew.alert(ew.language.phrase('InvalidRecord'));";
				}
				if (Empty(parm))
					return url;
				else
					return url + "?" + parm;
			}

			// Sort URL (already URL-encoded)
			public string SortUrl(DbField fld) {
				if (!Empty(CurrentAction) || !Empty(Export) ||
					(new List<int> {141, 201, 203, 128, 204, 205}).Contains(fld.Type)) { // Unsortable data type
					return "";
				} else if (fld.Sortable) {
					string urlParm = UrlParm("order=" + UrlEncode(fld.Name) + "&amp;ordertype=" + fld.ReverseSort());
					return AddMasterUrl(CurrentPageName() + "?" + urlParm);
				}
				return "";
			}
			#pragma warning disable 168

			// Get record keys
			public List<string> GetRecordKeys() {
				var result = new List<string>();
				StringValues sv;
				var keysList = new List<string>();
				if (Post("key_m[]", out sv) || Get("key_m[]", out sv)) { // DN
					keysList = sv.ToList();
				} else if (RouteValues.Count > 0 || Query.Count > 0 || Form.Count > 0) { // DN
					string key = "";
					string[] keyValues = null;
					object rv;
					if (IsApi() && RouteValues.TryGetValue("key", out object k))
						keyValues = k.ToString().Split('/');
					if (RouteValues.TryGetValue("AccountID", out rv)) { // AccountID
						key = Convert.ToString(rv);
					} else if (IsApi() && !Empty(keyValues)) {
						key = keyValues[0];
					} else {
						key = Param("AccountID");
					}
					keysList.Add(key);
				}

				// Check keys
				foreach (var keys in keysList) {
					if (!IsNumeric(keys)) // AccountID
						continue;
					result.Add(keys);
				}
				return result;
			}
			#pragma warning restore 168

			// Get filter from record keys
			public string GetFilterFromRecordKeys(bool setCurrent = true) {
				List<string> recordKeys = GetRecordKeys();
				string keyFilter = "";
				foreach (var keys in recordKeys) {
					if (!Empty(keyFilter))
						keyFilter += " OR ";
					if (setCurrent)
						AccountID.CurrentValue = keys;
					else
						AccountID.OldValue = keys;
					keyFilter += "(" + GetRecordFilter() + ")";
				}
				return keyFilter;
			}
			#pragma warning disable 618

			// Load rows based on filter // DN
			public async Task<DbDataReader> LoadRs(string filter, DatabaseConnectionBase<SqlConnection, SqlCommand, SqlDataReader, SqlDbType> conn = null) {

				// Set up filter (SQL WHERE clause) and get return SQL
				string sql = GetSql(filter);
				try {
					var dr = await (conn ?? Connection).OpenDataReaderAsync(sql);
					if (dr?.HasRows ?? false)
						return dr;
				} catch {}
				return null;
			}
			#pragma warning restore 618

			// Load row values from recordset
			public void LoadListRowValues(DbDataReader rs) {
				AccountID.SetDbValue(rs["AccountID"]);
				AccountNumber.SetDbValue(rs["AccountNumber"]);
				FirstName.SetDbValue(rs["FirstName"]);
				OtherNames.SetDbValue(rs["OtherNames"]);
				LastName.SetDbValue(rs["LastName"]);
				AccountTypeID.SetDbValue(rs["AccountTypeID"]);
				BankVerificationNumber.SetDbValue(rs["BankVerificationNumber"]);
				DateOfBirth.SetDbValue(rs["DateOfBirth"]);
				Photo.Upload.DbValue = rs["Photo"];
				_Email.SetDbValue(rs["Email"]);
			}
			#pragma warning disable 1998

			// Render list row values
			public async Task RenderListRow() {

				// Call Row Rendering event
				Row_Rendering();

				// Common render codes
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

				// Call Row Rendered event
				Row_Rendered();

				// Save data for Custom Template
				Rows.Add(CustomTemplateFieldValues());
			}
			#pragma warning restore 1998
			#pragma warning disable 1998

			// Render edit row values
			public async Task RenderEditRow() {

				// Call Row Rendering event
				Row_Rendering();

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

				// Email
				_Email.EditAttrs["class"] = "form-control";
				if (!_Email.Raw)
					_Email.CurrentValue = HtmlDecode(_Email.CurrentValue);
				_Email.EditValue = _Email.CurrentValue; // DN
				_Email.PlaceHolder = RemoveHtml(_Email.Caption);

				// Call Row Rendered event
				Row_Rendered();
			}
			#pragma warning restore 1998

			// Aggregate list row values
			public void AggregateListRowValues() {
			}
			#pragma warning disable 1998

			// Aggregate list row (for rendering)
			public async Task AggregateListRow() {

				// Call Row Rendered event
				Row_Rendered();
			}
			#pragma warning restore 1998

			// Export document
			public dynamic ExportDoc;

			// Export data in HTML/CSV/Word/Excel/Email/PDF format
			public async Task ExportDocument(dynamic doc, DbDataReader dataReader, int startRec, int stopRec, string exportType = "") {
				if (dataReader == null || doc == null)
					return;
				if (!doc.ExportCustom) {

					// Write header
					doc.ExportTableHeader();
					if (doc.Horizontal) { // Horizontal format, write header
						doc.BeginExportRow();
						if (exportType == "view") {
							doc.ExportCaption(AccountID);
							doc.ExportCaption(AccountNumber);
							doc.ExportCaption(FirstName);
							doc.ExportCaption(OtherNames);
							doc.ExportCaption(LastName);
							doc.ExportCaption(AccountTypeID);
							doc.ExportCaption(BankVerificationNumber);
							doc.ExportCaption(DateOfBirth);
							doc.ExportCaption(Photo);
							doc.ExportCaption(_Email);
						} else {
							doc.ExportCaption(AccountID);
							doc.ExportCaption(AccountNumber);
							doc.ExportCaption(FirstName);
							doc.ExportCaption(OtherNames);
							doc.ExportCaption(LastName);
							doc.ExportCaption(AccountTypeID);
							doc.ExportCaption(BankVerificationNumber);
							doc.ExportCaption(DateOfBirth);
							doc.ExportCaption(_Email);
						}
						doc.EndExportRow();
					}
				}

				// Move to first record
				// For List page only. For View page, the recordset is alreay at the start record. // DN

				int recCnt = startRec - 1;
				if (exportType != "view") {
					if (Connection.SelectOffset) {
						await dataReader.ReadAsync();
					} else {
						for (int i = 0; i < startRec; i++) // Move to the start record and use do-while loop
							await dataReader.ReadAsync();
					}
				}
				int rowcnt = 0; // DN
				do { // DN
					recCnt++;
					if (recCnt >= startRec) {
						rowcnt = recCnt - startRec + 1;

						// Page break
						if (ExportPageBreakCount > 0) {
							if (rowcnt > 1 && (rowcnt - 1) % ExportPageBreakCount == 0)
								doc.ExportPageBreak();
						}
						LoadListRowValues(dataReader);

						// Render row
						RowType = Config.RowTypeView; // Render view
						ResetAttributes();
						await RenderListRow();
						if (!doc.ExportCustom) {
							doc.BeginExportRow(rowcnt); // Allow CSS styles if enabled
							if (exportType == "view") {
								await doc.ExportField(AccountID);
								await doc.ExportField(AccountNumber);
								await doc.ExportField(FirstName);
								await doc.ExportField(OtherNames);
								await doc.ExportField(LastName);
								await doc.ExportField(AccountTypeID);
								await doc.ExportField(BankVerificationNumber);
								await doc.ExportField(DateOfBirth);
								await doc.ExportField(Photo);
								await doc.ExportField(_Email);
							} else {
								await doc.ExportField(AccountID);
								await doc.ExportField(AccountNumber);
								await doc.ExportField(FirstName);
								await doc.ExportField(OtherNames);
								await doc.ExportField(LastName);
								await doc.ExportField(AccountTypeID);
								await doc.ExportField(BankVerificationNumber);
								await doc.ExportField(DateOfBirth);
								await doc.ExportField(_Email);
							}
							doc.EndExportRow(rowcnt);
						}
					}

					// Call Row Export server event
					if (doc.ExportCustom)
						CurrentPage.Row_Export(dataReader);
				} while (recCnt < stopRec && await dataReader.ReadAsync()); // DN
				if (!doc.ExportCustom)
					doc.ExportTableFooter();
			}

			// Table filter
			private string _tableFilter = null;

			public string TableFilter {
				get => _tableFilter ?? "";
				set => _tableFilter = value;
			}

			// TblBasicSearchDefault
			private string _tableBasicSearchDefault = null;

			public string TableBasicSearchDefault {
				get => _tableBasicSearchDefault ?? "";
				set => _tableBasicSearchDefault = value;
			}
			#pragma warning disable 1998

			// Get file data
			public async Task<IActionResult> GetFileData(string fldparm, string key, bool resize, int width = -1, int height = -1) {
				if (width < 0)
					width = Config.ThumbnailDefaultWidth;
				if (height < 0)
					height = Config.ThumbnailDefaultHeight;

				// Set up field names
				string fldName = "", fileNameFld = "", fileTypeFld = "";
				if (SameText(fldparm, "Photo")) {
					fldName = "Photo";
				} else {
					return JsonBoolResult.FalseResult; // Incorrect field
				}

				// Set up key values
				var ar = key.Split(Convert.ToChar(Config.CompositeKeySeparator));
				if (ar.Length == 1) {
					AccountID.CurrentValue = ar[0];
				} else {
					return JsonBoolResult.FalseResult; // Incorrect key
				}

				// Set up filter (WHERE Clause)
				string filter = GetRecordFilter();
				CurrentFilter = filter;
				string sql = CurrentSql;
				using var rs = await Connection.GetDataReaderAsync(sql);
				if (rs != null && await rs.ReadAsync()) {
					var val = rs[fldName];
					if (!Empty(val)) {

						// Binary data
						DbField fld;
						if (Fields.TryGetValue(fldName, out fld) && fld.IsBlob) {
							byte[] data = (byte[])val;
							if (resize && data.Length > 0)
								ResizeBinary(ref data, ref width, ref height);
							string contentType = "";

							// Write file type
							if (!Empty(fileTypeFld) && !Empty(rs[fileTypeFld]))
								contentType = Convert.ToString(rs[fileTypeFld]);
							else
								contentType = ContentType(data);

							// Write file data
							if (data.Take(8).SequenceEqual(new byte[] {0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00}) && // Fix Office 2007 documents
								!data.TakeLast(4).SequenceEqual(new byte[] {0x00, 0x00, 0x00, 0x00}))
									data.Concat(new byte[] {0x00, 0x00, 0x00, 0x00});

							// Clear any debug message
							// Response.Clear();
							// Return file content result // DN

							if (!Empty(fileNameFld) && !Empty(rs[fileNameFld]))
								return Controller.File(data, contentType, Convert.ToString(rs[fileNameFld]));
							else
								return Controller.File(data, contentType);

						// Upload to folder
						} else {
							List<string> files;
							if (fld.UploadMultiple)
								files = Convert.ToString(val).Split(Config.MultipleUploadSeparator).ToList();
							else
								files = new List<string> { Convert.ToString(val) };
							var result = files.ToDictionary(f => f, f => FullUrl(fld.HrefPath + f));
							return new JsonBoolResult(new Dictionary<string, object> { { fld.Param, result } }, true);
						}
					}
				}
				return JsonBoolResult.FalseResult; // Incorrect key
			}
			#pragma warning restore 1998

			// Table level events
			// Recordset Selecting event
			public void Recordset_Selecting(ref string filter) {

				// Enter your code here
			}

			// Recordset Search Validated event
			public void Recordset_SearchValidated() {

				// Enter your code here
			}

			// Recordset Searching event
			public void Recordset_Searching(ref string filter) {

				// Enter your code here
			}

			// Row_Selecting event
			public void Row_Selecting(ref string filter) {

				// Enter your code here
			}

			// Row Selected event
			public void Row_Selected(Dictionary<string, object> row) {

				//Log("Row Selected");
			}

			// Row Inserting event
			public bool Row_Inserting(Dictionary<string, object> rsold, Dictionary<string, object> rsnew) {

				// Enter your code here
				// To cancel, set return value to False and error message to CancelMessage

				return true;
			}

			// Row Inserted event
			public void Row_Inserted(Dictionary<string, object> rsold, Dictionary<string, object> rsnew) {

				//Log("Row Inserted");
			}

			// Row Updating event
			public bool Row_Updating(Dictionary<string, object> rsold, Dictionary<string, object> rsnew) {

				// Enter your code here
				// To cancel, set return value to False and error message to CancelMessage

				return true;
			}

			// Row Updated event
			public void Row_Updated(Dictionary<string, object> rsold, Dictionary<string, object> rsnew) {

				//Log("Row Updated");
			}

			// Row Update Conflict event
			public bool Row_UpdateConflict(Dictionary<string, object> rsold, Dictionary<string, object> rsnew) {

				// Enter your code here
				// To ignore conflict, set return value to false

				return true;
			}

			// Recordset Deleting event
			public bool Row_Deleting(Dictionary<string, object> rs) {

				// Enter your code here
				// To cancel, set return value to False and error message to CancelMessage

				return true;
			}

			// Row Deleted event
			public void Row_Deleted(Dictionary<string, object> rs) {

				//Log("Row Deleted");
			}

			// Email Sending event
			public virtual bool Email_Sending(Email email, dynamic args) {

				//Log(email);
				return true;
			}

			// Lookup Selecting event
			public void Lookup_Selecting(DbField fld, ref string filter) {

				// Enter your code here
			}

			// Row Rendering event
			public void Row_Rendering() {

				// Enter your code here
			}

			// Row Rendered event
			public void Row_Rendered() {

				//VarDump(<FieldName>); // View field properties
			}

			// User ID Filtering event
			public void UserID_Filtering(ref string filter) {

				// Enter your code here
			}
		}
	} // End Partial class
} // End namespace