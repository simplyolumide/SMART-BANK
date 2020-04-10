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
		/// Static properties
		/// </summary>
		// Conn
		public static dynamic Conn {
			get => HttpData.Get<dynamic>("_Conn");
			set => HttpData["_Conn"] = value;
		}

		// Connections
		public static Dictionary<string, dynamic> Connections {
			get => HttpData.GetOrCreate<Dictionary<string, dynamic>>("_Connections");
			set => HttpData["_Connections"] = value;
		}

		// _Connections
		public static Dictionary<string, dynamic> _Connections {
			get => HttpData.GetOrCreate<Dictionary<string, dynamic>>("__Connections");
			set => HttpData["__Connections"] = value;
		}

		// Security
		public static AdvancedSecurityBase Security {
			get => HttpData.Get<AdvancedSecurityBase>("_Security");
			set => HttpData["_Security"] = value;
		}

		// CurrentForm
		public static HttpForm CurrentForm {
			get => HttpData.Get<HttpForm>("_CurrentForm");
			set => HttpData["_CurrentForm"] = value;
		}

		// Language
		public static Lang Language {
			get => HttpData.Get<Lang>("_Language");
			set => HttpData["_Language"] = value;
		}

		// CurrentBreadcrumb
		public static Breadcrumb CurrentBreadcrumb {
			get => HttpData.Get<Breadcrumb>("_CurrentBreadcrumb");
			set => HttpData["_CurrentBreadcrumb"] = value;
		}

		// TopMenu
		public static Task<string> TopMenu {
			get => HttpData.Get<Task<string>>("_TopMenu");
			set => HttpData["_TopMenu"] = value;
		}

		// SideMenu
		public static Task<string> SideMenu {
			get => HttpData.Get<Task<string>>("_SideMenu");
			set => HttpData["_SideMenu"] = value;
		}

		// CurrentLanguage
		public static string CurrentLanguage {
			get => HttpData.Get<string>("_CurrentLanguage");
			set => HttpData["_CurrentLanguage"] = value;
		}

		// SkipHeaderFooter
		public static bool SkipHeaderFooter {
			get => HttpData.Get<bool>("_SkipHeaderFooter");
			set => HttpData["_SkipHeaderFooter"] = value;
		}

		// StartTime
		public static long StartTime {
			get => HttpData.Get<long>("_StartTime");
			set => HttpData["_StartTime"] = value;
		}

		// CurrentPage
		public static dynamic CurrentPage {
			get => HttpData.Get<dynamic>("_CurrentPage");
			set => HttpData["_CurrentPage"] = value;
		}

		// CurrentGrid
		public static dynamic CurrentGrid {
			get => HttpData.Get<dynamic>("_CurrentGrid");
			set => HttpData["_CurrentGrid"] = value;
		}

		// FormError
		public static string FormError {
			get => HttpData.Get<string>("_FormError");
			set => HttpData["_FormError"] = value;
		}

		// SearchError
		public static string SearchError {
			get => HttpData.Get<string>("_SearchError");
			set => HttpData["_SearchError"] = value;
		}

		// ExportType
		public static string ExportType {
			get => HttpData.Get<string>("_ExportType");
			set => HttpData["_ExportType"] = value;
		}

		// ExportFileName
		public static string ExportFileName {
			get => HttpData.Get<string>("_ExportFileName");
			set => HttpData["_ExportFileName"] = value;
		}

		// ReportExportType
		public static string ReportExportType {
			get => HttpData.Get<string>("_ReportExportType");
			set => HttpData["_ReportExportType"] = value;
		}

		// CustomExportType
		public static string CustomExportType {
			get => HttpData.Get<string>("_CustomExportType");
			set => HttpData["_CustomExportType"] = value;
		}

		// EmailError
		public static string EmailError {
			get => HttpData.Get<string>("_EmailError");
			set => HttpData["_EmailError"] = value;
		}

		// DebugMessage
		public static string DebugMessage {
			get => HttpData.Get<string>("_DebugMessage");
			set => HttpData["_DebugMessage"] = value;
		}

		// CurrentToken
		public static string CurrentToken {
			get => HttpData.Get<string>("_CurrentToken");
			set => HttpData["_CurrentToken"] = value;
		}

		// TempImages
		public static List<string> TempImages {
			get => HttpData.GetOrCreate<List<string>>("_TempImages");
			set => HttpData["_TempImages"] = value;
		}

		// CurrentNumberFormatInfo
		public static NumberFormatInfo CurrentNumberFormatInfo {
			get => HttpData.GetOrCreate<NumberFormatInfo>("_CurrentNumberFormatInfo");
			set => HttpData["_CurrentNumberFormatInfo"] = value;
		}

		// CurrencySymbolPrecedesPositive
		public static int CurrencySymbolPrecedesPositive {
			get => HttpData.Get<int>("_CurrencySymbolPrecedesPositive");
			set => HttpData["_CurrencySymbolPrecedesPositive"] = value;
		}

		// CurrencySymbolSpacePositive
		public static int CurrencySymbolSpacePositive {
			get => HttpData.Get<int>("_CurrencySymbolSpacePositive");
			set => HttpData["_CurrencySymbolSpacePositive"] = value;
		}

		// CurrencySymbolPrecedesNegative
		public static int CurrencySymbolPrecedesNegative {
			get => HttpData.Get<int>("_CurrencySymbolPrecedesNegative");
			set => HttpData["_CurrencySymbolPrecedesNegative"] = value;
		}

		// CurrencySymbolSpaceNegative
		public static int CurrencySymbolSpaceNegative {
			get => HttpData.Get<int>("_CurrencySymbolSpaceNegative");
			set => HttpData["_CurrencySymbolSpaceNegative"] = value;
		}

		// PositiveSignPosition
		public static int PositiveSignPosition {
			get => HttpData.Get<int>("_PositiveSignPosition");
			set => HttpData["_PositiveSignPosition"] = value;
		}

		// NegativeSignPosition
		public static int NegativeSignPosition {
			get => HttpData.Get<int>("_NegativeSignPosition");
			set => HttpData["_NegativeSignPosition"] = value;
		}

		// DateSeparator
		public static string DateSeparator {
			get => HttpData.Get<string>("_DateSeparator");
			set => HttpData["_DateSeparator"] = value;
		}

		// TimeSeparator
		public static string TimeSeparator {
			get => HttpData.Get<string>("_TimeSeparator");
			set => HttpData["_TimeSeparator"] = value;
		}

		// DateFormat
		public static string DateFormat {
			get => HttpData.Get<string>("_DateFormat");
			set => HttpData["_DateFormat"] = value;
		}

		// DateFormatId
		public static int DateFormatId {
			get => HttpData.Get<int>("_DateFormatId");
			set => HttpData["_DateFormatId"] = value;
		}

		// ClientVariables
		public static Dictionary<string, object> ClientVariables {
			get => HttpData.GetOrCreate<Dictionary<string, object>>("_ClientVariables");
			set => HttpData["_ClientVariables"] = value;
		}

		// LoginStatus
		public static Dictionary<string, object> LoginStatus {
			get => HttpData.GetOrCreate<Dictionary<string, object>>("_LoginStatus");
			set => HttpData["_LoginStatus"] = value;
		}

		// Profile
		public static UserProfile Profile {
			get => HttpData.Get<UserProfile>("_Profile");
			set => HttpData["_Profile"] = value;
		}

		// UseSession
		public static bool UseSession {
			get => HttpData.Get<bool>("_UseSession");
			set => HttpData["_UseSession"] = value;
		}

		// IsDrillDownInPanel
		public static bool IsDrillDownInPanel {
			get => HttpData.Get<bool>("_IsDrillDownInPanel");
			set => HttpData["_IsDrillDownInPanel"] = value;
		}

		// DashboardReport
		public static bool DashboardReport {
			get => HttpData.Get<bool>("_DashboardReport");
			set => HttpData["_DashboardReport"] = value;
		}

		// DashboardPage
		public static dynamic DashboardPage {
			get => HttpData.Get<dynamic>("_DashboardPage");
			set => HttpData["_DashboardPage"] = value;
		}

		// Chart
		public static DbChart Chart {
			get => HttpData.Get<DbChart>("_Chart");
			set => HttpData["_Chart"] = value;
		}

		// ReportOptions
		public static Dictionary<string, object> ReportOptions {
			get => HttpData.GetOrCreate<Dictionary<string, object>>("_ReportOptions");
			set => HttpData["_ReportOptions"] = value;
		}

		// ReportParameters
		public static Dictionary<string, string> ReportParameters {
			get => HttpData.GetOrCreate<Dictionary<string, string>>("_ReportParameters");
			set => HttpData["_ReportParameters"] = value;
		}

		// ReportTableClass
		public static string ReportTableClass {
			get => HttpData.Get<string>("_ReportTableClass");
			set => HttpData["_ReportTableClass"] = value;
		}

		// Personal data file name
		public static string PersonalDataFileName {
			get => HttpData.Get<string>("_PersonalDataFileName") ?? "PersonalData.json";
			set => HttpData["_PersonalDataFileName"] = value;
		}
	}
}