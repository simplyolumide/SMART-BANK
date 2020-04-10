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
		/// ChartTypes class
		/// </summary>
		public static class ChartTypes
		{

			/// <summary>
			/// Supported chart types
			/// 
			/// Format - [chart_id, [normal_chart_name, scroll_chart_name]]
			/// chart_id - abnn
			/// **id = chart_id in previous version
			/// - a: 1 = Single Series, 2 = Multi Series, 3 = Stacked, 4 = Combination, 5 = Financial, 6 = Other
			/// - b: 0 = 2D, 1 = 3D
			/// - nn: 01 = Column, 02 = Line, 03 = Area, 04 = Bar, 05 = Pie, 06 = Doughnut, 07 Pareto
			/// - nn: 91 = Marimekko, 92 = Zoom-line
			/// - nn: 99 = Candlestick, 98 = Gantt
			/// </summary>
			public static Dictionary<string, string[]> Types = new Dictionary<string, string[]> {

				// Single Series
				{ "1001", new[] {"bar"} }, // Column 2D (**1)
				{ "1101", new[] {"bar"} }, // Column 3D (**5) // NOT supported, revert to Column 2D
				{ "1002", new[] {"line"} }, // Line 2D (**4) // fill=false
				{ "1003", new[] {"line"} }, // Area 2D (**7)
				{ "1004", new[] {"horizontalBar"} }, // Bar 2D (**3)
				{ "1104", new[] {"horizontalBar"} }, // Bar 3D (**104) // NOT supported, revert to Bar 2D
				{ "1005", new[] {"pie"} }, // Pie 2D (**2)
				{ "1105", new[] {"pie"} }, // Pie 3D (**6) // NOT supported, revert to Pie 2D
				{ "1006", new[] {"doughnut"} }, // Doughnut 2D (**8)
				{ "1106", new[] {"doughnut"} }, // Doughnut 3D (**101) // NOT supported, revert to Dougnut 2D

				// Multi Series
				{ "2001", new[] {"bar"} }, // Multi-series Column 2D (**9)
				{ "2101", new[] {"bar"} }, // Multi-series Column 3D (**10) // NOT supported, revert to Column 2D
				{ "2002", new[] {"line"} }, // Multi-series Line 2D (**11) // fill=false
				{ "2003", new[] {"line"} }, // Multi-series Area 2D (**12)
				{ "2004", new[] {"horizontalBar"} }, // Multi-series Bar 2D (**13)
				{ "2104", new[] {"horizontalBar"} }, // Multi-series Bar 3D (**102) // NOT supported, revert to Bar 2D

				// Stacked
				{ "3001", new[] {"bar"} }, // Stacked Column 2D (**14)
				{ "3101", new[] {"bar"} }, // Stacked Column 3D (**15) // NOT supported, revert to Column 2D
				{ "3003", new[] {"line"} }, // Stacked Area 2D (**16)
				{ "3004", new[] {"horizontalBar"} }, // Stacked Bar 2D (**17)
				{ "3104", new[] {"horizontalBar"} }, // Stacked Bar 3D (**103) // NOT supported, revert to Bar 2D

				// Combination
				{ "4001", new[] {"bar"} }, // Multi-series 2D Single Y Combination Chart (Column + Line + Area)
				{ "4101", new[] {"bar"} }, // Multi-series 3D Single Y Combination Chart (Column + Line + Area) // NOT supported, revert to 4001
				{ "4111", new[] {"bar"} }, // Multi-series Column 3D + Line - Single Y Axis // NOT supported, revert to 4001
				{ "4021", new[] {"bar"} }, // Stacked Column2D + Line single Y Axis // Mixed, type in dataset
				{ "4121", new[] {"bar"} }, // Stacked Column3D + Line single Y Axis // NOT supported, revert to 4021
				{ "4031", new[] {"bar"} }, // Multi-series 2D Dual Y Combination Chart (Column + Line + Area) (**18) // Mixed, type in dataset
				{ "4131", new[] {"bar"} }, // Multi-series Column 3D + Line - Dual Y Axis (**19) // NOT supported, revert to 4031
				{ "4141", new[] {"bar"} } // Stacked Column 3D + Line Dual Y Axis // NOT supported, revert to 2D (Stacked Column 2D + Line Dual Y Axis)
			};

			/// <summary>
			/// Default type ID
			/// </summary>
			public static string DefaultType = "1001"; // // Default

			/// <summary>
			/// Get chart type name
			/// </summary>
			/// <param name="id">Chart type ID</param>
			/// <param name="scroll">Whether chart is scrollable</param>
			/// <returns>Chart name</returns>
			public static string GetName(string id, bool scroll = false) {
				if (Types.TryGetValue(id, out string[] names))
					return (scroll && names.Length >= 2) ? names[1] : names[0];
				return "bar"; // Default
			}

			/// <summary>
			/// Get renderer class
			/// </summary>
			/// <param name="id">Chart type ID</param>
			/// <returns>Renderer class typee</returns>
			public static Type GetRendererClass(string id) {
				if (!Empty(Config.DefaultChartRenderer))
					return Type.GetType(Config.DefaultChartRenderer);
				return typeof(ChartJsRenderer);
			}
		}
	} // End Partial class
} // End namespace