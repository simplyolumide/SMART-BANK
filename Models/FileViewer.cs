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
		/// File Viewer class
		/// </summary>
		public class FileViewer
		{

			// Constructor
			public FileViewer(Controller controller = null) { // DN
				if (controller != null)
					Controller = controller;
			}

			/// <summary>
			/// Output file by file name
			/// </summary>
			/// <returns>Action result</returns>
			public async Task<IActionResult> GetFile(string fn)
			{

				// Get parameters
				string sessionId = Get("session");
				sessionId = Decrypt(sessionId);
				bool resize = Get<bool>("resize");
				int width = Get<int>("width");
				int height = Get<int>("height");
				bool download = Get("download", out StringValues d) ? ConvertToBool(d) : true; // Download by default
				if (width == 0 && height == 0 && resize) {
					width = Config.ThumbnailDefaultWidth;
					height = Config.ThumbnailDefaultHeight;
				}

				// If using session (internal request), file path is always encrypted.
				// If not (external request), DO NOT support external request for file path.

				string key = Config.RandomKey + sessionId;
				fn = (UseSession) ? Decrypt(fn, key) : "";
				if (FileExists(fn)) {
					Response.Clear();
					string ext = Path.GetExtension(fn).Replace(".", "").ToLower();
					string ct = ContentType(fn);
					if (Config.ImageAllowedFileExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase)) {
						if (width > 0 || height > 0)
							return Controller.File(ResizeFileToBinary(fn, ref width, ref height), ct, Path.GetFileName(fn));
						else
							return Controller.PhysicalFile(fn, ct, Path.GetFileName(fn));
					} else if (Config.DownloadAllowedFileExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase)) {
						if (ext == "pdf" && Config.EmbedPdf && FileExists(fn)) // Embed Pdf // DN
							return Controller.File(await FileReadAllBytes(fn), ct); // Return File Content
						else
							return Controller.PhysicalFile(fn, ct, Path.GetFileName(fn));
					}
				}
				return JsonBoolResult.FalseResult;
			}

			/// <summary>
			/// Output file by table name, field name and primary key
			/// </summary>
			/// <returns>Action result</returns>
			public async Task<IActionResult> GetFile(string table, string field, string recordkey)
			{

				// Get parameters
				//string sessionId = Get("session");

				bool resize = Get<bool>("resize");
				int width = Get<int>("width");
				int height = Get<int>("height");
				bool download = Get("download", out StringValues d) ? ConvertToBool(d) : true; // Download by default
				if (width == 0 && height == 0 && resize) {
					width = Config.ThumbnailDefaultWidth;
					height = Config.ThumbnailDefaultHeight;
				}

				// Get table object
				string tableName = "";
				dynamic tbl = null;
				if (!Empty(table)) {
					tbl = CreateTable(table);
					tableName = tbl.Name;
				}
				if (Empty(tableName) || Empty(field) || Empty(recordkey))
					return JsonBoolResult.FalseResult;
				bool validRequest = true;

				// Reject invalid request
				if (!validRequest)
					return JsonBoolResult.FalseResult;
				return await tbl.GetFileData(field, recordkey, resize, width, height);
			}
		}
	} // End Partial class
} // End namespace