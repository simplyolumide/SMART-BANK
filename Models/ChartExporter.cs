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
		/// Chart exporter class
		/// </summary>
		public class ChartExporter {

			// Constructor
			public ChartExporter(Controller controller = null) { // DN
				if (controller != null)
					Controller = controller;
			}

			// Valid post
			protected async Task<bool> ValidPost() => !Config.CheckToken || !IsPost() || IsApi() || await Antiforgery.IsRequestValidAsync(HttpContext);

			// Run
			public async Task<IActionResult> Export() {

				// Check token
				if (!await ValidPost())
					return ServerError("Invalid post request."); // Invalid post request
				string json = Post<string>("charts") ?? "[]";
				var charts = JsonConvert.DeserializeObject<List<Dictionary<string, string>>>(json);
				var files = new List<string>();
				foreach (var chart in charts) {
					byte[] img = null;
					string streamType = chart["stream_type"];
					string streamData = chart["stream"];
					string chartEngine = chart["chart_engine"];

					// Google Charts base64
					if (streamType == "base64") {
						if (!Empty(streamData)) {
							streamData = Regex.Replace(streamData, @"^data:image/\w+;base64,", "");
							img = Convert.FromBase64String(streamData);
						}
					} else { // SVG
						img ??= GetImageFromImagick(chart); // Get from Imagick
					}
					if (img == null)
						return ServerError($"Unable to load image for chart engine '{chartEngine}' and stream type '{streamType}'.");
					string filename = "";
					var m = Regex.Match(chart["parameters"], @"exportfilename=([\w-]+\.png)\|");
					if (m.Success)
						filename = m.Groups[1].Value;
					if (Empty(filename))
						return ServerError("Missing file name.");
					var path = ServerMapPath(Config.UploadDestPath);
					if (!DirectoryExists(path) && !CreateFolder(path))
						return ServerError("Upload folder does not exist.");
					if (await SaveFile(path, filename, img))
						files.Add(filename);
					else
						return ServerError($"Failed to save image '{filename}' to '{path}'.");
				}
				return Controller.Json(new { success = true, files = files });
			}

			// Send server error
			protected IActionResult ServerError(string msg) => Controller.Json(new { success = false, error = msg });

			// Get image from fusioncharts.com
			protected byte[] GetImageFromFusionCharts(Dictionary<string, string> chart)
			{
				var data = new NameValueCollection();
				foreach (var (key, value) in chart)
					data.Add(key, value);
				return DownloadData("http://export.api3.fusioncharts.com/", data); // Get the chart from fusioncharts.com
			}

			// Get image from Imagick
			protected byte[] GetImageFromImagick(Dictionary<string, string> chart)
			{
				string svgdata = chart["stream"];
				if (Empty(svgdata))
					return null;
				svgdata = svgdata.Replace("+", " "); // Replace + to ' '

				// IMPORTANT NOTE: Magick.NET does not support SVG syntax: fill="url('#id')". Need to replace the attributes:
				// - fill="url('#id')" style="fill-opacity: n1; ..."
				// to:
				// - fill="color" style="fill-opacity: n2; ..."
				// from xml below:
				// <linearGradient ... id="id">
				// <stop stop-opacity="0.5" stop-color="#ff0000" offset="0%"></stop>
				// ...</linearGradient>

				var doc = new XmlDocument();
				doc.LoadXml(svgdata);
				var nodes = doc.SelectNodes("//*[@fill]");
				foreach (XmlElement node in nodes) {
					string fill = node.GetAttribute("fill");
					string style = node.GetAttribute("style");
					if (fill.StartsWith("url(") && fill.Substring(5, 1) == "#") {
						var id = fill.Substring(6, fill.Length - 8);
						var nsmgr = new XmlNamespaceManager(doc.NameTable);
						nsmgr.AddNamespace("ns", "http://www.w3.org/2000/svg");
						var gnode = doc.SelectSingleNode("//*/ns:linearGradient[@id='" + id + "']", nsmgr);
						if (gnode != null) {
							XmlElement snode = (XmlElement)gnode.SelectSingleNode("ns:stop[@offset='0%']", nsmgr);
							if (snode != null) {
								var fillcolor = snode.GetAttribute("stop-color");
								var fillopacity = snode.GetAttribute("stop-opacity");
								if (!Empty(fillcolor))
									node.SetAttribute("fill", fillcolor);
								if (!Empty(fillopacity) && !Empty(style)) {
									style = Regex.Replace(style, @"fill-opacity:\s*\S*;", "fill-opacity: " + fillopacity + ";");
									node.SetAttribute("style", style);
								}
							}
						}
					}
				}
				svgdata = doc.DocumentElement.OuterXml;
				ImageMagick.MagickNET.SetLogEvents(ImageMagick.LogEvents.All);
				ImageMagick.MagickReadSettings settings = new ImageMagick.MagickReadSettings();
				settings.ColorSpace = ImageMagick.ColorSpace.RGB;
				settings.Format = ImageMagick.MagickFormat.Svg;
				using var image = new ImageMagick.MagickImage(Encoding.UTF8.GetBytes(svgdata), settings);

				//image.BackgroundColor = new ImageMagick.MagickColor(System.Drawing.Color.Transparent);
				image.Format = ImageMagick.MagickFormat.Png;
				return image.ToByteArray();
			}
		}
	} // End Partial class
} // End namespace