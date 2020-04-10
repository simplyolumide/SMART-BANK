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
		/// Chart.js Renderer class
		/// </summary>
		public class ChartJsRenderer: IChartRenderer
		{

			public DbChart Chart;

			public Dictionary<string, dynamic> Data = new Dictionary<string, dynamic>();

			public Dictionary<string, dynamic> Options = new Dictionary<string, dynamic>();
			static int DefaultWidth = 600;
			static int DefaultHeight = 500;

			// Constructor
			public ChartJsRenderer(DbChart chart) => Chart = chart;

			// Get chart canvas
			// Get chart canvas
			public string GetContainer(int width, int height) {
				width = (width > 0) ? width : DefaultWidth;
				height = (height > 0) ? height : DefaultHeight;
				return $"<div id=\"div_{Chart.ID}\" class=\"ew-chart-container\"><canvas id=\"chart_{Chart.ID}\" width=\"{width}\" height=\"{height}\" class=\"ew-chart-canvas\"></canvas></div>";
			}

			// Get chart JavaScript
			public string GetScript(int width, int height)
			{
				bool drilldown = Chart.DrillDownInPanel;
				string typ = !Empty(Chart.Type) ? Chart.Type : ChartTypes.DefaultType; // Chart type (nnnn)
				string id = Chart.ID; // Chart ID

				// scroll = Chart.ScrollChart; // Not supported
				// trends = Chart.Trends;
				// series = Chart.Series;
				// align = Chart.Align;

				string chartType = ChartTypes.GetName(typ); // Chart type name
				string canvasId = "chart_" + id;
				LoadChart();
				var chartData = new Dictionary<string, dynamic> { {"type", chartType}, {"data", Data}, {"options", Options} };
				string chartJson = ConvertToJson(chartData);

				// Output JavaScript for Chart.js
				string dataformat = Chart.DataFormat;
				string chartid = "chart_" + id + (drilldown ? "_" + Random() : "");
				string obj = drilldown ? "drillDownCharts" : "exportCharts";
				string drilldownAction = "";
				if (!Empty(Chart.DrillDownUrl)) {
					if (Chart.UseDrillDownPanel)
						drilldownAction = "ew.showDrillDown(null, canvas, link.url, link.id, link.hdr);";
					else
						drilldownAction = "ew.redirect(link.url, null, \"get\");";
				}
				string wrk = $@"
<script>
loadjs.ready(""head"", function() {{
	var canvas = document.getElementById(""{canvasId}""),
		json = {chartJson};
	if (json.data && json.data.datasets.length > 0) {{ 
		json.options.onHover = function(e) {{
			var el = this.getElementAtEvent(e);
			e.target.style.cursor = (el.length) ? ""pointer"" : ""default"";
		}};
		json.options = jQuery.extend(true, {{}}, ew.chartJsOptions, json.options); // Deep merge
		var args = {{ id: ""{canvasId}"", ctx: canvas, config: json }};
		jQuery(document).trigger(""chart"", [args]);
		var chart = new Chart(args.ctx, args.config);
		if (ew.DEBUG)
			console.log(args.config);
		args.ctx.onclick = function(e) {{
			var activePoints = chart.getElementsAtEvent(e);
			if (activePoints[0]) {{
				var chartData = activePoints[0][""_chart""].config.data,
					idx = activePoints[0][""_index""],
					links = chartData.datasets[0].links,
					link = Array.isArray(links) ? links[idx] : {{}};
				{drilldownAction}
			}}
		}};
		window.exportCharts[""chart_{id}""] = chart; // Export chart
	}} else {{
		canvas.classList.add(""d-none"");
	}}
}});
</script>";

				// Show data for debug
				if (Config.Debug)
					SetDebugMessage("(Chart JSON):<pre>" + HtmlEncode(JsonConvert.SerializeObject(chartData, Newtonsoft.Json.Formatting.Indented)) + "</pre>");
				return wrk;
			}

			// Load chart
			protected void LoadChart()
			{
				string chtType = Chart.LoadParameter("type");
				List<dynamic> chartSeries = Chart.Series;
				List<Dictionary<string, object>> chartData = Chart.ViewData;
				int multiSeries = Chart.IsSingleSeries ? 0 : 1; // $multiSeries = 1 (Multi series charts)
				string seriesType = Chart.LoadParameter("seriestype");

				// Load default options
				Options = (Dictionary<string, dynamic>)Chart.Parameters.Get("options") ?? new Dictionary<string, dynamic>();
				string title = Chart.LoadParameter("caption");

				// Initialise X / Y Axes
				var xAxes = new List<Dictionary<string, dynamic>>();
				var yAxes = new List<Dictionary<string, dynamic>>();
				var scale = (Dictionary<string, dynamic>)Chart.Parameters.Get("scale") ?? new Dictionary<string, dynamic>(); // Default bar chart scale
				if (IsList(chartData)) {

					// Multi series
					if (multiSeries == 1) {
						var labels = new List<string>();
						var datasets = new List<Dictionary<string, dynamic>>();

						// Multi-Y values
						if (seriesType == "1") {

							// Set up labels
							int cntCat = chartData.Count;
							labels = chartData.Select(item => Chart.FormatName(item.Values.First())).ToList();

							// Set up datasets
							int cntData = chartData.Count;
							int cntSeries = chartSeries.Count;
							if (cntData > 0 && cntSeries > chartData[0].Count - 2) // DN
								cntSeries = chartData[0].Count - 2;
							for (int i = 0; i < cntSeries; i++) {
								string seriesName = IsList(chartSeries[i]) ? chartSeries[i][0] : Convert.ToString(chartSeries[i]);
								string yAxisId = IsList(chartSeries[i]) ? chartSeries[i][1] : "";
								if (!EmptyString(yAxisId) && !yAxes.Select(item => Convert.ToString(item["id"])).Contains(yAxisId)) // Dual axis
									yAxes.Add(new Dictionary<string, dynamic> { {"id", yAxisId}, {"position", yAxisId == "P" ? "left" : "right"} });
								string color = Chart.GetPaletteRgbaColor(i);
								string renderAs = Chart.GetRenderAs(i);
								bool showSeries = Config.ChartShowBlankSeries;
								var data = new List<double>();
								var links = new List<Dictionary<string, string>>();
								for (int j = 0; j < cntData; j++) {
									double val = ConvertToDouble(chartData[j].Values.ToList()[i + 2]);
									if (val != 0)
										showSeries = true;
									var lnk = GetChartLink(Chart.DrillDownUrl, Chart.Data[j]);
									links.Add(lnk);
									data.Add(val);
								}
								if (showSeries) {
									var dataset = GetDataset(data, color, links, seriesName, renderAs, yAxisId);
									datasets.Add(dataset);
								}
							}

						// Series field
						} else {

							// Get series names
							int cntSeries = IsList(chartSeries) ? chartSeries.Count : 0;

							// Set up labels
							int cntData = chartData.Count;
							labels = chartData.Select(item => Convert.ToString(item.Values.First())).Distinct().ToList();

							// Set up dataset
							int cntLabels = labels.Count();
							for (int i = 0; i < cntSeries; i++) {
								string seriesName = IsList(chartSeries[i]) ? chartSeries[i][0] : Convert.ToString(chartSeries[i]);
								string yAxisId = IsList(chartSeries[i]) ? chartSeries[i][1] : "";
								if (!EmptyString(yAxisId) && !yAxes.Select(item => Convert.ToString(item["id"])).Contains(yAxisId)) // Dual axis
									yAxes.Add(new Dictionary<string, dynamic> { {"id", yAxisId}, {"position", yAxisId == "P" ? "left" : "right"} });
								string color = Chart.GetPaletteRgbaColor(i);
								string renderAs = Chart.GetRenderAs(i);
								bool showSeries = Config.ChartShowBlankSeries;
								List<double> data = new List<double>();
								List<Dictionary<string, string>> links = new List<Dictionary<string, string>>();
								for (int j = 0; j < cntLabels; j++) {
									double val = 0;
									for (int k = 0; k < cntData; k++) {
										var values = chartData[k].Values.ToList();
										if (SameString(values[0], labels[j]) && SameString(values[1], seriesName)) {
											val = ConvertToDouble(values[2]);
											if (val != 0)
												showSeries = true;
											var lnk = GetChartLink(Chart.DrillDownUrl, Chart.Data[k]);
											links.Add(lnk);
											break;
										}
									}
									data.Add(val);
								}
								if (showSeries) {
									var dataset = GetDataset(data, color, links, seriesName, renderAs, yAxisId);
									datasets.Add(dataset);
								}
							}
						}

						// Set up Data/Options
						Data["labels"] = labels;
						Data["datasets"] = datasets;
						Options = Merge(Options, new Dictionary<string, dynamic> {
							{ "responsive", false },
							{ "legend", new Dictionary<string, dynamic> { {"display", true } } },
							{ "title", new Dictionary<string, dynamic> { {"display", true}, {"text", title} } }
						});

						// Set up tooltips for stacked charts
						if (Chart.IsStackedChart)
							Options["tooltips"] = new Dictionary<string, dynamic> { {"mode", "index" } };

						// Set up X/Y Axes
						if (Chart.IsCombinationChart) {
							if (scale.Count > 0)
								xAxes.Add(scale);
						} else {
							var stack = new Dictionary<string, dynamic> { {"stacked", Chart.IsStackedChart} };
							var dx = new Dictionary<string, dynamic>(stack);
							if (Chart.IsColumnChart)
								dx = Merge(scale, dx);
							if (dx.Count > 0)
								xAxes.Add(dx);
							var dy = new Dictionary<string, dynamic>(stack);
							if (Chart.IsBarChart)
								dy = Merge(scale, dy);
							if (dy.Count > 0)
								yAxes.Add(dy);
						}

					// Single series
					} else {
						int cntData = chartData.Count;
						List<string> labels = new List<string>();
						object backgroundColor = new List<string>();
						List<double> data = new List<double>();
						List<Dictionary<string, string>> links = new List<Dictionary<string, string>>();
						for (int i = 0; i < cntData; i++) {
							var values = chartData[i].Values.ToList();
							string name = Chart.FormatName(values[0]);
							string color = Chart.GetPaletteRgbaColor(i);
							if (!Empty(values[1])) 
								name += ", " + values[1];
							double val = ConvertToDouble(values[2]);
							var lnk = GetChartLink(Chart.DrillDownUrl, Chart.Data[i]);
							links.Add(lnk);
							labels.Add(name);
							((List<string>)backgroundColor).Add(color);
							data.Add(val);
						}

						// Set bar defaults
						if (Chart.IsColumnChart && scale.Count > 0)
							xAxes.Add(scale);
						else if (Chart.IsBarChart && scale.Count > 0)
							yAxes.Add(scale);

						// Line/Area chart, use first color
						if (Chart.IsLineChart || Chart.IsAreaChart)
							backgroundColor = Chart.GetPaletteRgbaColor(0); // Use first color

						// Get dataset
						var dataset = GetDataset(data, backgroundColor, links);
						var datasets = new List<Dictionary<string, dynamic>> { dataset };

						// Set up Data/Options
						Data["labels"] = labels;
						Data["datasets"] = datasets;
						Options = Merge(Options, new Dictionary<string, dynamic> {
							{ "responsive", false },
							{ "legend", new Dictionary<string, dynamic> { {"display", false } } },
							{ "title", new Dictionary<string, dynamic> { {"display", true}, {"text", title} } }
						});
					}

					// Set X / Y Axes
					Options["scales"] = new Dictionary<string, dynamic> { {"xAxes", xAxes}, {"yAxes", yAxes} };
				}

				// Chart_Rendered event
				Chart_Rendered(this);
			}

			// Get chart link
			protected Dictionary<string, string> GetChartLink(string src, Dictionary<string, object> row)
			{
				if (!Empty(src) && row != null) {
					int cntrow = row.Count;
					string lnk = src;
					var sdt = Chart.SeriesDateType;
					var xdt = Chart.XAxisDateFormat;
					if (!Empty(sdt))
						xdt = sdt;
					var m = Regex.Match(lnk, "&t=([^&]+)&");
					string tblCaption = (m.Success) ? Language.TablePhrase(m.Groups[1].Value, "TblCaption") : "";
					var values = row.Values.ToList();
					for (int i = 0; i < cntrow; i++) { // Link format: %i:Parameter:FieldType%
						m = Regex.Match(lnk, $@"%{i}:([^%:]*):([\d]+)%");
						if (m.Success) {
							int fldtype = FieldDataType(ConvertToInt(m.Groups[2].Value));
							if (i == 0)  // Format X SQL
								lnk = lnk.Replace(m.Groups[0].Value, Encrypt(Chart.GetXSql("@" + m.Groups[1].Value, fldtype, values[i], xdt)));
							else if (i == 1) // Format Series SQL
								lnk = lnk.Replace(m.Groups[0].Value, Encrypt(Chart.GetSeriesSql("@" + m.Groups[1].Value, fldtype, values[i], sdt)));
							else
								lnk = lnk.Replace(m.Groups[0].Value, Encrypt("@"  + m.Groups[1].Value + " = " + QuotedValue(values[i], fldtype, Chart.Table.Dbid)));
						}
					}
					return new Dictionary<string, string> { {"url", lnk}, {"id", Chart.ID}, {"hdr", tblCaption} };
				}
				return null;
			}
			protected Dictionary<string, dynamic> GetDataset(object data, dynamic color, List<Dictionary<string, string>> links, object seriesName = null, string renderAs = "", string yAxisId = "")
			{
				var dataset = Chart.Parameters.Get("dataset") != null ? new Dictionary<string, dynamic>((Dictionary<string, dynamic>)Chart.Parameters.Get("dataset")) : new Dictionary<string, dynamic>(); // Load default dataset options
				dataset["data"] = data; // Load data
				dataset["backgroundColor"] = color; // Background color
				if (IsList<string>(color)) {
					dataset["borderColor"] = ((List<string>)color).Select(c => changeAlpha(c));
					dataset["borderWidth"] = 1;
				} else if (color is string) {
					dataset["borderColor"] = changeAlpha(color);
					dataset["borderWidth"] = 1;
				}
				bool hasLink = links.Any();
				dataset["links"] = hasLink ? links : null; // Drill down link
				if (seriesName != null) { // Multi series
					dataset["label"] = seriesName;
					if (Chart.IsCombinationChart) { // Combination chart, set render type / stack id / axis id
						string renderType = GetRenderType(renderAs);
						dataset["type"] = renderType;
						if (renderType == "bar" && Chart.IsStackedChart) // Set up stack id
							dataset["stack"] = Chart.ID;
						if (Chart.IsDualAxisChart) // Set up axis id
							dataset["yAxisID"] = yAxisId;
					} else if (Chart.IsStackedChart) { // Stacked chart, set up stack id
						dataset["stack"] = Chart.ID;
					}
				}
				if (Chart.IsLineChart || Chart.IsCombinationChart && SameText(renderAs, "line")) // Line chart, set no fill
					dataset["fill"] = false;
				return dataset;

				// Change alpha
				string changeAlpha(string c) => Regex.Replace(c, @"[\d\.]+(?=\))", "1.0"); // Change alpha to 1.0
			}

			// Get render type for combination chart
			protected string GetRenderType(string renderAs) =>
				renderAs.ToLower() switch { 
					"line" => "line",
					"area" => Chart.IsStackedChart ? "bar" : "line",
					_ => "bar"
				};
		}
	} // End Partial class
} // End namespace