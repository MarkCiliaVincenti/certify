﻿using System.Text;
using Certify.Management;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.AspNetCore.SignalR;
using Microsoft.OpenApi.Models;

namespace Certify.Server.Core
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();

            services
                .AddSignalR()
                .AddMessagePackProtocol();

            services.AddDataProtection(a =>
            {
                a.ApplicationDiscriminator = "certify";
            });
            services.AddResponseCompression(opts =>
            {
                opts.MimeTypes = ResponseCompressionDefaults.MimeTypes.Concat(new[] { "application/octet-stream", "application/json" });
            });

            services.AddCors(options =>
            {
                options.AddDefaultPolicy(
                                  builder =>
                                  {

                                      builder.AllowAnyOrigin();
                                      builder.AllowAnyMethod();
                                  });
            });

#if DEBUG
            services.AddEndpointsApiExplorer();

            // Register the Swagger generator, defining 1 or more Swagger documents
            // https://docs.microsoft.com/en-us/aspnet/core/tutorials/getting-started-with-swashbuckle?view=aspnetcore-3.1&tabs=visual-studio
            services.AddSwaggerGen(c =>
            {

                c.SwaggerDoc("v1", new OpenApiInfo
                {
                    Title = "Certify Core Internal API",
                    Version = "v1",
                    Description = "Provides a private API for use by the Certify The Web UI and related components. This internal API changes between versions, you should use the public API when building integrations instead."
                });

                // declare authorization method
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
                    Name = "Authorization",
                    Scheme = "bearer",
                    BearerFormat = "JWT",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.Http
                });

                // set security requirement
                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        }, new List<string>()
                    }
                });

            });
#endif

            var useHttps = bool.Parse(Configuration["API:Service:UseHttps"]);

            if (useHttps)
            {
                services.AddHttpsRedirection(options =>
                {
                    options.RedirectStatusCode = Microsoft.AspNetCore.Http.StatusCodes.Status307TemporaryRedirect;
                    options.HttpsPort = 443;
                });
            }

            // inject instance of certify manager
            var certifyManager = new Management.CertifyManager();
            certifyManager.Init().Wait();

            services.AddSingleton<Management.ICertifyManager>(certifyManager);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            var statusHubContext = app.ApplicationServices.GetRequiredService<IHubContext<Service.StatusHub>>();
            if (statusHubContext == null)
            {
                throw new Exception("Status Hub not registered");
            }

            var certifyManager = app.ApplicationServices.GetRequiredService(typeof(ICertifyManager)) as CertifyManager;

            if (certifyManager == null)
            {
                throw new Exception("Certify Manager not registered");
            }

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();

                // Enable middleware to serve generated Swagger as a JSON endpoint.
                app.UseSwagger();

                // Enable middleware to serve swagger-ui (HTML, JS, CSS, etc.),
                // specifying the Swagger JSON endpoint.
                app.UseSwaggerUI(c =>
                {
                    c.RoutePrefix = "docs";
                    c.DocumentTitle = "Certify Core Server API";
                    c.SwaggerEndpoint("/swagger/v1/swagger.json", "Certify Core Server API");
                });
            }

            // set status report context provider
            certifyManager.SetStatusReporting(new Service.StatusHubReporting(statusHubContext));

            var useHttps = bool.Parse(Configuration["API:Service:UseHttps"]);

            if (useHttps)
            {
                app.UseHttpsRedirection();
            }

            app.UseRouting();

            app.UseCors();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapHub<Service.StatusHub>("/api/status");
                endpoints.MapControllers();

#if DEBUG
                endpoints.MapGet("/debug/routes", (IEnumerable<EndpointDataSource> endpointSources) =>
                {
                    var sb = new StringBuilder();
                    var endpoints = endpointSources.SelectMany(es => es.Endpoints);
                    foreach (var endpoint in endpoints)
                    {
                        if (endpoint is RouteEndpoint routeEndpoint)
                        {
                            sb.AppendLine($"{routeEndpoint.DisplayName} {routeEndpoint.RoutePattern.RawText}");
                        }
                    }

                    return sb.ToString();
                });
#endif
            });
        }
    }
}
