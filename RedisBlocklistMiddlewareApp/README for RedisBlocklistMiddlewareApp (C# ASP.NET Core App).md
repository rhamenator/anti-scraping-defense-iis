# **README for RedisBlocklistMiddlewareApp (C\# ASP.NET Core App)**

This document describes the RedisBlocklistMiddlewareApp, a C\# ASP.NET Core application designed to act as the primary request filtering layer for the anti-scraping-defense-iis system when hosted on IIS.

## **Purpose**

This application replaces the filtering logic originally handled by Nginx and Lua scripts in the containerized version. It intercepts incoming web requests early in the processing pipeline and performs several checks to block malicious traffic or redirect suspicious requests to the Tarpit API service.

Its core responsibilities include:

1. **IP Blocklist Check:** Queries a configured Redis database to see if the incoming request's IP address is on the blocklist. If found, the request is immediately blocked with a 403 Forbidden response.  
2. **Known Bad User-Agent Blocking:** Checks the request's User-Agent header against a configurable list of known malicious or undesirable bot signatures. If matched, the request is blocked with a 403 Forbidden response.  
3. **Heuristic Analysis:** Performs basic checks on request headers (e.g., presence of User-Agent, Accept-Language, type of Accept header) based on configurable rules.  
4. **Tarpit Redirection:** If the heuristic analysis flags a request as suspicious (but not blocked outright), this application internally rewrites the request's path to target the separate Tarpit API service before allowing it to proceed further down the pipeline.  
5. **Allowing Legitimate Traffic:** Requests that pass all checks are allowed to proceed to the next stage (typically routing to the appropriate backend Python service application like Admin UI or the actual protected application).

## **Components**

* **Program.cs**: The main entry point for the ASP.NET Core application. It configures and runs the web host (Kestrel), sets up dependency injection (e.g., for Redis connections and configuration), and builds the request processing pipeline, including registering the RedisBlocklistMiddleware.  
* **RedisBlocklistMiddleware.cs**: Contains the custom ASP.NET Core middleware class that implements the core filtering logic described above (Redis check, UA check, heuristics, tarpit rewrite).  
* **appsettings.json**: Contains configuration settings for the application, including Redis connection details, blocklist key formats, heuristic rules, and the Tarpit application's rewrite path. See the accompanying README for appsettings.json for details on these settings.  
* **.csproj file**: The C\# project file, defining dependencies (like StackExchange.Redis) and target framework (.NET 6/8 recommended).

## **Hosting in IIS**

This application is designed to be hosted **in-process** within an IIS application pool using the **ASP.NET Core Module (ANCM) v2**.

* **Requires:** .NET Hosting Bundle installed on the Windows Server.  
* **Configuration:** IIS is configured to use ANCM to launch and manage this .NET application. Typically, no specific \<handlers\> entry is needed in web.config for ANCM itself if the Hosting Bundle is installed correctly.  
* **Placement:** This application can be configured as the root application of the IIS website or as a dedicated sub-application. The request pipeline configured in Program.cs (specifically the UseMiddleware call) ensures the filtering logic runs for requests handled by this application.

## **Workflow**

1. An incoming request hits IIS.  
2. IIS routes the request to this RedisBlocklistMiddlewareApp application (either because it's the root application or via specific routing rules if it's a sub-application).  
3. ANCM starts the .NET process (if not already running) defined by this project.  
4. The request enters the ASP.NET Core pipeline defined in Program.cs.  
5. app.UseMiddleware\<RedisBlocklistMiddleware\>() invokes the custom middleware.  
6. The middleware performs:  
   * IP Address extraction.  
   * Redis blocklist check \-\> Returns 403 if blocked.  
   * Known Bad User-Agent check \-\> Returns 403 if blocked.  
   * Heuristic checks.  
7. Based on heuristics:  
   * If suspicious: The middleware modifies context.Request.Path to the Tarpit path and calls await \_next(context). The request continues down the pipeline, now targeting the Tarpit service (which should be handled by a separate IIS application or routing rule further down).  
   * If not suspicious: The middleware calls await \_next(context) without modifying the path.  
8. The request continues to subsequent middleware or endpoint routing defined in Program.cs or potentially gets passed back out to IIS for further routing if no endpoint within this app matches.

## **Dependencies**

* .NET SDK (6.0 LTS or 8.0 LTS recommended) for building.  
* .NET Hosting Bundle installed on the IIS server.  
* StackExchange.Redis NuGet package.  
* An accessible Redis instance.  
* Configuration provided via appsettings.json and/or environment variables.