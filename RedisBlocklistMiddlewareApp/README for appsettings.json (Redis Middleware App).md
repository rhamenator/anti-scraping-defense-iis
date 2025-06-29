# **README for appsettings.json (Redis Blocklist Middleware App)**

This document explains the configuration settings within the appsettings.json file for the RedisBlocklistMiddlewareApp C\# application. This application hosts the ASP.NET Core middleware responsible for checking incoming request IPs against the Redis blocklist and performing basic heuristic checks.

## **Purpose**

The appsettings.json file provides configuration values used by the ASP.NET Core application at runtime. This includes settings for logging, host filtering, database connections (Redis), and custom application parameters. Configuration values can be overridden by environment-specific files (e.g., appsettings.Development.json), environment variables, or command-line arguments.

## **Configuration Sections**

### **Logging**

* **Purpose:** Configures the built-in ASP.NET Core logging framework.  
* **LogLevel**: Defines the minimum severity level for logs to be recorded for different categories.  
  * Default: The fallback level if a more specific category isn't matched. (Information logs informational messages, startup details, etc.)  
  * Microsoft.AspNetCore: Sets the level specifically for ASP.NET Core's internal logging. (Warning reduces noise from the framework itself).  
  * StackExchange.Redis: Sets the level for the Redis client library. (Information is useful for seeing connection attempts/status).  
  * RedisBlocklistMiddlewareApp: Sets the level specifically for logs generated by your custom middleware code (using the project's namespace). Adjust this to Debug for more detailed troubleshooting.

### **AllowedHosts**

* **Purpose:** Standard ASP.NET Core setting used by the host filtering middleware to specify which host headers are allowed for incoming requests.  
* **\***: Allows any host header. Suitable for development/testing, but should ideally be restricted to your specific domain(s) in production for security.

### **ConnectionStrings**

* **Purpose:** Standard location for storing database connection strings.  
* **RedisConnection**: **(Required)** This is the connection string used by Program.cs to connect to your Redis instance via the StackExchange.Redis client.  
  * **Format:** Follows the [StackExchange.Redis configuration format](https://stackexchange.github.io/StackExchange.Redis/Configuration.html).  
  * **Examples:**  
    * "localhost:6379" (Default, no password)  
    * "your\_redis\_host:6379"  
    * "localhost:6379,password=yourSecretPassword"  
    * "redis-sentinel-master,serviceName=yourServiceName,password=yourPassword" (For Sentinel)  
  * **Action Needed:** You **MUST** update the placeholder value with the correct connection string for your Redis server, including the password if applicable.

### **Redis**

* **Purpose:** Contains custom configuration settings specifically used by the RedisBlocklistMiddleware.cs. These values are read using IConfiguration in the middleware's constructor.  
* **BlocklistKeyPrefix**: **(Required)** Defines the prefix prepended to the IP address when checking for a blocklist key in Redis.  
  * Example Value: "blocklist:"  
  * Resulting Key Checked: blocklist:ip:1.2.3.4 (as constructed in the middleware code)  
  * **Action Needed:** Ensure this prefix **exactly matches** the prefix used by the Python ai\_service when it *adds* IPs to the blocklist. Consistency is crucial.  
* **DbBlocklist**: **(Required)** Specifies the numeric Redis database index (typically 0-15) where the blocklist keys are stored.  
  * Example Value: 2  
  * **Action Needed:** Ensure this database number matches the REDIS\_DB\_BLOCKLIST environment variable used by the Python services.

### **Heuristics**

* **Purpose:** Contains settings for the heuristic checks performed by the RedisBlocklistMiddleware after the Redis blocklist check.  
* **KnownBadUaSubstrings**: **(Required)** An array of strings. If any of these substrings (matched case-insensitively) are found within the request's User-Agent header, the middleware will immediately block the request with a 403 Forbidden status. Add or remove entries based on observed malicious traffic patterns.  
* **TarpitRewritePath**: **(Required)** Specifies the base URL path *within your IIS site* where the Tarpit API application is hosted (e.g., /anti-scrape-tarpit/). When the middleware decides to tarpit a request based on other heuristics, it will internally rewrite the request to {TarpitRewritePath}{OriginalPath}.  
  * **Action Needed:** Ensure this value correctly points to your Tarpit application's configured base URL path within IIS and typically ends with a /.  
* **CheckEmptyUa**: **(Optional, Default: true)** If true, requests with a missing or empty User-Agent header will be rewritten to the TarpitRewritePath.  
* **CheckMissingAcceptLanguage**: **(Optional, Default: true)** If true, requests missing the Accept-Language header will be rewritten to the TarpitRewritePath (potentially excluding asset requests depending on middleware logic).  
* **CheckGenericAccept**: **(Optional, Default: true)** If true, requests where the Accept header is exactly \*/\* will be rewritten to the TarpitRewritePath (potentially excluding asset requests).

## **Overrides**

Remember that settings in appsettings.json can be overridden by:

1. appsettings.Development.json (or other environment-specific files).  
2. Environment variables (e.g., ConnectionStrings\_\_RedisConnection=your\_string, Redis\_\_DbBlocklist=3, Heuristics\_\_CheckEmptyUa=false). Environment variables often use \_\_ (double underscore) to denote hierarchy.  
3. Command-line arguments.

Check your hosting environment (like the web.config for IIS deployment) to see how environment variables might be set, potentially overriding these JSON values.