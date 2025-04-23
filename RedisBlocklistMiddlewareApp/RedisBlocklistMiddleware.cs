using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration; // Required for IConfiguration
using Microsoft.Extensions.Logging;
using StackExchange.Redis; // Make sure this package is added (dotnet add package StackExchange.Redis)
using System;
using System.Collections.Generic; // For List/HashSet
using System.Linq; // For LINQ methods like Any()
using System.Net;
using System.Text.RegularExpressions; // For potential regex matching
using System.Threading.Tasks;

// Enable nullable reference types context for better null checking
#nullable enable

namespace RedisBlocklistMiddlewareApp // Use the namespace of your project
{
    /// <summary>
    /// ASP.NET Core Middleware to check incoming request IPs against a Redis blocklist
    /// and perform basic heuristic checks (User-Agent, Headers) to block or redirect to tarpit.
    /// </summary>
    public class RedisBlocklistMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<RedisBlocklistMiddleware> _logger;
        private readonly IConnectionMultiplexer _redisConnection;
        private readonly string _redisKeyPrefix; // Now guaranteed non-null after constructor
        private readonly int _redisDbNumber;
        private readonly HashSet<string> _knownBadUaSubstrings; // Use HashSet for efficient lookups
        private readonly string _tarpitRewritePath; // Now guaranteed non-null after constructor
        private readonly bool _checkEmptyUa;
        private readonly bool _checkMissingAcceptLanguage;
        private readonly bool _checkGenericAccept;

        /// <summary>
        /// Constructor for the middleware.
        /// </summary>
        public RedisBlocklistMiddleware(
            RequestDelegate next,
            ILogger<RedisBlocklistMiddleware> logger,
            IConnectionMultiplexer redisConnection, // Injected via DI
            IConfiguration configuration) // Inject IConfiguration
        {
            _next = next ?? throw new ArgumentNullException(nameof(next));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _redisConnection = redisConnection ?? throw new ArgumentNullException(nameof(redisConnection));

            // --- Get Redis Configuration ---
            // Use null-coalescing operator (??) to ensure a non-null default is assigned
            _redisKeyPrefix = configuration.GetValue<string?>("Redis:BlocklistKeyPrefix") ?? "blocklist:"; // Fix CS8618/CS8601
            _redisDbNumber = configuration.GetValue<int>("Redis:DbBlocklist", 2);

            // --- Get Heuristic Configuration ---
            var badUaList = configuration.GetSection("Heuristics:KnownBadUaSubstrings").Get<List<string>>() ?? new List<string>();
            _knownBadUaSubstrings = new HashSet<string>(badUaList.Select(ua => ua.ToLowerInvariant()), StringComparer.OrdinalIgnoreCase);

            // Use null-coalescing operator (??) to ensure a non-null default is assigned
            _tarpitRewritePath = configuration.GetValue<string?>("Heuristics:TarpitRewritePath") ?? "/anti-scrape-tarpit/"; // Fix CS8618/CS8601

            // Ensure it ends with / (now safe to call EndsWith because _tarpitRewritePath is non-null) - Fix CS8602
            if (!_tarpitRewritePath.EndsWith("/"))
            {
                _tarpitRewritePath += "/";
            }

            _checkEmptyUa = configuration.GetValue<bool>("Heuristics:CheckEmptyUa", true);
            _checkMissingAcceptLanguage = configuration.GetValue<bool>("Heuristics:CheckMissingAcceptLanguage", true);
            _checkGenericAccept = configuration.GetValue<bool>("Heuristics:CheckGenericAccept", true);


            _logger.LogInformation("RedisBlocklistMiddleware initialized.");
            _logger.LogDebug(" - Redis Prefix: '{Prefix}', DB: {DbNumber}", _redisKeyPrefix, _redisDbNumber);
            _logger.LogDebug(" - Known Bad UA Substrings loaded: {Count}", _knownBadUaSubstrings.Count);
            _logger.LogDebug(" - Tarpit Rewrite Path: {Path}", _tarpitRewritePath);
            _logger.LogDebug(" - Check Empty UA: {Check}", _checkEmptyUa);
            _logger.LogDebug(" - Check Missing Accept-Language: {Check}", _checkMissingAcceptLanguage);
            _logger.LogDebug(" - Check Generic Accept: {Check}", _checkGenericAccept);
        }

        /// <summary>
        /// Processes the HTTP request. Checks IP blocklist, then User-Agent, then Headers.
        /// Blocks, allows, or rewrites to tarpit path.
        /// </summary>
        public async Task InvokeAsync(HttpContext context)
        {
            // --- 1. Get Remote IP Address ---
            string? remoteIpAddressString = GetRemoteIpAddress(context); // Returns nullable string
            if (string.IsNullOrEmpty(remoteIpAddressString))
            {
                _logger.LogWarning("Could not determine remote IP address for request {TraceIdentifier}. Skipping checks.", context.TraceIdentifier);
                await _next(context); // Allow request if IP cannot be determined
                return;
            }
            // From here, remoteIpAddressString is guaranteed non-null and non-empty

            // --- 2. Check Redis Blocklist ---
            // _redisKeyPrefix is guaranteed non-null from constructor
            string redisKey = $"{_redisKeyPrefix}ip:{remoteIpAddressString}";
            bool isIpBlocked = await CheckRedisBlocklistAsync(redisKey, remoteIpAddressString);

            if (isIpBlocked)
            {
                _logger.LogWarning("BLOCKING request from IP {RemoteIp} found in Redis blocklist (Key: {RedisKey}, DB: {DbNumber}).", remoteIpAddressString, redisKey, _redisDbNumber);
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsync("Access Denied.");
                return; // Stop processing
            }

            // --- 3. Check Known Bad User Agents ---
            string userAgent = context.Request.Headers.UserAgent.ToString() ?? string.Empty; // Ensure non-null
            string userAgentLower = userAgent.ToLowerInvariant();

            if (_knownBadUaSubstrings.Count > 0 && !string.IsNullOrEmpty(userAgentLower))
            {
                if (_knownBadUaSubstrings.Any(badUa => userAgentLower.Contains(badUa)))
                {
                     _logger.LogWarning("BLOCKING request from IP {RemoteIp} due to known bad User-Agent: '{UserAgent}'.", remoteIpAddressString, userAgent);
                     context.Response.StatusCode = StatusCodes.Status403Forbidden;
                     await context.Response.WriteAsync("Access Denied.");
                     return; // Stop processing
                }
            }

            // --- 4. Perform Other Heuristic Checks ---
            bool shouldTarpit = false;
            List<string> tarpitReasons = new List<string>();

            if (_checkEmptyUa && string.IsNullOrEmpty(userAgent))
            {
                shouldTarpit = true;
                tarpitReasons.Add("Empty UA");
            }

            if (_checkMissingAcceptLanguage && !context.Request.Headers.ContainsKey("Accept-Language"))
            {
                shouldTarpit = true;
                tarpitReasons.Add("Missing Accept-Language");
            }

            string acceptHeader = context.Request.Headers.Accept.ToString() ?? string.Empty; // Ensure non-null
            if (_checkGenericAccept && acceptHeader == "*/*")
            {
                shouldTarpit = true;
                tarpitReasons.Add("Generic Accept */*");
            }

            // --- 5. Take Action: Rewrite to Tarpit or Allow ---
            if (shouldTarpit)
            {
                string originalPath = context.Request.Path.ToString();
                string queryString = context.Request.QueryString.ToString();
                // _tarpitRewritePath is guaranteed non-null from constructor
                string newPath = $"{_tarpitRewritePath.TrimEnd('/')}{originalPath}{queryString}";

                _logger.LogWarning("TARPITTING request from IP {RemoteIp}. Reasons: {Reasons}. Rewriting path from '{OriginalPath}' to '{NewPath}'",
                                   remoteIpAddressString, string.Join(", ", tarpitReasons), originalPath, newPath);

                context.Request.Path = new PathString(newPath);
                context.Request.Headers.Append("X-Tarpit-Reason", string.Join(";", tarpitReasons));

                await _next(context);
            }
            else
            {
                _logger.LogDebug("ALLOWING request from IP {RemoteIp}. No block/tarpit conditions met.", remoteIpAddressString);
                await _next(context);
            }
        }

        /// <summary>
        /// Helper to get the remote IP address, prioritizing X-Forwarded-For. Returns null if IP cannot be determined.
        /// </summary>
        private string? GetRemoteIpAddress(HttpContext context) // Return type changed to nullable
        {
            string? remoteIpAddressString = null;
            if (context.Request.Headers.TryGetValue("X-Forwarded-For", out var forwardedFor))
            {
                remoteIpAddressString = forwardedFor.FirstOrDefault()?.Split(',').FirstOrDefault()?.Trim();
            }

            if (string.IsNullOrEmpty(remoteIpAddressString) && context.Connection.RemoteIpAddress != null)
            {
                remoteIpAddressString = context.Connection.RemoteIpAddress.ToString();
            }

            if (IPAddress.TryParse(remoteIpAddressString, out IPAddress? parsedIp) && parsedIp != null && parsedIp.IsIPv4MappedToIPv6)
            {
                remoteIpAddressString = parsedIp.MapToIPv4().ToString();
            }

            // Return null if still empty after checks
            return string.IsNullOrEmpty(remoteIpAddressString) ? null : remoteIpAddressString;
        }

        /// <summary>
        /// Helper to check the Redis blocklist asynchronously. Returns false on error (fail open).
        /// </summary>
        private async Task<bool> CheckRedisBlocklistAsync(string redisKey, string remoteIpAddressString) // remoteIpAddressString is non-null when called
        {
            IDatabase? redisDb = null; // Declare as nullable
            try
            {
                redisDb = _redisConnection.GetDatabase(_redisDbNumber);
                if (redisDb != null) // Check if GetDatabase succeeded
                {
                    return await redisDb.KeyExistsAsync(redisKey);
                }
                else
                {
                    _logger.LogError("Failed to get Redis database instance (DB {DbNumber}) for blocklist check.", _redisDbNumber);
                    return false; // Fail open
                }
            }
            catch (RedisConnectionException ex)
            {
                _logger.LogError(ex, "Redis connection error checking blocklist for IP {RemoteIp}. Allowing request.", remoteIpAddressString);
                return false; // Fail open
            }
            catch (TimeoutException ex)
            {
                _logger.LogWarning(ex, "Redis timeout checking blocklist for IP {RemoteIp}. Allowing request.", remoteIpAddressString);
                return false; // Fail open
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error checking Redis blocklist for IP {RemoteIp}. Allowing request.", remoteIpAddressString);
                return false; // Fail open
            }
        }
    }
}

// Disable nullable context if it causes issues elsewhere, though it's generally recommended
// to keep it enabled for better null safety.
// #nullable disable