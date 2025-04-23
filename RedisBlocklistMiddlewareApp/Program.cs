
// This is a simple ASP.NET Core application that uses Redis to block certain IP addresses.
// The RedisBlocklistMiddleware checks incoming requests against a Redis blocklist.
// If the request's IP is found in the blocklist, it returns a 403 Forbidden response.
// Otherwise, it allows the request to proceed to the next middleware or endpoint.
// The Redis connection is managed by a singleton IConnectionMultiplexer instance.
// The application is configured to log connection status and errors.
// The Redis connection string can be configured in appsettings.json or environment variables.
// The application also includes a simple health check endpoint and a fallback for unmatched requests.
// The middleware is added to the pipeline early, ensuring it runs before any endpoint execution.
// The application is built using the ASP.NET Core minimal hosting model, which simplifies startup and configuration.
// The code is structured to be clear and maintainable, with comments explaining each section.
// The application is designed to be extensible, allowing for additional services and middleware to be added as needed.
// The use of dependency injection and logging follows best practices for ASP.NET Core applications.
// The application is ready to be run in a development or production environment, with appropriate configuration settings. 
// The Redis connection is established using the StackExchange.Redis library, which is a popular choice for interacting with Redis in .NET applications.
// The application is designed to be lightweight and efficient, focusing on the core functionality of blocking IP addresses using Redis.
// The use of middleware allows for easy integration into existing ASP.NET Core applications, making it a flexible solution for IP blocking.
// The application can be further enhanced with additional features, such as dynamic blocklist updates, logging of blocked requests, or integration with other security measures.using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using StackExchange.Redis; // Required for Redis
using System;
using RedisBlocklistMiddlewareApp; // Use the namespace where your middleware class resides

var builder = WebApplication.CreateBuilder(args);

// --- Configuration ---
// Configuration is automatically loaded from appsettings.json, appsettings.{Environment}.json,
// environment variables, command-line arguments etc.

// --- Add Services to the Dependency Injection (DI) Container ---

// 1. Logging (already configured by default)
// You can customize logging further here if needed. e.g., builder.Logging.AddConsole();

// 2. Redis Connection Multiplexer
// Register IConnectionMultiplexer as a singleton. This manages Redis connections efficiently.
builder.Services.AddSingleton<IConnectionMultiplexer>(sp =>
{
    var logger = sp.GetRequiredService<ILogger<Program>>(); // Get logger for connection status
    // Get Redis configuration string from appsettings.json or environment variables
    // Example key in appsettings.json: "Redis:ConnectionString"
    // Value: "localhost:6379,password=yourpassword,allowAdmin=true"
    // Looks for "ConnectionStrings:RedisConnection" first, then "Redis:ConnectionString"
    string? redisConnectionString = builder.Configuration.GetConnectionString("RedisConnection")
                                   ?? builder.Configuration.GetValue<string>("Redis:ConnectionString");

    if (string.IsNullOrEmpty(redisConnectionString))
    {
        logger.LogError("Redis connection string ('ConnectionStrings:RedisConnection' or 'Redis:ConnectionString') is not configured.");
        // Throw an exception or handle appropriately - middleware needs Redis to function.
        throw new InvalidOperationException("Redis connection string is not configured.");
    }

    // Log only the host/port part for security
    logger.LogInformation("Attempting to connect to Redis: {RedisHost}", redisConnectionString.Split(',')[0]);

    try
    {
        // Connect to Redis
        var connection = ConnectionMultiplexer.Connect(redisConnectionString);
        logger.LogInformation("Successfully connected to Redis.");
        return connection;
    }
    catch (RedisConnectionException ex)
    {
        // Log critical error if connection fails
        logger.LogCritical(ex, "FATAL: Could not connect to Redis using connection string starting with: {RedisHost}", redisConnectionString.Split(',')[0]);
        // Depending on requirements, you might want the application to fail startup if Redis isn't available.
        throw; // Re-throw to potentially stop application startup
    }
    catch (Exception ex)
    {
         // Catch any other unexpected connection errors
         logger.LogCritical(ex, "FATAL: An unexpected error occurred during Redis connection.");
         throw;
    }
});

// 3. Add other services if needed (e.g., AddControllers if you add API endpoints later)
// builder.Services.AddControllers();

// Remove services added by the webapi template if not needed
// builder.Services.AddEndpointsApiExplorer(); // Only needed if using minimal APIs with OpenAPI
// builder.Services.AddSwaggerGen(); // Only needed for OpenAPI/Swagger UI


// --- Build the Application ---
var app = builder.Build();

// --- Configure the HTTP Request Pipeline ---

// Middleware runs in the order it's added.

// Optional: Configure Swagger/OpenAPI for development (if you keep/add APIs)
// if (app.Environment.IsDevelopment())
// {
//     app.UseSwagger();
//     app.UseSwaggerUI();
// }

// Optional: HTTPS Redirection (usually recommended)
// app.UseHttpsRedirection();

// *** Add the Redis Blocklist Middleware ***
// This should run early in the pipeline, after routing/auth (if any) but before endpoint execution.
app.UseMiddleware<RedisBlocklistMiddleware>();

// Optional: Add routing if you plan to have endpoints later
// app.UseRouting();

// Optional: Add Authorization middleware if needed later
// app.UseAuthorization();

// Optional: Map controllers if you add API endpoints later
// app.MapControllers();

// Add a default response or health check endpoint (optional)
// This minimal app might not have actual endpoints if it only serves middleware.
// Adding a simple health check is good practice.
app.MapGet("/health", () => Results.Ok(new { status = "healthy" }));

// Fallback for any request that wasn't handled (e.g., blocked by middleware)
// Could return 404 or a default message.
// If middleware blocks, this won't be reached for those requests.
app.Run(async context =>
{
    // This code runs if the request wasn't blocked by the middleware
    // and no other endpoint matched. You might want to return 404 here.
    context.Response.StatusCode = StatusCodes.Status404NotFound;
    await context.Response.WriteAsync("Endpoint not found.");
});


// Start the application
app.Run();

// --- End of Program.cs ---
// This is a simple ASP.NET Core application that uses Redis to block certain IP addresses.
// The RedisBlocklistMiddleware checks incoming requests against a Redis blocklist.
// If the request's IP is found in the blocklist, it returns a 403 Forbidden response.
// Otherwise, it allows the request to proceed to the next middleware or endpoint.
// The Redis connection is managed by a singleton IConnectionMultiplexer instance.
// The application is configured to log connection status and errors.
// The Redis connection string can be configured in appsettings.json or environment variables.
// The application also includes a simple health check endpoint and a fallback for unmatched requests.
// The middleware is added to the pipeline early, ensuring it runs before any endpoint execution.
// The application is built using the ASP.NET Core minimal hosting model, which simplifies startup and configuration.
// The code is structured to be clear and maintainable, with comments explaining each section.
// The application is designed to be extensible, allowing for additional services and middleware to be added as needed.
// The use of dependency injection and logging follows best practices for ASP.NET Core applications.
// The application is ready to be run in a development or production environment, with appropriate configuration settings. 
// The Redis connection is established using the StackExchange.Redis library, which is a popular choice for interacting with Redis in .NET applications.
// The application is designed to be lightweight and efficient, focusing on the core functionality of blocking IP addresses using Redis.
// The use of middleware allows for easy integration into existing ASP.NET Core applications, making it a flexible solution for IP blocking.
// The application can be further enhanced with additional features, such as dynamic blocklist updates, logging of blocked requests, or integration with other security measures.