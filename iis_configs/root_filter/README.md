# **README for Root Filter web.config (IIS) \- Simplified**

This document explains the **simplified** web.config file intended for the **root directory of the IIS Website** (or parent IIS Application) hosting the various anti-scraping-defense-iis services.

**IMPORTANT:** This version of the web.config assumes that the primary request filtering (Redis IP blocklist check, User-Agent blocking, heuristic checks, and tarpit redirection logic) is now handled by the **C\# ASP.NET Core Middleware** (RedisBlocklistMiddlewareApp) hosted via the ASP.NET Core Module (ANCM).

## **Purpose**

With the core filtering logic moved to the C\# middleware, the primary purposes of this root web.config are now:

1. **Module Registration Notes:** Provides guidance on where to register classic IHttpModules if used (though the recommended approach uses ASP.NET Core middleware, which doesn't require manual registration here). It also notes the importance of the ASP.NET Core Module (ANCM) being installed for hosting the C\# middleware application.  
2. **Basic Site Configuration:** Sets site-level configurations like default documents (if applicable) and custom error pages.  
3. **(Optional) Minimal Rewrite Rules:** Can contain essential site-wide rules like forcing HTTPS or blocking specific sensitive files at the root, but **does not** contain the complex bot detection or tarpit redirection rules anymore.

## **Placement & Deployment**

* **Source Code:** Store this web.config file and this README.md in \\anti-scraping-defense-iis\\iis\_configs\\root\_filter\\ for organization.  
* **Deployment:** Place the actual web.config file in the physical root directory of the IIS Website that receives public traffic for this application stack.

## **Configuration Details**

### **1\. Module Registration (\<modules\>)**

* This section now primarily serves as a placeholder and reminder.  
* If using the recommended ASP.NET Core middleware approach for Redis checking and heuristics, the middleware is invoked via the ASP.NET Core Module (ANCM), which should be installed globally in IIS via the .NET Hosting Bundle. No manual registration of your middleware is typically needed in *this* root web.config.  
* The placeholder \`\` is only relevant if you were using an older .NET Framework IHttpModule.

### **2\. URL Rewrite Rules (\<rewrite\> \<rules\>)**

* **Simplified:** This section should be mostly empty or contain only very basic, site-wide rules.  
* **Filtering Removed:** The rules for blocking User-Agents, checking headers, and rewriting to the tarpit path have been **removed** as this logic is now handled by the C\# RedisBlocklistMiddleware.  
* **Example Rules:** You might include rules here for non-application-specific tasks like:  
  * Forcing all traffic to HTTPS (see commented-out example).  
  * Blocking direct access to specific files in the root directory.  
* **Routing:** Explicit routing rules are generally **not needed** here if your backend services (Tarpit, Admin UI, etc.) and the C\# middleware app are configured as separate IIS Applications under this root site. IIS application routing will typically direct requests based on their path (e.g., /anti-scrape-tarpit/\* goes to the Tarpit application).

### **3\. Other Settings (\<defaultDocument\>, \<httpErrors\>)**

* These sections configure standard IIS behavior for the root site, such as default files to serve (if any) and custom error pages (e.g., for 403 Forbidden, 404 Not Found). Ensure the specified error page paths (like /errors/403.html) exist relative to the site root.

## **Dependencies**

* IIS with URL Rewrite Module installed.  
* .NET Hosting Bundle installed (includes ANCM V2 for hosting the C\# middleware application).  
* The C\# RedisBlocklistMiddlewareApp deployed and configured correctly as an IIS Application (potentially as the root application itself, or as a sub-application).  
* The Python backend services (Tarpit, Admin, etc.) deployed and configured as separate IIS Applications.

This simplified web.config relies heavily on the C\# middleware application to perform the core request filtering and tarpitting decisions.