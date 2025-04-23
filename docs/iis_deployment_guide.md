# **IIS Deployment Guide: Anti-Scraping Defense Stack (Updated)**

This guide provides detailed steps for deploying the IIS-adapted version of the AI Scraping Defense Stack (anti-scraping-defense-iis) onto a Windows Server environment using Internet Information Services (IIS).

**Target Audience:** System Administrators responsible for installing and configuring web applications on Windows Server with IIS.

**Goal:** To configure IIS to host the C\# filtering middleware and the backend Python services (Tarpit, Escalation, Admin UI, AI Service), enabling the anti-scraping functionality.

**Prerequisites:**

* Administrative access to the target Windows Server.  
* The application source code package (anti-scraping-defense-iis), including the pre-compiled C\# middleware application (typically found in a deploy or publish subfolder within the package).  
* Access to Redis and PostgreSQL database instances (either running locally on the Windows Server or accessible over the network).  
* Necessary credentials (database passwords, API keys) for Redis, PostgreSQL, and any configured external services (SMTP, Slack, community blocklists, etc.).

## **Phase 1: Server Prerequisites Installation**

Ensure the following software components are installed and configured on the target Windows Server before proceeding with the application deployment. Use Server Manager (Add Roles and Features) or appropriate installers.

1. **Windows Server:** A supported version (e.g., Windows Server 2016, 2019, 2022).  
2. **IIS (Internet Information Services):** Install the Web Server (IIS) role with the following features enabled:  
   * Web Server \-\> Common HTTP Features (Default Document, Static Content, HTTP Errors, HTTP Redirection)  
   * Web Server \-\> Health and Diagnostics (HTTP Logging, Request Monitor)  
   * Web Server \-\> Performance (Static Content Compression, Dynamic Content Compression)  
   * Web Server \-\> Security (Request Filtering, IP and Domain Restrictions \- *optional*)  
   * Web Server \-\> Application Development \-\> **ASP.NET** (select the version corresponding to the .NET Framework, e.g., 4.7 or 4.8, if required by specific modules, although the primary components use .NET Core/5+ or run externally via HttpPlatformHandler).  
   * Management Tools (IIS Management Console)  
3. **.NET Framework:** Ensure the version targeted by your C\# module (if using classic IHttpModule) or required by the .NET Hosting Bundle (if using ASP.NET Core middleware) is installed (e.g., .NET Framework 4.7.2 or 4.8). Usually installed with Windows or via Add Roles and Features.  
4. **.NET Hosting Bundle:** **(Required)**  
   * Download and install the appropriate **ASP.NET Core Hosting Bundle** version (e.g., .NET 6 LTS or .NET 8 LTS) from the official Microsoft .NET website. Match the version targeted by the included C\# middleware application (RedisBlocklistMiddlewareApp).  
   * This bundle installs the necessary .NET runtimes and the **ASP.NET Core Module (ANCM) v2** required by IIS to host the C\# middleware. Install *after* IIS. A server restart may be required.  
5. **IIS URL Rewrite Module:** Download and install from the official IIS website ([https://www.iis.net/downloads/microsoft/url-rewrite](https://www.iis.net/downloads/microsoft/url-rewrite)).  
6. **IIS HttpPlatformHandler:** Download and install the latest version from the official IIS website ([https://www.iis.net/downloads/microsoft/httpplatformhandler](https://www.iis.net/downloads/microsoft/httpplatformhandler)). This module enables IIS to manage the Python processes.  
7. **Python:**  
   * Install a compatible version of Python for Windows (e.g., 3.9, 3.10, 3.11) from [python.org](https://python.org).  
   * **IMPORTANT:** During installation, ensure the option "Add Python X.Y to PATH" is selected for all users or the system.  
   * Verify the installation via Command Prompt/PowerShell: python \--version, pip \--version.  
8. **Redis:**  
   * Ensure a Redis instance is running and accessible over the network from the IIS server. Note its hostname/IP, port, and password (if configured). Firewall rules may need adjustment. (Common Windows options include Redis via WSL or Docker).  
9. **PostgreSQL:**  
   * Ensure a PostgreSQL instance is running and accessible over the network from the IIS server. Note its hostname/IP, port, database name (e.g., markovdb), and user credentials. Check firewall rules and PostgreSQL's pg\_hba.conf for connection permissions.  
   * The database schema must be initialized using the provided db/init\_markov.sql script. This creates the markov\_words and markov\_sequences tables required by the Tarpit service.

## **Phase 2: Application Files Deployment**

1. **Build C\# Middleware Application:**  
   * Navigate to the RedisBlocklistMiddlewareApp directory.  
   * Run dotnet restore.  
   * Run dotnet publish \-c Release \-o ..\\..\\deploy\\RedisBlocklistMiddlewareApp \--no-self-contained (adjust output path \-o if needed).  
2. **Create Deployment Directory Structure on Server:**  
   * Establish a root location for the application stack on the server (e.g., C:\\inetpub\\apps\\anti-scrape\\).  
   * Create the following subdirectories within the root: app\_code, middleware, logs, secrets, data, models, archives, config.  
3. **Copy Files to Server:**  
   * Copy Python application source files (admin\_ui, ai\_service, escalation, tarpit, shared, rag, metrics.py, requirements.txt, etc.) into the app\_code directory.  
   * Copy the contents of the pre-compiled C\# middleware application (from the deploy or publish folder in the source package) into the middleware directory.  
   * Copy robots.txt into the config directory.  
   * Copy the pre-trained Random Forest model (.joblib file) into the models directory.  
4. **Install Python Dependencies:**  
   * Open Command Prompt or PowerShell **as Administrator**.  
   * Navigate to the Python code directory: cd C:\\inetpub\\apps\\anti-scrape\\app\_code  
   * **Recommended:** Create and activate a Python virtual environment to isolate dependencies:  
     python \-m venv .venv  
     .\\.venv\\Scripts\\activate

   * Install required packages: pip install \-r requirements.txt. Resolve any installation errors (e.g., install Microsoft C++ Build Tools if needed for packages like psycopg2).  
5. **Configure Secret Files:**  
   * Navigate to the secrets directory (C:\\inetpub\\apps\\anti-scrape\\secrets).  
   * Create the necessary plain text files containing sensitive credentials: pg\_password.txt, redis\_password.txt (if used), smtp\_password.txt (if used), etc.  
   * **Security:** Apply strict file system permissions to this directory. Grant only **Read** access to the specific Application Pool identities that will run the C\# and Python applications. Remove permissions for other non-administrative users.

## **Phase 3: IIS Configuration**

Use **IIS Manager** (run as Administrator) for these steps.

1. **Create Main IIS Website:**  
   * Create a new website (e.g., "AntiScrapeSite") or use an existing one.  
   * **Physical Path:** Set to a directory that will contain the root filtering web.config (e.g., C:\\inetpub\\wwwroot\\anti-scrape-root).  
   * **Binding:** Configure HTTP/HTTPS bindings. Assign a valid SSL certificate for HTTPS.  
   * Assign an Application Pool (see next step).  
2. **Create Application Pools:** Create dedicated pools for isolation:  
   * AntiScrapeMiddlewareAppPool: For C\# middleware. Set **.NET CLR Version:** **"No Managed Code"**. Configure Identity (e.g., ApplicationPoolIdentity or a dedicated low-privilege service account).  
   * AntiScrapePythonAppPool: For Python services. Set **.NET CLR Version:** **"No Managed Code"**. Configure Identity.  
3. **Create IIS Applications:** Under the main website, add applications for each service:  
   * **C\# Middleware App:** Configure the main website ("AntiScrapeSite") to use the middleware physical path and AntiScrapeMiddlewareAppPool. This is recommended if it should process all incoming site traffic first. (Alternatively, create as a sub-application like /filtering if needed).  
   * **Tarpit API App:** Alias: anti-scrape-tarpit (or match TarpitRewritePath setting), Pool: AntiScrapePythonAppPool, Path: C:\\inetpub\\apps\\anti-scrape\\app\_code.  
   * **Admin UI App:** Alias: admin, Pool: AntiScrapePythonAppPool, Path: C:\\inetpub\\apps\\anti-scrape\\app\_code.  
   * **Escalation Engine App:** Alias: anti-scrape-escalation, Pool: AntiScrapePythonAppPool, Path: C:\\inetpub\\apps\\anti-scrape\\app\_code.  
   * **AI Service App:** Alias: anti-scrape-aiservice, Pool: AntiScrapePythonAppPool, Path: C:\\inetpub\\apps\\anti-scrape\\app\_code.  
4. **Deploy web.config Files:**  
   * Copy the simplified **root filter** web.config (from the source package's iis\_configs\\root\_filter\\) to the main site's physical root (e.g., C:\\inetpub\\wwwroot\\anti-scrape-root). Edit it to remove any placeholder module registrations. See [iis\_configs/root\_filter/README.md](http://docs.google.com/iis_configs/root_filter/README.md) for details.  
   * Copy the **C\# middleware's** web.config (generated by dotnet publish) into its physical directory (middleware). Verify it correctly points to the .NET application DLL. See [RedisBlocklistMiddlewareApp/README.md](http://docs.google.com/RedisBlocklistMiddlewareApp/README.md) for application details.  
   * Copy the **service-specific** web.config files (from iis\_configs\\tarpit\_api\\, iis\_configs\\admin\_ui\\, etc.) to the physical root directory of their corresponding IIS Applications. **Edit each** web.config to set correct processPath and environment variables. Refer to the README file within each iis\_configs/\<service\_name\>/ directory for specific instructions:  
     * Tarpit API: [iis\_configs/tarpit\_api/README.md](http://docs.google.com/iis_configs/tarpit_api/README.md)  
     * Admin UI: [iis\_configs/admin\_ui/README.md](http://docs.google.com/iis_configs/admin_ui/README.md)  
     * Escalation Engine: [iis\_configs/escalation\_engine/README.md](http://docs.google.com/iis_configs/escalation_engine/README.md)  
     * AI Service: [iis\_configs/ai\_service/README.md](http://docs.google.com/iis_configs/ai_service/README.md)  
5. **Configure C\# appsettings.json:**  
   * Edit the appsettings.json file located in the C\# middleware's physical directory (middleware).  
   * Set the correct ConnectionStrings:RedisConnection value for your Redis instance.  
   * Verify the Redis:\* and Heuristics:\* sections, especially TarpitRewritePath. See [RedisBlocklistMiddlewareApp/README for appsettings.json.md](http://docs.google.com/RedisBlocklistMiddlewareApp/README%20for%20appsettings.json%20%28Redis%20Middleware%20App%29.md) for details.  
6. **Configure Environment Variables:**  
   * **Crucial:** Ensure all necessary environment variables (e.g., REDIS\_HOST, PG\_HOST, SYSTEM\_SEED, APP\_BASE\_DIRECTORY, APP\_SECRETS\_DIRECTORY, API keys, alert settings) are available to the C\# and Python applications. Set these either system-wide or (recommended) directly in IIS Manager for each Application (Configuration Editor \-\> system.webServer/httpPlatform \-\> environmentVariables).

## **Phase 4: Permissions Configuration**

Grant the configured Application Pool Identities (IIS AppPool\\YourAppPoolName) the minimum necessary file system permissions using File Explorer \-\> Properties \-\> Security:

* **Secrets Directory:** Read  
* **Logs Directory:** Modify  
* **Data Directory:** Modify (AntiScrapePythonAppPool)  
* **Models Directory:** Read (AntiScrapePythonAppPool)  
* **Archives Directory:** Modify (AntiScrapePythonAppPool)  
* **Python Code (app\_code):** Read & Execute (AntiScrapePythonAppPool)  
* **C\# Middleware (middleware):** Read & Execute (AntiScrapeMiddlewareAppPool)  
* **Python Install/Venv Directory:** Read & Execute

## **Phase 5: Data Population & Background Tasks**

Execute these tasks after deployment, typically via an administrative command prompt or PowerShell on the server.

1. **Markov DB Training (train\_markov\_postgres.py):**  
   * Activate the Python virtual environment (.\\.venv\\Scripts\\activate inside app\_code).  
   * Run the script, providing the correct path to the text corpus file:  
     python rag\\train\_markov\_postgres.py C:\\path\\to\\your\\corpus.txt

2. **ML Model Training (training.py):**  
   * **CRITICAL: Adapt Log Parser:** Before running, **modify the parse\_iis\_w3c\_log\_line function inside training.py** to correctly parse your specific IIS log file format. Check IIS Logging settings ("Select Fields...") to see which fields are enabled and their order.  
   * Ensure IIS log files and feedback logs (honeypot\_hits.log, captcha\_success.log) are accessible.  
   * Activate the venv and run: python rag\\training.py. This will generate the .joblib model file in the models directory.  
3. **Archive Rotation (rotating\_archive.py):**  
   * Use **Windows Task Scheduler** to run this script periodically (e.g., daily).  
   * Configure the task action to start the python.exe from the virtual environment, passing the full path to rotating\_archive.py as the argument. Set the "Start in" directory to the app\_code path. Configure the task to run under an account with appropriate permissions.

## **Phase 6: Testing and Verification**

1. **Recycle Application Pools:** In IIS Manager.  
2. **Start Website:** Ensure the IIS website is started.  
3. **Basic Connectivity:** Browse to the main URL of the IIS site.  
4. **Health Checks:** Access the health endpoints configured for the C\# middleware and Python services (e.g., http://your-site/health, http://your-site/anti-scrape-tarpit/health).  
5. **Admin UI:** Access the Admin UI via its configured alias (e.g., http://your-site/admin/).  
6. **Filtering Tests:** Use curl or dev tools with bad UAs, empty UAs, missing headers. Verify 403s and slow tarpit responses. Test IPs added manually to Redis blocklist.  
7. **Log Verification:** Check IIS W3C Logs, HttpPlatformHandler stdout logs, Python app logs, C\# middleware logs.  
8. **Redis Verification:** Use redis-cli to inspect relevant databases for keys (blocklist, frequency, tarpit flags/hops).

## **Phase 7: Troubleshooting Common Issues**

* **500 Internal Server Error:** Check HttpPlatformHandler stdout logs, application logs, Windows Event Viewer. Verify paths, permissions, dependencies, connection strings.  
* **403 Forbidden:** Check Redis blocklist (DB 2). Check C\# middleware logs for UA blocks. Check file system permissions.  
* **404 Not Found:** Verify IIS Application aliases, routing, TarpitRewritePath in appsettings.json. Check IIS Failed Request Tracing (FREB).  
* **Service Unavailable (503):** Check Application Pool status, identity permissions, Windows Event Viewer.  
* **Redis/Database Errors:** Verify connection strings/passwords, firewall rules, service status, pg\_hba.conf.

This guide provides a comprehensive checklist for deploying the IIS version of the stack. Careful attention to paths, permissions, and configuration is key to a successful deployment.