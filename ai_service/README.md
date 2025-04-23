# **AI Service**

This directory contains the Python code for the AI Service (ai\_webhook.py).

## **Purpose**

The AI Service is a FastAPI application that acts as the central action handler for confirmed malicious activity detected by the Escalation Engine.

Its key functions include:

* Receiving webhook notifications containing details of malicious requests.  
* Adding the offending IP address to the shared Redis blocklist (DB 2\) with a configured Time-To-Live (TTL).  
* Optionally reporting the blocked IP address to configured third-party community blocklist services (e.g., AbuseIPDB).  
* Dispatching alerts based on the configured method (ALERT\_METHOD environment variable) and severity thresholds. Supported methods include Slack, SMTP (email), and generic webhooks.  
* Logging block events, alert dispatches, and reporting actions.

**Note:** For deployment configuration specific to IIS, refer to the main [IIS Deployment Guide](http://docs.google.com/docs/iis_deployment_guide.md) and the configuration file README located in iis\_configs/ai\_service/.