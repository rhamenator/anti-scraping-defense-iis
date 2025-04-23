# **Admin UI Service**

This directory contains the Python code for the Admin UI microservice (admin\_ui.py) and its associated HTML template (templates/index.html).

## **Purpose**

The Admin UI is a Flask web application that provides a simple dashboard for monitoring the real-time activity of the AI Scraping Defense Stack.

Its key functions include:

* Serving a basic HTML dashboard page.  
* Providing a /metrics API endpoint that returns current system metrics collected by the shared metrics.py module.  
* Displaying metrics like tarpit hits, escalations, blocks, uptime, etc., fetched dynamically via JavaScript from the /metrics endpoint.  
* Optionally triggering the periodic dumping of metrics to a JSON file if configured via environment variables (LOG\_METRICS\_TO\_JSON).

**Note:** For deployment configuration specific to IIS, refer to the main [IIS Deployment Guide](http://docs.google.com/docs/iis_deployment_guide.md) and the configuration file README located in iis\_configs/admin\_ui/.