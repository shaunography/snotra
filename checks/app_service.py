from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.web.models import SiteAuthSettings
import logging
import re

class app_service(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.resource_groups = resource_groups
        self.resources = resources
        self.web_apps = self.get_web_apps()
        self.web_apps_config = self.get_web_apps_config()

    def get_web_apps(self):
        web_apps = {}
        for subscription, resource_groups in self.resources.items():
            results = []
            client = WebSiteManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.Web/sites":
                        logging.info(f'getting web app { resource.name }')
                        try:
                            web_app = client.web_apps.get(name=resource.name, resource_group_name=resource_group)
                            results.append(web_app)
                        except Exception as e:
                            logging.error(f'error getting web app: { resource.name }, error: { e }')
            if results:
                web_apps[subscription] = results
        return web_apps

    def get_web_apps_config(self):
        web_apps = {}
        for subscription, resource_groups in self.resources.items():
            results = []
            client = WebSiteManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.Web/sites":
                        logging.info(f'getting web app config { resource.name }')
                        try:
                            web_app = client.web_apps.get_configuration(name=resource.name, resource_group_name=resource_group)
                            results.append(web_app)
                        except Exception as e:
                            logging.error(f'error getting web app: { resource.name }, error: { e }')
            if results:
                web_apps[subscription] = results
        return web_apps

    def run(self):
        findings = []
        findings += [ self.app_service_1() ]
        findings += [ self.app_service_2() ]
        findings += [ self.app_service_3() ]
        findings += [ self.app_service_4() ]
        findings += [ self.app_service_5() ]
        findings += [ self.app_service_6() ]
        findings += [ self.app_service_7() ]
        findings += [ self.app_service_8() ]
        findings += [ self.app_service_9() ]
        findings += [ self.app_service_10() ]
        findings += [ self.app_service_11() ]
        findings += [ self.app_service_12() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.app_service_2() ]
        return findings

    def app_service_1(self):
        # Azure App Services

        results = {
            "id" : "app_service_1",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "app_service",
            "name" : "Azure App Services",
            "affected": [],
            "analysis" : "N/A",
            "description" : "N/A",
            "remediation" : "N/A",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["analysis"] = self.web_apps

        if results["analysis"]:
            results["affected"] = [ i for i, v in results["analysis"].items() ]
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "no web apps found"

        return results

    def app_service_2(self):
        # Ensure App Service Authentication is set up for apps in Azure App Service (CIS)

        results = {
            "id" : "app_service_2",
            "ref" : "9.1",
            "compliance" : "cis_v2.1.0",
            "level": 2,
            "service" : "app_service",
            "name" : "Ensure App Service Authentication is set up for apps in Azure App Service (CIS)",
            "affected": [],
            "analysis" : {},
            "description" : "Azure App Service Authentication is a feature that can prevent anonymous HTTP requests from reaching a Web Application or authenticate those with tokens before they reach the app. If an anonymous request is received from a browser, App Service will redirect to a logon page. To handle the logon process, a choice from a set of identity providers can be made, or a custom authentication mechanism can be implemented. By Enabling App Service Authentication, every incoming HTTP request passes through it before being handled by the application code. It also handles authentication of users with the specified provider (Entra ID, Facebook, Google, Microsoft Account, and Twitter), validation, storing and refreshing of tokens, managing the authenticated sessions and injecting identity information into request headers. Disabling HTTP Basic Authentication functionality further ensures legacy authentication methods are disabled within the application.",
            "remediation" : "From Azure Portal\n1. Login to Azure Portal using https://portal.azure.com\n2. Go to App Services\n3. Click on each App\n4. Under Setting section, click on Authentication\n5. If no identity providers are set up, then click Add identity provider\n6. Choose other parameters as per your requirements and click on Add\nTo disable the Basic Auth Publishing Credentials setting, perform the following\nsteps:\nPage 448\n1. Login to Azure Portal using https://portal.azure.com\n2. Go to App Services\n3. Click on each App\n4. Under Settings, click on Configuration\n5. Click on the 'General Settings' tab\n6. Under Platform settings, ensure Basic Auth Publishing Credentials is set to\nOff",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "4.8",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["analysis"]["system assigned"] = []
        results["analysis"]["user assigned"] = []

        for subscription, web_apps in self.web_apps.items():
            client = WebSiteManagementClient(credential=self.credential, subscription_id=subscription)

            for web_app in web_apps:
                try:
                    auth_settings = client.web_apps.get_auth_settings(web_app.resource_group, web_app.name)
                except Exception as e:
                    logging.error(f'error getting web app auth settings: { web_app.name }, error: { e }')
                else:
                    if auth_settings.enabled == False:
                        results["affected"].append(web_app.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected web apps are not using app service authentication"
        elif self.web_apps:
            results["pass_fail"] = "PASS"
            results["analysis"] = "app service authentication is in use"
        else:
            results["analysis"] = "no web apps in use"

        return results

    def app_service_3(self):
        # Ensure Web App Redirects All HTTP traffic to HTTPS in Azure App Service (CIS)

        results = {
            "id" : "app_service_3",
            "ref" : "9.2",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "app_service",
            "name" : "Ensure Web App Redirects All HTTP traffic to HTTPS in Azure App Service (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Azure Web Apps allows sites to run under both HTTP and HTTPS by default. Web apps can be accessed by anyone using non-secure HTTP links by default. Non-secure HTTP requests can be restricted and all HTTP requests redirected to the secure HTTPS port. It is recommended to enforce HTTPS-only traffic. Enabling HTTPS-only traffic will redirect all non-secure HTTP requests to HTTPS ports. HTTPS uses the TLS/SSL protocol to provide a secure connection which is both encrypted and authenticated. It is therefore important to support HTTPS for the security benefits.",
            "remediation" : "Enable HTTPS only for all affected applications.\nFrom Azure Portal\n1. Login to Azure Portal using https://portal.azure.com\n2. Go to App Services\n3. Click on each App\n4. Click on configuration\n5. Under the HTTPS Only heading select 'On' to enable https only\n6. Click Save at the top",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "4.8",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, web_apps in self.web_apps.items():
            for web_app in web_apps:
                if web_app.https_only == False:
                    results["affected"].append(web_app.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected web apps do not have https_only enabled"
        elif self.web_apps:
            results["pass_fail"] = "PASS"
            results["analysis"] = "web apps have https_only enabled"
        else:
            results["analysis"] = "no web apps in use"


        return results

    def app_service_4(self):
        # App Services Lacking Network Access Restrictions

        results = {
            "id" : "app_service_4",
            "ref" : "snorta",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "app_service",
            "name" : "App Services Lacking Network Access Restrictions",
            "affected": [],
            "analysis" : {},
            "description" : "The subscription under review contained resources which did not implement network level access restrictions (Firewall rules) and therefore allowed unrestricted traffic from the public internet. This configuration impacted the security posture of the cloud environment and increased the risk of unauthorized data exposure.  By default resources in Azure do not implement a firewall to restrict network level access, therefore all users, applications, and services including those on the public internet could potentially communicate with resources  hosted within a subscription at the network layer. Although often protected by authentication, the lack of network restrictions increased the attack surface of the resources and the wider Azure environment. An attacker able to compromise valid credentials could use those credentials to interact with the service from clients on any network or from other Azure tenancies.  To restrict access to Storage Accounts and provide a greater defence in depth for stored data, it is recommended to use private endpoints that only permit access from internal Azure Virtual Networks and/or configure Firewall rules following the principle of least privilege to only allow access from trusted networks and IP addresses.",
            "remediation" : "The affected resources should be configured to restrict network access to the internal virtual private networks. Where external access is required for legitimate purposes, access should be restricted to a subset of whitelisted public IP addresses. \nAdditionally, where external access is not required, organisations should consider implementing a private endpoint connection to facilitate a secure connection between internal services whilst removing the requirement to use public infrastructure. When a private endpoint is configured all traffic between resources is transmitted over the Azure backbone ‘Azure PrivateLink’ network using virtual private IP addresses reducing the exposure of sensitive data. \nTo configure firewall rules within the Azure Portal:\nGo to resource.\nFor each resource, click on the settings menu called ‘Networking’.\nEnsure that you have elected to allow access from Selected networks.\nAdd rules to allow traffic from specific networks and IPs as required. \nClick Save to apply your changes.\nIf you want to limit access at the SQL Server database level consider also implementing an additional layer of database level firewall rules.",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "5.4",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, web_apps in self.web_apps.items():
            for web_app in web_apps:
                if web_app.public_network_access != "Disabled":
                    results["affected"].append(web_app.name)
                    results["analysis"][web_app.name] = web_app.default_host_name

        if results["affected"]:
            results["pass_fail"] = "FAIL"
        elif self.web_apps:
            results["pass_fail"] = "PASS"
            results["analysis"] = "web apps do not have public network access enabled"
        else:
            results["analysis"] = "no web apps in use"

        return results

    def app_service_5(self):
        # Ensure Web App is using the latest version of TLS encryption (CIS)

        results = {
            "id" : "app_service_5",
            "ref" : "9.3",
            "compliance" : "cis_v2.1.0",
            "level": 1,
            "service" : "app_service",
            "name" : "Ensure Web App is using the latest version of TLS encryption (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "The TLS (Transport Layer Security) protocol secures transmission of data over the internet using standard encryption technology. Encryption should be set with the latest version of TLS. App service allows TLS 1.2 by default, which is the recommended TLS level by industry standards such as PCI DSS.  App service currently allows the web app to set TLS versions 1.0, 1.1 and 1.2. It is highly recommended to use the latest TLS 1.2 version for web app secure connections.",
            "remediation" : "Configure the affected App Services with a minimum TLS version of 1.2.\nFrom Azure Portal\n1. Login to Azure Portal using https://portal.azure.com\n2. Go to App Services\n3. Click on each App\n4. Under Setting section, Click on SSL settings\n5. Under the Bindings pane, set Minimum TLS Version to 1.2 under Protocol\nSettings section",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "4.8",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, web_apps in self.web_apps_config.items():
            for web_app in web_apps:
                if web_app.min_tls_version != "1.2":
                    results["affected"].append(web_app.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the afected web apps do not have the latest TLS version enabled"
        elif self.web_apps:
            results["pass_fail"] = "PASS"
            results["analysis"] = "web apps are using the latest TLS version"
        else:
            results["analysis"] = "no web apps in use"

        return results

    def app_service_6(self):
        # Ensure App Services Are Using Managed Identities To Access Resources In Azure (CIS)

        results = {
            "id" : "app_service_6",
            "ref" : "9.4",
            "compliance" : "cis_v2.1.0",
            "level": 1,
            "service" : "app_service",
            "name" : "Ensure App Services Are Using Managed Identities To Access Resources In Azure (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Managed service identity in App Service provides more security by eliminating secrets\nfrom the app, such as credentials in the connection strings. When registering an App\nService with Entra ID, the app will connect to other Azure services securely without the\nneed for usernames and passwords.\nRationale:\nApp Service provides a highly scalable, self-patching web hosting service in Azure. It\nalso provides a managed identity for apps, which is a turn-key solution for securing\naccess to Azure SQL Database and other Azure services.",
            "remediation" : "Any App Services that require access to resources in Azure should be configured with a Managed Identity according to the principle of least privilegeFrom Azure Portal\n1. Login to Azure Portal using https://portal.azure.com\n2. Go to App Services\n3. Click on each App\n4. Under Setting section, Click on Identity\n5. Under the System assigned pane, set Status to On",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "4.8",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, web_apps in self.web_apps_config.items():
            for web_app in web_apps:
                if not web_app.x_managed_service_identity_id and not web_app.managed_service_identity_id:
                    results["affected"].append(web_app.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the afected web apps do not have a managed identity configured, if the web apps not require access to other Azure resources (SQL database for example) than this finding can be ignored"
        elif self.web_apps:
            results["pass_fail"] = "PASS"
            results["analysis"] = "web apps are using managed identities"
        else:
            results["analysis"] = "no web apps in use"

        return results


    def app_service_7(self):
        # Ensure Web Apps Are Using Supported Runtimes (CIS)

        results = {
            "id" : "app_service_7",
            "ref" : "9.5-9.7",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "app_service",
            "name" : "Ensure Web Apps Are Using Supported Runtimes (CIS)",
            "affected": [],
            "analysis" : {},
            "description" : "Periodically newer versions are released for stack software either due to security flaws or to include additional functionality. Using the latest stack version for web apps is recommended in order to take advantage of security fixes, if any, and/or additional functionalities of the newer version. Newer versions may contain security enhancements and additional functionality. Using the latest software version is recommended in order to take advantage of enhancements and new capabilities. With each software installation, organizations need to determine if a given update meets their requirements. They must also verify the compatibility and support provided for any additional software against the update revision that is selected.",
            "remediation" : "From Azure Portal\n1. From Azure Home open the Portal Menu in the top left\n2. Go to App Services\n3. Click on each App\n4. Under Settings section, click on Configuration\n5. Click on the General settings pane, ensure that for a Stack of stack the Major\nVersion and Minor Version reflect the latest stable and supported release.",
            "impact" : "INFO",
            "probability" : "INFO",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 
        
        #https://github.com/Azure/app-service-linux-docs/tree/master/Runtime_Support
        unsupported = ["NODE|16-lts", "PHP|8.0", "PHP|8.1"]

        for subscription, web_apps in self.web_apps_config.items():
            for web_app in web_apps:

                # dotnet
                if web_app.net_framework_version:
                    if web_app.net_framework_version != "v4.0": # hack for shity api
                        if web_app.net_framework_version == "v5.0":
                            results["affected"].append(web_app.name)
                            results["analysis"][web_app.name] = web_app.net_framework_version


                if web_app.linux_fx_version in unsupported:
                    results["affected"].append(web_app.name)
                    results["analysis"][web_app.name] = web_app.linux_fx_version

        if results["affected"]:
            results["pass_fail"] = "FAIL"
        elif self.web_apps:
            results["pass_fail"] = "PASS"
            results["analysis"] = "web apps are using supported runtimes"
        else:
            results["analysis"] = "no web apps in use"

        return results

    def app_service_8(self):
        # Ensure that 'HTTP Version' is the Latest, if Used to Run the Web App (CIS)

        results = {
            "id" : "app_service_8",
            "ref" : "9.8",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "app_service",
            "name" : "Ensure that 'HTTP Version' is the Latest, if Used to Run the Web App (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Periodically, newer versions are released for HTTP either due to security flaws or to include additional functionality. Using the latest HTTP version for web apps to take advantage of security fixes, if any, and/or new functionalities of the newer version. Newer versions may contain security enhancements and additional functionality. Using the latest version is recommended in order to take advantage of enhancements and new capabilities. With each software installation, organizations need to determine if a given update meets their requirements. They must also verify the compatibility and support provided for any additional software against the update revision that is selected. HTTP 2.0 has additional performance improvements on the head-of-line blocking problem of old HTTP version, header compression, and prioritization of requests. HTTP 2.0 no longer supports HTTP 1.1's chunked transfer encoding mechanism, as it provides its own, more efficient, mechanisms for data streaming.",
            "remediation" : "Enable HTTP 2.0 on the affected app services.\nFrom Azure Portal\n1. Login to Azure Portal using https://portal.azure.com\n2. Go to App Services\n3. Click on each App\n4. Under Setting section, Click on Configuration\n5. Set HTTP version to 2.0 under General settings\nNOTE: Most modern browsers support HTTP 2.0 protocol over TLS only, while non-\nencrypted traffic continues to use HTTP 1.1. To ensure that client browsers connect to\nyour app with HTTP/2, either buy an App Service Certificate for your app's custom\ndomain or bind a third party certificate.",
            "impact" : "INFO",
            "probability" : "INFO",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, web_apps in self.web_apps_config.items():
            for web_app in web_apps:
                if web_app.http20_enabled == False:
                    results["affected"].append(web_app.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the afected web apps do not have http 2.0 enabled"
        elif self.web_apps:
            results["pass_fail"] = "PASS"
            results["analysis"] = "web apps have http 2.0 enabled"
        else:
            results["analysis"] = "no web apps in use"

        return results


    def app_service_9(self):
        # Ensure FTP deployments are Disabled (CIS)

        results = {
            "id" : "app_service_9",
            "ref" : "9.9",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "app_service",
            "name" : "Ensure FTP deployments are Disabled (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "By default, Azure Functions, Web, and API Services can be deployed over FTP. If FTP is required for an essential deployment workflow, FTPS should be required for FTP login for all App Service Apps and Functions. Azure FTP deployment endpoints are public. An attacker listening to traffic on a wifi network used by a remote employee or a corporate network could see login traffic in clear-text which would then grant them full control of the code base of the app or service. This finding is more severe if User Credentials for deployment are set at the subscription level rather than using the default Application Credentials which are unique per App.",
            "remediation" : "Configure the affected app services to use FTPS only deployments.From Azure Portal\n1. Go to the Azure Portal\n2. Select App Services\n3. Click on an app\n4. Select Settings and then Configuration\n5. Under General Settings, for the Platform Settings, the FTP state should be\nset to Disabled or FTPS Only",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, web_apps in self.web_apps_config.items():
            for web_app in web_apps:
                if web_app.ftps_state != "FtpsOnly":
                    results["affected"].append(web_app.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the afected web apps do not have FTPS only deployments enabled"
        elif self.web_apps:
            results["pass_fail"] = "PASS"
            results["analysis"] = "web apps have FTPS only enabled"
        else:
            results["analysis"] = "no web apps in use"

        return results


    def app_service_10(self):
        # web apps with managed identity assigned

        results = {
            "id" : "app_service_10",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level": "N/A",
            "service" : "app_service",
            "name" : "Web Apps With Managed Identity Assigned",
            "affected": [],
            "analysis" : {},
            "description" : "When Web Apps require access to Azure Resources it is recomended to enabled access via a Managed Identity.This provides better security by eliminating the use of secrets such as credentials in the connection strings. System assigned Managed Identities allow each web app to have their own Managed IDentity, if you would like to use a single Managed Identity across a number of apps you can use a User Assigned Identity. Managed Identities should be configured following the principle of least privilege with only the minimal set of roles and permissions required in order for the application to function.",
            "remediation" : "Any App Services that require access to resources in Azure should be configured with a Managed Identity according to the principle of least privilegeFrom Azure Portal\n1. Login to Azure Portal using https://portal.azure.com\n2. Go to App Services\n3. Click on each App\n4. Under Setting section, Click on Identity\n5. Under the System assigned pane, set Status to On",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "4.8",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["analysis"]["system assigned"] = []
        results["analysis"]["user assigned"] = []

        for subscription, web_apps in self.web_apps_config.items():
            for web_app in web_apps:
                if web_app.x_managed_service_identity_id:
                    results["analysis"]["user assigned"].append(web_app.name)
                    results["affected"].append(web_app.name)
                if web_app.managed_service_identity_id:
                    results["analysis"]["system assigned"].append(web_app.name)
                    results["affected"].append(web_app.name)

        if results["affected"]:
            results["pass_fail"] = "INFO"
            results["analysis"] = "the afected web apps have a managed identity configured, if the web apps not require access to other Azure resources (SQL database for example) the Managed ID should be removed, otherwise review the roles and permissons assigned to the ID and ensure it is configured following the principal of least privilege."
        elif self.web_apps:
            results["pass_fail"] = "INFO"
            results["analysis"] = "web apps are not using managed identities"
        else:
            results["analysis"] = "no web apps in use"

        return results

    def app_service_11(self):
        # Web Apps With Remote Debugging Enabled

        results = {
            "id" : "app_service_11",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level": "N/A",
            "service" : "app_service",
            "name" : "Web Apps With Remote Debugging Enabled",
            "affected": [],
            "analysis" : {},
            "description" : "",
            "remediation" : "",
            "impact" : "INFO",
            "probability" : "INFO",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, web_apps in self.web_apps_config.items():
            for web_app in web_apps:
                if web_app.remote_debugging_enabled == True:
                    results["affected"].append(web_app.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected web apps have remote debugging enabled"
        elif self.web_apps:
            results["pass_fail"] = "PASS"
            results["analysis"] = "remote debugging is not enabled on any web apps"
        else:
            results["analysis"] = "no web apps in use"

        return results

    def app_service_12(self):
        # Web Apps Without Always On enabled

        results = {
            "id" : "app_service_12",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level": "N/A",
            "service" : "app_service",
            "name" : "App Services Without Always On Enabled",
            "affected": [],
            "analysis" : {},
            "description" : "The account under review contains App Services that do not have “Always On” enabled. By default, websites and web applications are unloaded if they have been idle for too long. Always On keeps the app loaded even when there's no traffic. When Always On is disabled (default), the app is unloaded after 20 minutes without any incoming requests. The unloaded app can cause high latency for new requests because of its warm-up time. When Always On is turned on, the front-end load balancer sends a GET request to the application root every five minutes. The continuous ping prevents the app from being unloaded. Always On is required for continuous WebJobs or for WebJobs that are triggered using a CRON expression",
            "remediation" : "Consider enabling always on for workloads that require high availability and response times\nMore Information\nhttps://docs.microsoft.com/en-us/azure/app-service/configure-common",
            "impact" : "INFO",
            "probability" : "INFO",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, web_apps in self.web_apps_config.items():
            for web_app in web_apps:
                if web_app.always_on == False:
                    results["affected"].append(web_app.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected web apps do not have always on enabled"
        elif self.web_apps:
            results["pass_fail"] = "PASS"
            results["analysis"] = "web apps have always on enabled"
        else:
            results["analysis"] = "no web apps in use"

        return results

