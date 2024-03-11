from azure.mgmt.web import WebSiteManagementClient
import logging

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
            web_apps[subscription] = []
            client = WebSiteManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.Web/sites":
                        logging.info(f'getting web app { resource.name }')
                        try:
                            web_app = client.web_apps.get(name=resource.name, resource_group_name=resource_group)
                            web_apps[subscription].append(web_app)
                        except Exception as e:
                            logging.error(f'error getting web app: { resource.name }, error: { e }')
        return web_apps

    def get_web_apps_config(self):
        web_apps = {}
        for subscription, resource_groups in self.resources.items():
            web_apps[subscription] = []
            client = WebSiteManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.Web/sites":
                        logging.info(f'getting web app config { resource.name }')
                        try:
                            web_app = client.web_apps.get_configuration(name=resource.name, resource_group_name=resource_group)
                            web_apps[subscription].append(web_app)
                        except Exception as e:
                            logging.error(f'error getting web app: { resource.name }, error: { e }')
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
        # Ensure Web App Redirects All HTTP traffic to HTTPS in Azure App Service (CIS)

        results = {
            "id" : "app_service_2",
            "ref" : "9.2",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "app_service",
            "name" : "Ensure Web App Redirects All HTTP traffic to HTTPS in Azure App Service (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Azure Web Apps allows sites to run under both HTTP and HTTPS by default. Web apps can be accessed by anyone using non-secure HTTP links by default. Non-secure HTTP requests can be restricted and all HTTP requests redirected to the secure HTTPS port. It is recommended to enforce HTTPS-only traffic.\nEnabling HTTPS-only traffic will redirect all non-secure HTTP requests to HTTPS ports. HTTPS uses the TLS/SSL protocol to provide a secure connection which is both encrypted and authenticated. It is therefore important to support HTTPS for the security benefits.",
            "remediation" : "Enable HTTPS only for all affected applications.\nFrom Azure Portal\n1. Login to Azure Portal using https://portal.azure.com\n2. Go to App Services\n3. Click on each App\n4. Click on configuration\n5. Under the HTTPS Only heading select 'On' to enable https only\n6. Click Save at the top",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "4.8",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subcription, web_apps in self.web_apps.items():
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

    def app_service_3(self):
        # Ensure Web App is using the latest version of TLS encryption

        results = {
            "id" : "app_service_3",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "app_service",
            "name" : "App Services Lacking Network Access Restrictions",
            "affected": [],
            "analysis" : "",
            "description" : "The subscription under review contained resources which did not implement network level access restrictions (Firewall rules) and therefore allowed unrestricted traffic from the public internet. This configuration impacted the security posture of the cloud environment and increased the risk of unauthorized data exposure. \nBy default resources in Azure do not implement a firewall to restrict network level access, therefore all users, applications, and services including those on the public internet could potentially communicate with resources  hosted within a subscription at the network layer. Although often protected by authentication, the lack of network restrictions increased the attack surface of the resources and the wider Azure environment. An attacker able to compromise valid credentials could use those credentials to interact with the service from clients on any network or from other Azure tenancies. \nTo restrict access to Storage Accounts and provide a greater defence in depth for stored data, it is recommended to use private endpoints that only permit access from internal Azure Virtual Networks and/or configure Firewall rules following the principle of least privilege to only allow access from trusted networks and IP addresses.",
            "remediation" : "The affected resources should be configured to restrict network access to the internal virtual private networks. Where external access is required for legitimate purposes, access should be restricted to a subset of whitelisted public IP addresses. \nAdditionally, where external access is not required, organisations should consider implementing a private endpoint connection to facilitate a secure connection between internal services whilst removing the requirement to use public infrastructure. When a private endpoint is configured all traffic between resources is transmitted over the Azure backbone ‘Azure PrivateLink’ network using virtual private IP addresses reducing the exposure of sensitive data. \nTo configure firewall rules within the Azure Portal:\nGo to resource.\nFor each resource, click on the settings menu called ‘Networking’.\nEnsure that you have elected to allow access from Selected networks.\nAdd rules to allow traffic from specific networks and IPs as required. \nClick Save to apply your changes.\nIf you want to limit access at the SQL Server database level consider also implementing an additional layer of database level firewall rules.",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "5.4",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subcription, web_apps in self.web_apps.items():
            for web_app in web_apps:
                if web_app.public_network_access == "Enabled":
                    results["affected"].append(web_app.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the afected web apps have public network acces enabled"
        elif self.web_apps:
            results["pass_fail"] = "PASS"
            results["analysis"] = "web apps do not have public network access enabled"
        else:
            results["analysis"] = "no web apps in use"

        return results

    def app_service_4(self):
        # Ensure Web App is using the latest version of TLS encryption (CIS)

        results = {
            "id" : "app_service_4",
            "ref" : "9.3",
            "compliance" : "cis_v2.1.0",
            "level": 1,
            "service" : "app_service",
            "name" : "Ensure Web App is using the latest version of TLS encryption (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "The TLS (Transport Layer Security) protocol secures transmission of data over the internet using standard encryption technology. Encryption should be set with the latest version of TLS. App service allows TLS 1.2 by default, which is the recommended TLS level by industry standards such as PCI DSS. \nApp service currently allows the web app to set TLS versions 1.0, 1.1 and 1.2. It is highly recommended to use the latest TLS 1.2 version for web app secure connections.",
            "remediation" : "Configure the affected App Services with a minimum TLS version of 1.2.\nFrom Azure Portal\n1. Login to Azure Portal using https://portal.azure.com\n2. Go to App Services\n3. Click on each App\n4. Under Setting section, Click on SSL settings\n5. Under the Bindings pane, set Minimum TLS Version to 1.2 under Protocol\nSettings section",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "4.8",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        #'http20_enabled': False, 'min_tls_version': '1.2', 'min_tls_cipher_suite': None, 'scm_min_tls_version': '1.2', 'ftps_state': 'FtpsOnly',

        for subcription, web_apps in self.web_apps_config.items():
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


    def app_service_5(self):
        # Ensure that 'HTTP Version' is the Latest, if Used to Run the Web App (CIS)

        results = {
            "id" : "app_service_5",
            "ref" : "9.8",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "app_service",
            "name" : "Ensure that 'HTTP Version' is the Latest, if Used to Run the Web App (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Periodically, newer versions are released for HTTP either due to security flaws or to include additional functionality. Using the latest HTTP version for web apps to take advantage of security fixes, if any, and/or new functionalities of the newer version.\nNewer versions may contain security enhancements and additional functionality. Using the latest version is recommended in order to take advantage of enhancements and new capabilities. With each software installation, organizations need to determine if a given update meets their requirements. They must also verify the compatibility and support provided for any additional software against the update revision that is selected. HTTP 2.0 has additional performance improvements on the head-of-line blocking problem of old HTTP version, header compression, and prioritization of requests. HTTP 2.0 no longer supports HTTP 1.1's chunked transfer encoding mechanism, as it provides its own, more efficient, mechanisms for data streaming.",
            "remediation" : "Enable HTTP 2.0 on the affected app services.\nFrom Azure Portal\n1. Login to Azure Portal using https://portal.azure.com\n2. Go to App Services\n3. Click on each App\n4. Under Setting section, Click on Configuration\n5. Set HTTP version to 2.0 under General settings\nNOTE: Most modern browsers support HTTP 2.0 protocol over TLS only, while non-\nencrypted traffic continues to use HTTP 1.1. To ensure that client browsers connect to\nyour app with HTTP/2, either buy an App Service Certificate for your app's custom\ndomain or bind a third party certificate.",
            "impact" : "INFO",
            "probability" : "INFO",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subcription, web_apps in self.web_apps_config.items():
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


    def app_service_6(self):
        # Ensure FTP deployments are Disabled (CIS)

        results = {
            "id" : "app_service_6",
            "ref" : "9.9",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "app_service",
            "name" : "Ensure FTP deployments are Disabled (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "By default, Azure Functions, Web, and API Services can be deployed over FTP. If FTP\nis required for an essential deployment workflow, FTPS should be required for FTP\nlogin for all App Service Apps and Functions.\nRationale:\nAzure FTP deployment endpoints are public. An attacker listening to traffic on a wifi\nnetwork used by a remote employee or a corporate network could see login traffic in\nclear-text which would then grant them full control of the code base of the app or\nservice. This finding is more severe if User Credentials for deployment are set at the\nsubscription level rather than using the default Application Credentials which are unique\nper App.",
            "remediation" : "Configure the affected app services to use FTPS only deployments.From Azure Portal\n1. Go to the Azure Portal\n2. Select App Services\n3. Click on an app\n4. Select Settings and then Configuration\n5. Under General Settings, for the Platform Settings, the FTP state should be\nset to Disabled or FTPS Only",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subcription, web_apps in self.web_apps_config.items():
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

    def app_service_7(self):
        # Ensure That stack version is the Latest, If Used to Run the Web App (CIS)

        results = {
            "id" : "app_service_7",
            "ref" : "9.5-9.8",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "app_service",
            "name" : "Ensure That stack version is the Latest, If Used to Run the Web App (CIS)",
            "affected": [],
            "analysis" : {},
            "description" : "Periodically newer versions are released for stack software either due to security flaws\nor to include additional functionality. Using the latest stack version for web apps is\nrecommended in order to take advantage of security fixes, if any, and/or additional\nfunctionalities of the newer version.\nRationale:\nNewer versions may contain security enhancements and additional functionality. Using\nthe latest software version is recommended in order to take advantage of\nenhancements and new capabilities. With each software installation, organizations need\nto determine if a given update meets their requirements. They must also verify the\ncompatibility and support provided for any additional software against the update\nrevision that is selected.",
            "remediation" : "From Azure Portal\n1. From Azure Home open the Portal Menu in the top left\n2. Go to App Services\n3. Click on each App\n4. Under Settings section, click on Configuration\n5. Click on the General settings pane, ensure that for a Stack of stack the Major\nVersion and Minor Version reflect the latest stable and supported release.",
            "impact" : "INFO",
            "probability" : "INFO",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 
        
 #Python|3.11
#PYTHON|3.12
#PHP|8.2
#JAVA|17-java17
#NODE|20-lts
        #https://github.com/Azure/app-service-linux-docs/tree/master/Runtime_Support

        php = False
        for subcription, web_apps in self.web_apps_config.items():
            for web_app in web_apps:
                if web_app.php_version:
                    php = True
                    if web_app.php_version != "PHP 8.2":
                        results["affected"].append(web_app.name)
                        results["analysis"][web_app.name] = web_app.php_version

        if results["affected"]:
            results["pass_fail"] = "FAIL"
        elif php:
            results["pass_fail"] = "PASS"
            results["analysis"] = "web apps are using the latest version of PHP"
        else:
            results["analysis"] = "no PHP web apps in use"

        return results

    def app_service_8(self):
        # Ensure That '.NET version' supported, If Used to Run the Web App 

        results = {
            "id" : "app_service_8",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "app_service",
            "name" : "Ensure That .NET Version is supported, If Used to Run the Web App",
            "affected": [],
            "analysis" : {},
            "description" : "Periodically newer versions are released for the .NET framework software either due to security flaws\nor to include additional functionality. Using the latest .NET version for web apps is\nrecommended in order to take advantage of security fixes, if any, and/or additional\nfunctionalities of the newer version.\nRationale:\nNewer versions may contain security enhancements and additional functionality. Using\nthe latest software version is recommended in order to take advantage of\nenhancements and new capabilities. With each software installation, organizations need\nto determine if a given update meets their requirements. They must also verify the\ncompatibility and support provided for any additional software against the update\nrevision that is selected.",
            "remediation" : "From Azure Portal\n1. From Azure Home open the Portal Menu in the top left\n2. Go to App Services\n3. Click on each App\n4. Under Settings section, click on Configuration\n5. Click on the General settings pane, ensure that for a Stack of .NET the Major\nVersion and Minor Version reflect the latest stable and supported release.",
            "impact" : "INFO",
            "probability" : "INFO",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 
        
        #https://github.com/Azure/app-service-linux-docs/tree/master/Runtime_Support

        dotnet = False
        for subcription, web_apps in self.web_apps_config.items():
            for web_app in web_apps:
                if web_app.net_framework_version:
                    dotnet = True
                    if web_app.net_framework_version != "v4.0": # hack for shity api
                        if web_app.net_framework_version != "v6.0" and web_app.net_framework_version != "v7.0":
                            results["affected"].append(web_app.name)
                            results["analysis"][web_app.name] = web_app.net_framework_version

        if results["affected"]:
            results["pass_fail"] = "FAIL"
        elif dotnet:
            results["pass_fail"] = "PASS"
            results["analysis"] = "web apps are using a supported version of .net"
        else:
            results["analysis"] = "no .net web apps in use"

        return results


