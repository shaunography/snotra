from azure.mgmt.web import WebSiteManagementClient
import logging

class app_service(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.resource_groups = resource_groups
        self.resources = resources
        self.web_apps = self.get_web_apps()

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

    def run(self):
        findings = []
        findings += [ self.app_service_1() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.app_service_1() ]
        return findings

    def app_service_1(self):
        # 

        results = {
            "id" : "app_service_1",
            "ref" : "",
            "compliance" : "",
            "level" : 1,
            "service" : "app_service",
            "name" : "Azure App Services",
            "affected": [],
            "analysis" : "",
            "description" : "",
            "remediation" : "",
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
            results["pass_fail"] = "INFO"
            results["analysis"] = "no web apps found"

        return results
