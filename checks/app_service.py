from azure.mgmt.web import WebSiteManagementClient
import logging

#from utils.utils import describe_regions
#from utils.utils import list_subscriptions

class app_service(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.web_apps = self.get_web_apps()

    def get_web_apps(self):
        web_apps = {}
        for subscription in self.subscriptions:
            logging.info(f'getting web apps in subscription: { subscription.display_name }')
            try:
                client= WebSiteManagementClient(credential=self.credential, subscription_id=subscription.subscription_id)
                web_apps[subscription.subscription_id] = list(client.web_apps.list())
            except Exception as e:
                logging.error(f'error getting web apps in subscription: { subscription.display_name }, error: { e }')

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

        for subscription, web_apps in self.web_apps.items():
            for app in web_apps:
                results["affected"].append(app.name)

        if results["analysis"]:
            results["pass_fail"] = "INFO"
        else:
            results["pass_fail"] = "INFO"
            results["analysis"] = "no web apps found"

        return results
