from azure.mgmt.monitor import MonitorManagementClient
import azure.core.exceptions as exceptions

import logging

class monitor(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.resource_groups = resource_groups
        self.resources = resources
        self.diagnostic_settings = self.get_diagnostic_settings()

    def get_diagnostic_settings(self):
        diagnostic_settings = {}
        for subscription, resource_groups in self.resources.items():
            results = []
            client = MonitorManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    try:
                        logging.info(f'getting diagnostic settings for { resource.name }')
                        for setting in client.diagnostic_settings.list(resource.id):
                            results.append(setting)
                    except exceptions.HttpResponseError as e:
                        if "ResourceTypeNotSupported" in e.message:
                            pass
                        else:
                            logging.error(f'error getting diagnostic settings for: { resource.name }, error: { e }')
                    except Exceptions as e:
                        logging.error(f'error getting diagnostic settings for: { resource.name }, error: { e }')
            if results:
                diagnostic_settings[subscription] = results
        return diagnostic_settings

    def run(self):
        findings = []
        findings += [ self.monitor_1() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.monitor_1() ]
        return findings

    def monitor_1(self):
        # 

        results = {
            "id" : "monitor_1",
            "ref" : "7.1",
            "compliance" : "cis_v2.1.0",
            "level" : 2,
            "service" : "monitor",
            "name" : "diagnostic settings",
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

        for subscription, diagnostic_settings in self.diagnostic_settings.items():
            for diagnostic_setting in diagnostic_settings:
                #print(diagnostic_setting)
                pass

        return results

