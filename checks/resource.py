from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource import SubscriptionClient

import logging

class resource(object):

    def __init__(self, credential):
        self.credential = credential
        self.subscriptions = self.get_subscriptions()
        self.resource_groups = self.get_resource_groups()
        self.resources = self.get_resources()

    def get_subscriptions(self):
        return list(SubscriptionClient(self.credential).subscriptions.list())

    def get_resource_groups(self):
        groups = {}
        for subscription in self.subscriptions:
            logging.info(f'getting resource groups in subscription: { subscription.display_name }')
            try:
                client= ResourceManagementClient(credential=self.credential, subscription_id=subscription.subscription_id)
                groups[subscription.subscription_id] = list(client.resource_groups.list())
            except Exception as e:
                logging.error(f'error getting resource groups in subscription: { subscription.display_name }, error: { e }')

        return groups

    def get_resources(self):
        resources = {}

        for subscription in self.subscriptions:
            resources[subscription.subscription_id] = {}
            for group in self.resource_groups[subscription.subscription_id]:
                logging.info(f'getting resources in resource group { group.name }')
                try:
                    client = ResourceManagementClient(credential=self.credential, subscription_id=subscription.subscription_id)
                    response = list(client.resources.list_by_resource_group(group.name, expand = "createdTime,changedTime"))
                    if response:
                        resources[subscription.subscription_id][group.name] = response
                except Exception as e:
                    logging.error(f'error getting resources in resource group: { group.name }, error: { e }')

        return resources

    def run(self):
        findings = []
        findings += [ self.resource_1() ]
        findings += [ self.resource_2() ]
        findings += [ self.resource_3() ]
        return findings


    def resource_1(self):
        # 

        results = {
            "id" : "resource_1",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "resource",
            "name" : "Resource Groups",
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

        results["analysis"] = self.resource_groups

        for subscription, groups in self.resource_groups.items():
            for group in groups:
                results["affected"].append(group.name)

        if results["analysis"]:
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "no resource groups found"


        return results

    def resource_2(self):
        # 

        results = {
            "id" : "resource_2",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "resource",
            "name" : "ALl Resources",
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

        results["analysis"] = self.resources

        for subscription, resource_groups in self.resources.items():
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    results["affected"].append(resource.name)

        if results["analysis"]:
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "no resources found"


        return results

    def resource_3(self):
        # 

        results = {
            "id" : "resource_3",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "resource",
            "name" : "Resource Types",
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

        results["analysis"]  = {}

        for subscription, resource_groups in self.resources.items():
            types = []
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    types.append(resource.type)

            results["analysis"][subscription] = list(set(types))

        if results["analysis"]:
            results["affected"] = [ i for i, v in results["analysis"].items() ]
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "no resources found"


        return results
