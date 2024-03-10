from azure.mgmt.compute import ComputeManagementClient
from checks.resource import resource
import logging

class compute(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.resource_groups = resource_groups
        self.virtual_machines = self.get_virtual_machines()

    def get_virtual_machines(self):
        virtual_machines = {}

        for subscription in self.subscriptions:
            virtual_machines[subscription.subscription_id] = {}
            for group in self.resource_groups[subscription.subscription_id]:
                logging.info(f'getting virtual machines in resource group { group.name }')
                try:
                    client= ComputeManagementClient(credential=self.credential, subscription_id=subscription.subscription_id)
                    response = list(client.virtual_machines.list(group.name))
                    if response:
                        virtual_machines[subscription.subscription_id][group.name] = response
                except Exception as e:
                    logging.error(f'error getting virtual machines in resource group: { group.name }, error: { e }')

        return virtual_machines

    def run(self):
        findings = []
        findings += [ self.compute_1() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.compute_1() ]
        return findings

    def compute_1(self):
        # 

        results = {
            "id" : "compute_1",
            "ref" : "",
            "compliance" : "",
            "level" : "",
            "service" : "compute",
            "name" : "Virtual Machines",
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

        results["analysis"] = self.virtual_machines

        for subscription, resource_groups in self.virtual_machines.items():
            for resource_group, virtual_machines in resource_groups.items():
                for virtual_machine in virtual_machines:
                    results["affected"].append(virtual_machine.name)

        if results["analysis"]:
            results["pass_fail"] = "INFO"
        else:
            results["pass_fail"] = "INFO"
            results["analysis"] = "no virtual machines found"

        return results
