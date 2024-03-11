from azure.mgmt.compute import ComputeManagementClient
from checks.resource import resource
import logging

class compute(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.resource_groups = resource_groups
        self.resources = resources
        self.virtual_machines = self.get_virtual_machines()

    def get_virtual_machines(self):
        virtual_machines = {}
        for subscription, resource_groups in self.resources.items():
            virtual_machines[subscription] = []
            client = ComputeManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.Compute/virtualMachines":
                        logging.info(f'getting virtual machine { resource.name }')
                        try:
                            virtual_machine = client.virtual_machines.get(vm_name=resource.name, resource_group_name=resource_group)
                            virtual_machines[subscription].append(virtual_machine)
                        except Exception as e:
                            logging.error(f'error getting virtual machine: { resource.name }, error: { e }')

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
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
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

        if results["analysis"]:
            results["affected"] = [ i for i, v in results["analysis"].items() ]
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "no virtual machines found"

        return results
