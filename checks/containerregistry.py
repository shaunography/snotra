from azure.mgmt.containerregistry import ContainerRegistryManagementClient

import azure.core.exceptions as exceptions

import logging

class containerregistry(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.resource_groups = resource_groups
        self.resources = resources
        self.registries = self.get_registries()

    def get_registries(self):
        registries = {}
        for subscription, resource_groups in self.resources.items():
            results = {}
            client = ContainerRegistryManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                registries_in_group = []
                for resource in resources:
                    if resource.type == "Microsoft.ContainerRegistry/registries":
                        logging.info(f'getting container registry { resource.name }')
                        try:
                            registries_in_group.append(client.registries.get(registry_name=resource.name, resource_group_name=resource_group))
                        except Exception as e:
                            logging.error(f'error getting container registry: { resource.name }, error: { e }')
                if registries_in_group:
                    results[resource_group] = registries_in_group
            if results:
                registries[subscription] = results
        return registries

    def run(self):
        findings = []
        findings += [ self.containerregistry_1() ]
        return findings

    def containerregistry_1(self):
        # Ensure that 'Public Network Access' is `Disabled' for Container Registries

        results = {
            "id" : "containerregistry_1",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "containerregistry",
            "name" : "Ensure that 'Public Network Access' is `Disabled' for Container Registries",
            "affected": [],
            "analysis" : "",
            "description" : "The account being reviewed was found to contain a container registry that doesn’t have any network level access restrictions in place and therefore allows unrestricted traffic from the public internet.\nMaster security In AKS, the Kubernetes master components are part of the managed service provided by Microsoft. Each AKS cluster has its own single-tenanted, dedicated Kubernetes master to provide the API Server, Scheduler, etc. This master is managed and maintained by Microsoft.\nBy default, the Kubernetes API server uses a public IP address and a fully qualified domain name (FQDN). You can limit access to the API server endpoint using authorized IP ranges. You can also create a fully private cluster to limit API server access to your virtual network. You can control access to the API server using Kubernetes role-based access control (Kubernetes RBAC) and Azure RBAC.\nAlthough protected with authentication to minimise the attack Surface of your account and provide greater defence in depth it is recommended to either use a private clusters that only permit access from internal Azure Virtual Networks and or configure a set of authorized IP ranges following the principle of least privilege and only allow access from trusted networks and IP addresses.",
            "remediation" : "Configure the affected Clusters to be Private and block public access from the internet, if internet access is required configure a set of authorized IP ranges following the principle of least privilege and only allow access from trusted IP addresses.",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "5.4",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, resource_groups in self.registries.items():
            for resource_group, registries in resource_groups.items():
                for registry in registries:
                    if registry.public_network_access != "Disabled":
                        results["affected"].append(registry.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected container registries allow public network access"
        elif self.registries:
            results["analysis"] = "container registry do not allow public network access"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no clusters found"

        return results

