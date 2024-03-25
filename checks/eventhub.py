from azure.mgmt.eventhub import EventHubManagementClient

import azure.core.exceptions as exceptions

import logging

class eventhub(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.resource_groups = resource_groups
        self.resources = resources
        self.name_spaces = self.get_name_spaces()
        #self.event_hubs = self.get_event_hubs()

    def get_name_spaces(self):
        name_spaces = {}
        for subscription, resource_groups in self.resources.items():
            results = {}
            client = EventHubManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                name_spaces_in_group = []
                for resource in resources:
                    if resource.type == "Microsoft.EventHub/namespaces":
                        logging.info(f'getting event hub namespace { resource.name }')
                        try:
                            name_spaces_in_group.append(client.namespaces.get(namespace_name=resource.name, resource_group_name=resource_group))
                        except Exception as e:
                            logging.error(f'error getting event hub namespace: { resource.name }, error: { e }')
                if name_spaces_in_group:
                    results[resource_group] = name_spaces_in_group
            if results:
                name_spaces[subscription] = results
        return name_spaces

    def get_event_hubs(self):
        event_hubs = {}
        for subscription, resource_groups in self.resources.items():
            results = {}
            client = EventHubManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                event_hubs_in_group = []
                for resource in resources:
                    if resource.type == "Microsoft.EventHub/namespaces":
                        logging.info(f'getting event hub { resource.name }')
                        try:
                            event_hubs_in_group.append(client.event_hubs.get(event_hub_name=resource.name, resource_group_name=resource_group, namespace_name=resource.name))
                        except Exception as e:
                            logging.error(f'error getting event hub: { resource.name }, error: { e }')
                if event_hubs_in_group:
                    results[resource_group] = event_hubs_in_group
            if results:
                event_hubs[subscription] = results
        return event_hubs

    def run(self):
        findings = []
        findings += [ self.eventhub_1() ]
        #findings += [ self.eventhub_2() ]
        return findings

    def eventhub_1(self):
        # Ensure that 'Public Network Access' is `Disabled' for Event Hub Namespaces

        results = {
            "id" : "eventhub_1",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "eventhubs",
            "name" : "Ensure that 'Public Network Access' is `Disabled' for Event Hub Namespaces",
            "affected": [],
            "analysis" : "",
            "description" : "The account being reviewed was found to contain an event hub namespaces that doesn’t have any network level access restrictions in place and therefore allows unrestricted traffic from the public internet.\nMaster security In AKS, the Kubernetes master components are part of the managed service provided by Microsoft. Each AKS cluster has its own single-tenanted, dedicated Kubernetes master to provide the API Server, Scheduler, etc. This master is managed and maintained by Microsoft.\nBy default, the Kubernetes API server uses a public IP address and a fully qualified domain name (FQDN). You can limit access to the API server endpoint using authorized IP ranges. You can also create a fully private cluster to limit API server access to your virtual network. You can control access to the API server using Kubernetes role-based access control (Kubernetes RBAC) and Azure RBAC.\nAlthough protected with authentication to minimise the attack Surface of your account and provide greater defence in depth it is recommended to either use a private clusters that only permit access from internal Azure Virtual Networks and or configure a set of authorized IP ranges following the principle of least privilege and only allow access from trusted networks and IP addresses.",
            "remediation" : "Configure the affected Clusters to be Private and block public access from the internet, if internet access is required configure a set of authorized IP ranges following the principle of least privilege and only allow access from trusted IP addresses.",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "5.4",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, resource_groups in self.name_spaces.items():
            client = EventHubManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, name_spaces in resource_groups.items():
                for name_space in name_spaces:
                    logging.info(f'getting network rule set for event hub namespace { name_space.name }')
                    try:
                        network = client.namespaces.get_network_rule_set(namespace_name=name_space.name, resource_group_name=resource_group)
                    except Exception as e:
                        logging.error(f'error network rule set getting event hub namespace: { name_space.name }, error: { e }')
                    else:
                        if network.public_network_access != "Disabled":
                            results["affected"].append(name_space.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected event hubs allow public network access"
        elif self.name_spaces:
            results["analysis"] = "event hubs do not allow public network access"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no event hubs found"

        return results

