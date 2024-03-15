from azure.mgmt.network import NetworkManagementClient

import logging
import re

class network(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.resource_groups = resource_groups
        self.resources = resources
        self.bastion_hosts = self.get_bastion_hosts()
        self.public_ip_addresses = self.get_public_ip_addresses()

    def get_bastion_hosts(self):
        bastion_hosts = {}
        for subscription, resource_groups in self.resources.items():
            bastion_hosts[subscription] = []
            #client = NetworkManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.Network/bastionHosts":
                        logging.info(f'getting bastion host { resource.name }')
                        try:
                            #bastion_host = client.bastion_host.get(name=resource.name, resource_group_name=resource_group)
                            #bastion_hosts[subscription].append(bastion_host)
                            bastion_hosts[subscription].append(resource)
                        except Exception as e:
                            logging.error(f'error getting bastion host: { resource.name }, error: { e }')
        return bastion_hosts

    def get_public_ip_addresses(self):
        public_ip_addresses = {}
        for subscription, resource_groups in self.resources.items():
            public_ip_addresses[subscription] = []
            client = NetworkManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.Network/publicIPAddresses":
                        logging.info(f'getting public ip address config { resource.name }')
                        try:
                            public_ip_address = client.public_ip_addresses.get(public_ip_address_name=resource.name, resource_group_name=resource_group)
                            public_ip_addresses[subscription].append(public_ip_address)
                        except Exception as e:
                            logging.error(f'error getting public ip address: { resource.name }, error: { e }')
        return public_ip_addresses

    def run(self):
        findings = []
        findings += [ self.network_1() ]
        findings += [ self.network_2() ]
        findings += [ self.network_3() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.network_1() ]
        return findings

    def network_1(self):
        # Ensure an Azure Bastion Host Exists (CIS)

        results = {
            "id" : "network_1",
            "ref" : "7.1",
            "compliance" : "cis_v2.1.0",
            "level" : 2,
            "service" : "network",
            "name" : "Ensure an Azure Bastion Host Exists (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "The Azure Bastion service allows secure remote access to Azure Virtual Machines over\nthe Internet without exposing remote access protocol ports and services directly to the\nInternet. The Azure Bastion service provides this access using TLS over 443/TCP, and\nsubscribes to hardened configurations within an organization's Azure Active Directory\nservice.\nRationale:\nThe Azure Bastion service allows organizations a more secure means of accessing\nAzure Virtual Machines over the Internet without assigning public IP addresses to those\nVirtual Machines. The Azure Bastion service provides Remote Desktop Protocol (RDP)\nand Secure Shell (SSH) access to Virtual Machines using TLS within a web browser,\nthus preventing organizations from opening up 3389/TCP and 22/TCP to the Internet on\nAzure Virtual Machines. Additional benefits of the Bastion service includes Multi-Factor\nAuthentication, Conditional Access Policies, and any other hardening measures\nconfigured within Azure Active Directory using a central point of access.",
            "remediation" : "From Azure Portal1. Click on Bastions\n2. Select the Subscription\n3. Select the Resource group\n4. Type a Name for the new Bastion host\n5. Select a Region\n6. Choose Standard next to Tier\n7. Use the slider to set the Instance count\n8. Select the Virtual network or Create new\n9. Select the Subnet named AzureBastionSubnet. Create a Subnet named\nAzureBastionSubnet using a /26 CIDR range if it doesn't already exist.\n10. Selct the appropriate Public IP address option.\n11. If Create new is selected for the Public IP address option, provide a Public IP\naddress name.\n12. If Use existing is selected for Public IP address option, select an IP address\nfrom Choose public IP address\n13. Click Next: Tags >\n14. Configure the appropriate Tags\n15. Click Next: Advanced >\n16. Select the appropriate Advanced options\n17. Click Next: Review + create >\n18. Click Create",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, resource_groups in self.resources.items():
            vms = False
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.Compute/virtualMachines":
                        vms = True
                        break

        if vms:
            if self.bastion_hosts:
                results["analysis"] = self.bastion_hosts
                results["affected"] = [ i for i, v in self.bastion_hosts.items() ]
                results["pass_fail"] = "PASS"

            else:
                results["analysis"] = "no bastion hosts in use"
                results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "no virtual machines in use"

        return results

    def network_2(self):
        # Ensure an Azure Bastion Host Exists (CIS)

        results = {
            "id" : "network_2",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "network",
            "name" : "Public IP Addresses",
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

        results["analysis"] = self.public_ip_addresses

        if results["analysis"]:
            results["affected"] = [ i for i, v in self.public_ip_addresses.items() ]
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no public ip addresses in use"
            results["pass_fail"] = "FAIL"

        return results

    def network_3(self):
        # unused public ip addresses

        results = {
            "id" : "network_3",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "network",
            "name" : "Unused Public IP Addresses",
            "affected": [],
            "analysis" : "",
            "description" : "Although not a security risk, Microsoft Azure enforces a small monthly charge for any static Public IP address within your account that is not associated with any resource. To ensure account hygiene and save costs it is recommended to delete any static Public IP Addresses that are no longer required.",
            "remediation" : "Delete any unused IP addresses by navigating to the “Public IP Addresses” service in the web portal, selecting statis IP addresses that are no longer associated with any resource and clicking delete.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, public_ip_addresses in self.public_ip_addresses.items():
            for public_ip_address in public_ip_addresses:
                if public_ip_address.ip_configuration == None:
                    results["affected"].append(public_ip_address.name)

        if results["affected"]:
            results["analysis"] = "The affected public ip addresses are not associated with an resources and are therefore not in use"
            results["pass_fail"] = "FAIL"
        elif self.public_ip_addresses:
            results["analysis"] = "no unused public ip addresses found"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no public ip addresses in use"

        return results

