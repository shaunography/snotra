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
        self.network_security_groups = self.get_network_security_groups()
        self.network_watchers = self.get_network_watchers()
        self.flow_logs = self.get_flow_logs()

    def get_bastion_hosts(self):
        bastion_hosts = {}
        for subscription, resource_groups in self.resources.items():
            results = []
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.Network/bastionHosts":
                        logging.info(f'getting bastion host { resource.name }')
                        try:
                            results.append(resource)
                        except Exception as e:
                            logging.error(f'error getting bastion host: { resource.name }, error: { e }')
            if results:
                bastion_hosts[subscription] = results
        return bastion_hosts

    def get_public_ip_addresses(self):
        public_ip_addresses = {}
        for subscription, resource_groups in self.resources.items():
            results = []
            client = NetworkManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.Network/publicIPAddresses":
                        logging.info(f'getting public ip address config { resource.name }')
                        try:
                            public_ip_address = client.public_ip_addresses.get(public_ip_address_name=resource.name, resource_group_name=resource_group)
                            results.append(public_ip_address)
                        except Exception as e:
                            logging.error(f'error getting public ip address: { resource.name }, error: { e }')
            if results:
                public_ip_addresses[subscription] = results
        return public_ip_addresses

    def get_network_security_groups(self):
        network_security_groups = {}
        for subscription, resource_groups in self.resources.items():
            results = []
            client = NetworkManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.Network/networkSecurityGroups":
                        logging.info(f'getting nsg address config { resource.name }')
                        try:
                            network_security_group = client.network_security_groups.get(network_security_group_name=resource.name, resource_group_name=resource_group)
                            results.append(network_security_group)
                        except Exception as e:
                            logging.error(f'error getting nsg: { resource.name }, error: { e }')
            if results:
                network_security_groups[subscription] = results
        return network_security_groups

    def get_network_watchers(self):
        network_watchers = {}
        for subscription, resource_groups in self.resources.items():
            results = []
            client = NetworkManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.Network/networkWatchers":
                        logging.info(f'getting network watcher config { resource.name }')
                        try:
                            network_watcher = client.network_watchers.get(network_watcher_name=resource.name, resource_group_name=resource_group)
                            results.append(network_watcher)
                        except Exception as e:
                            logging.error(f'error getting network watcher: { resource.name }, error: { e }')
            if results:
                network_watchers[subscription] = results
        return network_watchers

    def get_flow_logs(self):
        flow_logs = {}
        for subscription, resource_groups in self.resources.items():
            results = []
            client = NetworkManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "microsoft.network/networkWatchers/flowLogs":
                        logging.info(f'getting flow log config { resource.name }')
                        try:
                            flow_log = client.flow_logs.get(flow_log_name=resource.name.split("/")[1], resource_group_name=resource_group, network_watcher_name=resource.name.split("/")[0])
                            results.append(flow_log)
                        except Exception as e:
                            logging.error(f'error getting nsg: { resource.name }, error: { e }')
            if results:
                flow_logs[subscription] = results
        return flow_logs

    def run(self):
        findings = []
        findings += [ self.network_1() ]
        findings += [ self.network_2() ]
        findings += [ self.network_3() ]
        findings += [ self.network_4() ]
        findings += [ self.network_5() ]
        findings += [ self.network_6() ]
        findings += [ self.network_7() ]
        findings += [ self.network_8() ]
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
            "description" : "The Azure Bastion service allows secure remote access to Azure Virtual Machines over the Internet without exposing remote access protocol ports and services directly to the Internet. The Azure Bastion service provides this access using TLS over 443/TCP, and subscribes to hardened configurations within an organization's Azure Active Directory service. The Azure Bastion service allows organizations a more secure means of accessing Azure Virtual Machines over the Internet without assigning public IP addresses to those Virtual Machines. The Azure Bastion service provides Remote Desktop Protocol (RDP) and Secure Shell (SSH) access to Virtual Machines using TLS within a web browser, thus preventing organizations from opening up 3389/TCP and 22/TCP to the Internet on Azure Virtual Machines. Additional benefits of the Bastion service includes Multi-Factor Authentication, Conditional Access Policies, and any other hardening measures configured within Azure Active Directory using a central point of access.",
            "remediation" : "From Azure Portal1. Click on Bastions\n2. Select the Subscription\n3. Select the Resource group\n4. Type a Name for the new Bastion host\n5. Select a Region\n6. Choose Standard next to Tier\n7. Use the slider to set the Instance count\n8. Select the Virtual network or Create new\n9. Select the Subnet named AzureBastionSubnet. Create a Subnet named AzureBastionSubnet using a /26 CIDR range if it doesn't already exist.\n10. Selct the appropriate Public IP address option.\n11. If Create new is selected for the Public IP address option, provide a Public IP address name.\n12. If Use existing is selected for Public IP address option, select an IP address from Choose public IP address\n13. Click Next: Tags >\n14. Configure the appropriate Tags\n15. Click Next: Advanced >\n16. Select the appropriate Advanced options\n17. Click Next: Review + create >\n18. Click Create",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        vms = False
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
            results["pass_fail"] = "N/A"

        return results

    def network_2(self):
        # Ensure that Public IP addresses are Evaluated on a Periodic Basis (CIS)

        results = {
            "id" : "network_2",
            "ref" : "6.7",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "network",
            "name" : "Ensure that Public IP addresses are Evaluated on a Periodic Basis (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Public IP Addresses provide tenant accounts with Internet connectivity for resources contained within the tenant. During the creation of certain resources in Azure, a Public IP Address may be created. All Public IP Addresses within the tenant should be periodically reviewed for accuracy and necessity.\n Public IP Addresses allocated to the tenant should be periodically reviewed for necessity. Public IP Addresses that are not intentionally assigned and controlled present a publicly facing vector for threat actors and significant risk to the tenant.",
            "remediation" : "Review all public ip addresses and determine if there continued availability is required.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["analysis"] = self.public_ip_addresses

        if results["analysis"]:
            results["affected"] = [ i for i, v in results["analysis"].items() ]
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "no public ip addresses found"
            results["pass_fail"] = "N/A"

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
            results["pass_fail"] = "N/A"

        return results

    def network_4(self):
        # Unused Network Security Groups

        results = {
            "id" : "network_4",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "network",
            "name" : "Unused Network Security Groups",
            "affected": [],
            "analysis" : "",
            "description" : "The affected Network Security Groups are not associated with any Subnets of Network interfaces and therefore not in use. To maintain the hygiene of the environment, make maintenance and auditing easier and reduce the risk of NSGs erroneously being used and inadvertently granting more access than required, all old unused security groups should be removed.",
            "remediation" : "Ensure all security groups that are temporary and not being used are deleted when no longer required.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, network_security_groups in self.network_security_groups.items():
            for network_security_group in network_security_groups:
                if not network_security_group.network_interfaces and not network_security_group.subnets:
                    results["affected"].append(network_security_group.name)

        if results["affected"]:
            results["analysis"] = "the affected network security groups are not attached and are therefore not in use"
            results["pass_fail"] = "FAIL"
        elif self.network_security_groups:
            results["analysis"] = "no unused network security groups found"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no network security groups in use"
            results["pass_fail"] = "N/A"

        return results

    def network_5(self):
        # Ensure that Network Security Group Flow logs are captured and sent to Log Analytics (CIS)

        results = {
            "id" : "network_5",
            "ref" : "5.1.5",
            "compliance" : "cis_v2.1.0",
            "level" : 2,
            "service" : "network",
            "name" : "Ensure that Network Security Group Flow logs are captured and sent to Log Analytics (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Ensure that network flow logs are captured and fed into a central log analytics workspace. Network Flow Logs provide valuable insight into the flow of traffic around your network and feed into both Azure Monitor and Azure Sentinel (if in use), permitting the generation of visual flow diagrams to aid with analyzing for lateral movement, etc.",
            "remediation" : "From Azure Portal\n1. Navigate to Network Watcher.\n2. Select NSG flow logs.\n3. Select + Create.\n4. Select the desired Subscription.\n5. Select + Select NSG.\n6. Select a network security group.\n7. Click Confirm selection.\n8. Select or create a new Storage Account.\n9. Input the retention in days to retain the log.\n10. Click Next.\n11. Under Configuration, select Version 2.\n12. If rich analytics are required, select Enable Traffic Analytics, a processing interval, and a Log Analytics Workspace.\n13. Select Next.\n14. Optionally add Tags.\n15. Select Review + create.\n16. Select Create.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, network_security_groups in self.network_security_groups.items():
            for network_security_group in network_security_groups:
                if not network_security_group.flow_logs:
                    results["affected"].append(network_security_group.name)

        if results["affected"]:
            results["analysis"] = "the affected network security groups do not have flow logs configured"
            results["pass_fail"] = "FAIL"
        elif self.network_security_groups:
            results["analysis"] = "network security groups have flow logs configured"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no network security groups in use"
            results["pass_fail"] = "N/A"

        return results

    def network_6(self):
        # Ensure that Network Security Group Flow Log retention period is greater than 90 days (CIS)

        results = {
            "id" : "network_6",
            "ref" : "6.5",
            "compliance" : "cis_v2.1.0",
            "level" : 2,
            "service" : "network",
            "name" : "Ensure that Network Security Group Flow Log retention period is greater than 90 days (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Network Security Group Flow Logs should be enabled and the retention period set to greater than or equal to 90 days. Flow logs enable capturing information about IP traffic flowing in and out of network security groups. Logs can be used to check for anomalies and give insight into suspected breaches.",
            "remediation" : "From Azure Portal\n1. Go to Network Watcher\n2. Select NSG flow logs blade in the Logs section\n3. Select each Network Security Group from the list\n4. Ensure Status is set to On\n5. Ensure Retention (days) setting greater than 90 days\n6. Select your storage account in the Storage account field\n7. Select Save",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, flow_logs in self.flow_logs.items():
            for flow_log in flow_logs:
                if flow_log.retention_policy:
                    if flow_log.retention_policy.days < 90:
                        results["affected"].append(flow_log.name)

        if results["affected"]:
            results["analysis"] = "the affected flow logs are using a retention policy that is less than 90 days"
            results["pass_fail"] = "FAIL"
        elif self.flow_logs:
            results["analysis"] = "flow logs are using retention policies greater than 90 days"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no flow logs in use"
            results["pass_fail"] = "N/A"

        return results

    def network_7(self):
        # Ensure that Network Watcher is Enabled (CIS)

        results = {
            "id" : "network_7",
            "ref" : "6.6",
            "compliance" : "cis_v2.1.0",
            "level" : 2,
            "service" : "network",
            "name" : "Ensure that Network Watcher is Enabled (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Enable Network Watcher for physical regions in Azure subscriptions. Network diagnostic and visualization tools available with Network Watcher help users understand, diagnose, and gain insights to the network in Azure.\nThere are additional costs per transaction to run and store network data. For high- volume networks these charges will add up quickly.",
            "remediation" : "Opting out of Network Watcher automatic enablement is a permanent change. Once\nyou opt-out you cannot opt-in without contacting support.\nTo manually enable Network Watcher in each region where you want to use Network\nWatcher capabilities, follow the steps below.\nFrom Azure Portal\n1. Go to Network Watcher.\n2. Click Create.\n3. Select a Region from the drop-down menu.\n4. Click Add.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, network_watchers in self.network_watchers.items():
            if not network_watchers:
                results["affected"].append(subscription)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "no network watchers were found in the affected subscriptions"
        else:
            results["analysis"] = "network watchers are in use"
            results["pass_fail"] = "PASS"

        return results

    def network_8(self):
        # Ensure that Network Security Group Flow logs are captured and sent to Log Analytics (CIS)

        results = {
            "id" : "network_8",
            "ref" : "6.1-4",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "network",
            "name" : "Ensure that Network Security Group Flow logs are captured and sent to Log Analytics (CIS)",
            "affected": [],
            "analysis" : {},
            "description" : "The affected network security groups contain rules which allows unrestricted access to admin services from the internet. Admin services are often targetted by attackers and if compromised will often leave to unauthorised privileged access to resources. Network security groups should be periodically evaluated for port misconfigurations. Where certain ports and protocols may be exposed to the Internet, they should be evaluated for necessity and restricted wherever they are not explicitly required.\nThe potential security problem with using RDP / SSH / UDP / HTTP(S) over the Internet is that attackers can use various brute force techniques to gain access to Azure Virtual Machines. Once the attackers gain access, they can use a virtual machine as a launch point for compromising other machines on an Azure Virtual Network or even attack networked devices outside of Azure. ",
            "remediation" : "Network should be configured following the principle of least privilege. Where external access to admin services is required, NSGs should be configured to only allows access from a white list of trusted IP addresses.",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "6.5",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        admin_ports = [ "22", "3389", "1433" ]
        analysis = {}

        for subscription, network_security_groups in self.network_security_groups.items():
            analysis = {}
            for network_security_group in network_security_groups:
                rules = []
                for rule in network_security_group.security_rules:
                    if rule.direction == "Inbound":
                        if rule.access == "Allow":
                            if rule.source_address_prefix == "*":
                                if not rule.source_address_prefixes:
                                    if not rule.source_application_security_groups:
                                        if rule.destination_port_range in admin_ports:
                                            results["affected"].append(network_security_group.name)
                                            rules.append(rule)

                if rules:
                    analysis[network_security_group.name] = rules
            if analysis:
                    results["analysis"][subscription] = analysis

        if results["affected"]:
            results["pass_fail"] = "FAIL"
        elif self.network_security_groups:
            results["analysis"] = "no network security groups that allow access to admin services from the internet"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no network security groups in use"
            results["pass_fail"] = "N/A"

        return results
