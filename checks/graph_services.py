from azure.mgmt.graphservices import GraphServicesMgmtClient

from checks.resource import resource
import logging

from datetime import date
from datetime import datetime, timezone
from datetime import timedelta

class graph_services(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.resource_groups = resource_groups
        self.resources = resources
        self.operations = self.get_settings()

    def get_settings(self):
        settings = {}
        for subscription in self.subscriptions:
            client = GraphServicesMgmtClient(credential=self.credential, subscription_id=subscription.subscription_id)
            try:
                settings[subscription.subscription_id] = client.accounts.list_by_subscription()
            except Exception as e:
                logging.error(f'error getting defender settings: , error: { e }')
        return settings


    def run(self):
        findings = []
        findings += [ self.graph_services_1() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.graph_services_2() ]
        return findings

    def graph_services_1(self):
        # Defender For Cloud (CIS)

        results = {
            "id" : "security_1",
            "ref" : "cis",
            "compliance" : "2.1.1-11",
            "level" : 1,
            "service" : "security",
            "name" : "Defender For Cloud (CIS)",
            "affected": [],
            "analysis" : {},
            "description" : "The account under review does not make use of a number of security features provided by Microsoft Defender for Cloud. Microsoft Defender is a cloud-native application protection platform (CNAPP) with a set of security measures and practices designed to protect cloud-based applications from various cyber threats and vulnerabilities.  \nThis finding aims to provide guidance on Microsoft Defender for Cloud product plans and configuration settings. This guidance is intended to ensure that - at a minimum - the protective measures offered by these plans are being considered. Organizations may find that they have existing products or services that provide the same utility as some Microsoft Defender for Cloud products. Security and Administrative personnel need to make the determination on their organization's behalf regarding which - if any - of these recommendations are relevant to their organization's needs. In consideration of the above, and because of the potential for increased cost and complexity, please be aware that all Defender Plan recommendations are profiled as 'Level 2' recommendations under the CIS Azure Foundations Benchmark.",
            "remediation" : "It is recommended to configure Microsoft defender for cloud as follows:\nEnable Microsoft Defender for cloud services - Where relevant it is enable Threat Protection for; Servers, App Services, Databases, Azure SQL Databases, SQL Servers on Machines, Open-Source Relational, Databases, Storage, Containers, Azure Cosmos DB, Key Vault, DNS, Resource Manager. \nEnable all ASC Default Audit Policies – Audit Policies are what Microsoft Defender Cloud recommendations are based on. Enabling recommendations in ASC default policy ensures that Defender provides the ability to monitor all of the supported recommendations and optionally allow automated action for a few of the supported recommendations. \nEnable automatic provisioning of the monitoring agent to collect security data - When Log Analytics agent for Azure VMs is turned on, Microsoft Defender for Cloud provisions the Microsoft Monitoring Agent on all existing supported Azure virtual machines and any new ones that are created. The Microsoft Monitoring Agent scans for various security-related configurations and events such as system updates, OS vulnerabilities, endpoint protection, and provides alerts. \nEnable automatic provisioning of “vulnerability assessment for machines” - Vulnerability assessment for machines scans for various security-related configurations and events such as system updates, OS vulnerabilities, and endpoint protection, then produces alerts on threat and vulnerability findings. \nEnable Auto provisioning of “Microsoft Defender for Containers components” – if relevant Enable automatic provisioning of the Microsoft Defender for Containers components,  as with any compute resource, Container environments require hardening and run-time protection to ensure safe operations and detection of threats and vulnerabilities. \nEnable security alert emails to subscription owners and a security contact email address - Enabling security alert emails to subscription owners ensures that they receive security alert emails from Microsoft. Additionally, adding your Security Contact's email address to the 'Additional email addresses' field ensures that your organization's Security Team is included in these alerts. This ensures that the proper people are aware of any potential compromise in order to mitigate the risk in a timely fashion. \nEnable notifications for high severity alerts - Enabling security alert emails ensures that security alert emails are received from Microsoft. This ensures that the right people are aware of any potential security issues and are able to mitigate the risk. \nEnable Microsoft Defender for Cloud Apps (formally Microsoft cloud app Security) integration - This integration setting enables Microsoft Defender for Cloud Apps (formerly 'Microsoft Cloud App Security' or 'MCAS' - see additional info) to communicate with Microsoft Defender for Cloud. By analysing the Azure Resource Manager records, Microsoft Defender for Cloud detects unusual or potentially harmful operations in the Azure subscription environment. Several of the preceding analytics are powered by Microsoft Defender for Cloud Apps. To benefit from these analytics, subscription must have a Cloud App Security license. Microsoft Defender for Cloud Apps works only with Standard Tier subscriptions. \nEnable Microsoft Defender for Endpoint (Formally Advanced Threat Protection) integration - Microsoft Defender for Endpoint integration brings comprehensive Endpoint Detection and Response (EDR) capabilities within Microsoft Defender for Cloud. This integration helps to spot abnormalities, as well as detect and respond to advanced attacks on endpoints monitored by Microsoft Defender for Cloud. MDE works only with Standard Tier subscriptions. \nEnable Microsoft Defender for IoT Hub – If relevant enable Microsoft Defender in the IoT Hub. Microsoft Defender for IoT acts as a central security hub for IoT devices within your organization. IoT devices are very rarely patched and can be potential attack vectors for enterprise networks. Updating their network configuration to use a central security hub allows for detection of these breaches. \nMake use of Microsoft Defender for External Attack Surface Monitoring - As more services are exposed to the public internet it is important to be able to monitor the externally exposed surface of your Azure Tenant, to this end it is recommended that tools that monitor this surface are implemented. Microsoft have a new tool to do this in their Defender Suite of products. Defender EASM, this tool is configured very simply to scan specified domains and report on them, specific domains and addresses can be excluded from the scan. Typically, these tools will report on any vulnerability that is identified (CVE) and will also identify ports and protocols that are open on devices. Results are classified Critical/High/Medium & Low with proposed mitigations. \nSQL Server – Enable Vulnerability Assessment (VA) and periodic recurring scans for all SQL Servers \nAutomatically Send SQL Server VA scan reports to a designated email address, admins and subscriptions owners. \nNOTE: The above recommendations will incur additional costs, often requires additional licensing and in some cases may have undesirable side effects. \nFor more detailed information on how to implement these changes please consult section 2 of the CIS Azure Foundation Benchmark. ",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "6.5",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, operations in self.operations.items():
            for operation in operations:
                print(operation)
                        #results["affected"].append(subscription)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["affected"] = list(set(results["affected"]))
        else:
            results["pass_fail"] = "PASS"

        return results

