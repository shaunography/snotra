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
                    except Exception as e:
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
        # Azure Monitor Activity and Resource Logging (CIS)

        results = {
            "id" : "monitor_1",
            "ref" : "5.1",
            "compliance" : "cis_v2.1.0",
            "level" : 2,
            "service" : "monitor",
            "name" : "Azure Monitor Activity and Resource Logging (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "In order to enable effective monitoring of your Azure environment, it is necessary to capture Logs. A lack of monitoring reduces the visibility into the control and data plane, and therefore an organization's ability to detect and respond to malicious activity. Azure supports a number of log types:\nActivity logs - provide an insight into the operations performed on each Azure resource in the subscription from the outside, known as the management plane. in addition to updates on Service Health events. Use the Activity log to determine the what, who, and when for any write action executed on the resources in your subscription. There's a single activity log for each Azure subscription. \nMicrosoft Entra ID Activity logs - contain the history of sign-in activity and an audit trail of changes made in Microsoft Entra ID for a particular tenant. Are viewed via the Microsoft Entra ID admin centre but can be integrated with Azure Monitor via a log analytics workspace. \nResource logs - provide an insight into operations that were performed within an Azure resource. This is known as the data plane. Examples include getting a secret from a Key Vault or making a request to a database. The contents of resource logs vary according to the Azure service and resource type and are available for each individual resource within a subscription. \nNSG Flow Logs -. Network Flow Logs provide valuable insight into the flow of traffic around your network and feed into both Azure Monitor and Azure Sentinel (if in use), permitting the generation of visual flow diagrams to aid with analysing for lateral movement, etc. \nBasic Activity Logs are collected by default and retained for 90 days. Resource Logs (Previously known as Diagnostic Logs) aren't collected until they're enabled and routed to a destination. \nDiagnostic Settings define the type of events that are logged and where to send them. you can manage diagnostic settings at the subscription level which allows additional control of how Activity Logs are captured and retained beyond the defaults provided by Microsoft. Additionally, Diagnostic settings are also available for each individual resource within a subscription in order to capture Resource Logs. When configuring Diagnostic Settings, you may choose to export in one of four ways in which you need to ensure appropriate data retention. The options are Log Analytics, Event Hub, Storage Account, and various Partner Solutions.",
            "remediation" : "A good baseline recommendation for configuring Diagnostic Settings is as follows: \nEnable diagnostic settings for your subscription in order to capture more detailed activity logs and retain them beyond the default 90 day period. Ensure all categories “Administrative”, 'Alert', 'Policy' and 'Security' are enabled for capture. \nIf storing logs in a Storage Account container, ensure the container is not publicly accessible. \nIf storing logs in a Storage Account container, Encrypt the container with a Customer Managed Key (CMK). \nEnable all Diagnostic Settings for Azure Key Vault. \nEnable HTTP Logs for Azure App Service. \nEnable Diagnostic Settings for all mission critical resources that support it. \nEnable audit Logging for MySQL Databases \nEnable logging for PostgreSQL Databases, including: “log_checkpoints”, “log_connections”, “log_disconnections”, “connection_throttling” and “log_retention_days”. \nIt is recommended that network flow logs are captured and fed into a central log analytics workspace and the retention period set to greater than or equal to 90 days \nConsider implementing diagnostic Settings for all appropriate resources in your environment. Given that the mean time to detection in an enterprise is 240 days, a retention period of two years is recommended.  \nThe process of deploying Diagnostic Settings can be difficult to manage when you have many resources. ARM Templates can be used but to simplify the process of creating and applying diagnostic settings at scale, use Azure Policy to automatically generate diagnostic settings for both new and existing resources. At an additional cost you can choose to route the diagnostics to a Log Analytics Workspace so that they can be used in Azure Monitor or Azure Sentinel. Costs for monitoring will also vary with log volume. Not every resource needs to necessarily have logging enabled and not all events need to be logged. Consider compliance and governance requirements to determine the security classification of the data being processed by the given resource so you can adjust the level of logging accordingly. \nMore Information: \nhttps://learn.microsoft.com/en-us/azure/azure-monitor/essentials/platform-logs-overview \nhttps://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings-policy \nhttps://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/howto-access-activity-logs ",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, diagnostic_settings in self.diagnostic_settings.items():
            if not diagnostic_settings:
                results["affected"].append(subscription)
            else:
                for diagnostic_setting in diagnostic_settings:
                    print(diagnostic_setting)

        #Ensure that the following categories are checked: Administrative, Alert, Policy, and Security

        if results["affected"]:
            results["analysis"] = "the affected subscriptions do not have any diagnostic settings enabled"
            results["pass_fail"] = "FAIL"
        else:
            pass

        return results

