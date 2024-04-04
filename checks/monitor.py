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
        self.activity_log_alerts = self.get_activity_log_alerts()

    def get_diagnostic_settings(self):
        diagnostic_settings = {}
        for subscription, resource_groups in self.resources.items():
            results = []
            client = MonitorManagementClient(credential=self.credential, subscription_id=subscription)
            for setting in client.diagnostic_settings.list(resource_uri="/subscriptions/" + subscription): # get subscripton level diagnostic settings
                results.append(setting)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    # get diagnostic setting at blob etc level
                    if resource.type == "Microsoft.Storage/storageAccounts":
                        try:
                            logging.info(f'getting diagnostic settings for storage account { resource.name }')
                            for setting in client.diagnostic_settings.list(resource.id):
                                results.append(setting)
                            for setting in client.diagnostic_settings.list(resource.id + "/blobServices/default"):
                                results.append(setting)
                            for setting in client.diagnostic_settings.list(resource.id + "/queueServices/default"):
                                results.append(setting)
                            for setting in client.diagnostic_settings.list(resource.id + "/tableServices/default"):
                                results.append(setting)
                            for setting in client.diagnostic_settings.list(resource.id + "/fileServices/default"):
                                results.append(setting)
                        except exceptions.HttpResponseError as e:
                            if "ResourceTypeNotSupported" in e.message:
                                pass
                            else:
                                logging.error(f'error getting diagnostic settings for: { resource.name }, error: { e }')
                        except Exception as e:
                            logging.error(f'error getting diagnostic settings for: { resource.name }, error: { e }')
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

    def get_activity_log_alerts(self):
        activity_log_alerts = {}
        for subscription, resource_groups in self.resources.items():
            results = []
            client = MonitorManagementClient(credential=self.credential, subscription_id=subscription)
            results = client.activity_log_alerts.list_by_subscription_id()
            if results:
                activity_log_alerts[subscription] = results
        return activity_log_alerts

    def run(self):
        findings = []
        findings += [ self.monitor_1() ]
        findings += [ self.monitor_2() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.monitor_1() ]
        findings += [ self.monitor_2() ]
        return findings

    def monitor_1(self):
        # Azure Monitor Activity and Resource Logging (CIS)

        results = {
            "id" : "monitor_1",
            "ref" : "5.1,3.13,3.14",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "monitor",
            "name" : "Azure Monitor Activity and Resource Logging (CIS)",
            "affected": [],
            "analysis" : [], 
            "description" : "In order to enable effective monitoring of your Azure environment, it is necessary to capture Logs. A lack of monitoring reduces the visibility into the control and data plane, and therefore an organization's ability to detect and respond to malicious activity. Azure supports a number of log types:\nActivity logs - provide an insight into the operations performed on each Azure resource in the subscription from the outside, known as the management plane. in addition to updates on Service Health events. Use the Activity log to determine the what, who, and when for any write action executed on the resources in your subscription. There's a single activity log for each Azure subscription. \nMicrosoft Entra ID Activity logs - contain the history of sign-in activity and an audit trail of changes made in Microsoft Entra ID for a particular tenant. Are viewed via the Microsoft Entra ID admin centre but can be integrated with Azure Monitor via a log analytics workspace. \nResource logs - provide an insight into operations that were performed within an Azure resource. This is known as the data plane. Examples include getting a secret from a Key Vault or making a request to a database. The contents of resource logs vary according to the Azure service and resource type and are available for each individual resource within a subscription. \nNSG Flow Logs -. Network Flow Logs provide valuable insight into the flow of traffic around your network and feed into both Azure Monitor and Azure Sentinel (if in use), permitting the generation of visual flow diagrams to aid with analysing for lateral movement, etc. \nBasic Activity Logs are collected by default and retained for 90 days. Resource Logs (Previously known as Diagnostic Logs) aren't collected until they're enabled and routed to a destination. \nDiagnostic Settings define the type of events that are logged and where to send them. you can manage diagnostic settings at the subscription level which allows additional control of how Activity Logs are captured and retained beyond the defaults provided by Microsoft. Additionally, Diagnostic settings are also available for each individual resource within a subscription in order to capture Resource Logs. When configuring Diagnostic Settings, you may choose to export in one of four ways in which you need to ensure appropriate data retention. The options are Log Analytics, Event Hub, Storage Account, and various Partner Solutions.",
            "remediation" : "A good baseline recommendation for configuring Diagnostic Settings is as follows: \nEnable diagnostic settings for your subscription in order to capture more detailed activity logs and retain them beyond the default 90 day period. Ensure all categories “Administrative”, 'Alert', 'Policy' and 'Security' are enabled for capture. \nIf storing logs in a Storage Account container, ensure the container is not publicly accessible. \nIf storing logs in a Storage Account container, Encrypt the container with a Customer Managed Key (CMK). \nEnable all Diagnostic Settings for Azure Key Vault. \nEnable HTTP Logs for Azure App Service. \nEnable Diagnostic Settings for all mission critical resources that support it. \nEnable audit Logging for MySQL Databases \nEnable logging for PostgreSQL Databases, including: “log_checkpoints”, “log_connections”, “log_disconnections”, “connection_throttling” and “log_retention_days”.\nConsider implementing diagnostic Settings for all appropriate resources in your environment. Given that the mean time to detection in an enterprise is 240 days, a retention period of two years is recommended.  \nThe process of deploying Diagnostic Settings can be difficult to manage when you have many resources. ARM Templates can be used but to simplify the process of creating and applying diagnostic settings at scale, use Azure Policy to automatically generate diagnostic settings for both new and existing resources. At an additional cost you can choose to route the diagnostics to a Log Analytics Workspace so that they can be used in Azure Monitor or Azure Sentinel. Costs for monitoring will also vary with log volume. Not every resource needs to necessarily have logging enabled and not all events need to be logged. Consider compliance and governance requirements to determine the security classification of the data being processed by the given resource so you can adjust the level of logging accordingly. \nMore Information: \nhttps://learn.microsoft.com/en-us/azure/azure-monitor/essentials/platform-logs-overview \nhttps://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings-policy \nhttps://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/howto-access-activity-logs ",
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
                results["analysis"] = "the subscription does not have diagnostic settings configured for any resource"
            else:
                for diagnostic_setting in diagnostic_settings:
                    if diagnostic_setting.additional_properties["location"] == "global":
                        subscription_settings = True
                        for log in diagnostic_setting.logs:
                            if log.category == "Administrative":
                                if log.enabled != True:
                                    results["affected"].append(subscription)
                                    results["analysis"].append("the subscriptions diagnostic settings are not capturing Administrative activities")
                            if log.category == "Alert":
                                if log.enabled != True:
                                    results["affected"].append(subscription)
                                    results["analysis"].append("the subscriptions diagnostic settings are not capturing Alert activities")
                            if log.category == "Policy":
                                if log.enabled != True:
                                    results["affected"].append(subscription)
                                    results["analysis"].append("the subscriptions diagnostic settings are not capturing Policy activities")
                            if log.category == "Security":
                                if log.enabled != True:
                                    results["affected"].append(subscription)
                                    results["analysis"].append("the subscriptions diagnostic settings are not capturing Security activities")
                    else:
                        if "microsoft.web" in diagnostic_setting.id:
                            for log in diagnostic_setting.logs:
                                if log.category == "AppServiceHTTPLogs":
                                    if log.enabled != True:
                                        results["affected"].append(subscription)
                                        results["analysis"].append(f"the diagnostic setting {diagnostic_setting.id} is not capturing the AppServiceHTTPLogs category")
                        if "microsoft.keyvault" in diagnostic_setting.id:
                            for log in diagnostic_setting.logs:
                                if log.category == "AuditEvent":
                                    if log.enabled != True:
                                        results["affected"].append(subscription)
                                        results["analysis"].append(f"the diagnostic setting {diagnostic_setting.id} is not capturing the AuditEvent category")
                                if log.category == "AzurePolicyEvaluationDetails":
                                    if log.enabled != True:
                                        results["affected"].append(subscription)
                                        results["analysis"].append(f"the diagnostic setting {diagnostic_setting.id} is not capturing the AzurePolicyEvaluationDetails category")
                        if "blobservices" in diagnostic_setting.id or "tableservices" in diagnostic_setting.id:
                            for log in diagnostic_setting.logs:
                                if log.category == "StorageRead":
                                    if log.enabled != True:
                                        results["affected"].append(subscription)
                                        results["analysis"].append(f"the diagnostic setting {diagnostic_setting.id} is not capturing the StorageRead category")
                                if log.category == "StorageWrite":
                                    if log.enabled != True:
                                        results["affected"].append(subscription)
                                        results["analysis"].append(f"the diagnostic setting {diagnostic_setting.id} is not capturing the StorageWrite category")
                                if log.category == "StorageDelete":
                                    if log.enabled != True:
                                        results["affected"].append(subscription)
                                        results["analysis"].append(f"the diagnostic setting {diagnostic_setting.id} is not capturing the StorageDelete category")

                if not subscription_settings:
                        results["affected"].append(subscription)
                        results["analysis"].append("the subsciption does not have subscription level diagnostic settings configurd to increase the coverage of activity logs")


        for subscription, resource_groups in self.resources.items():
            client = MonitorManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:

                    if resource.type == "Microsoft.KeyVault/vaults" or resource.type == "Microsoft.Web/sites" or resource.type == "Microsoft.ContainerService/managedClusters":
                        try:
                            logging.info(f'getting diagnostic settings for { resource.name }')
                            if not [ setting for setting in client.diagnostic_settings.list(resource.id) ]:
                                results["affected"].append(subscription)
                                results["analysis"].append(f"the {resource.type} {resource.name} does not have diagnostic settings configured")
                        except Exception as e:
                            logging.error(f'error getting diagnostic settings for: { resource.name }, error: { e }')

                    if resource.type == "Microsoft.Storage/storageAccounts":
                        try:
                            logging.info(f'getting diagnostic settings for { resource.name }')
                            #if not [ i for i in client.diagnostic_settings.list(resource.id) ]:
                                #storage_accounts.append(resource.name)
                            if not [ i for i in client.diagnostic_settings.list(resource.id + "/blobServices/default") ]:
                                results["affected"].append(subscription)
                                results["analysis"].append(f"the {resource.type} {resource.name} does not have diagnostic settings configured for blob services")

                            if not [ i for i in client.diagnostic_settings.list(resource.id + "/queueServices/default") ]:
                                results["affected"].append(subscription)
                                results["analysis"].append(f"the {resource.type} {resource.name} does not have diagnostic settings configured queue services")

                            if not [ i for i in client.diagnostic_settings.list(resource.id + "/tableServices/default") ]:
                                results["affected"].append(subscription)
                                results["analysis"].append(f"the {resource.type} {resource.name} does not have diagnostic settings configured table services")

                            if not [ i for i in client.diagnostic_settings.list(resource.id + "/fileServices/default") ]:
                                results["affected"].append(subscription)
                                results["analysis"].append(f"the {resource.type} {resource.name} does not have diagnostic settings configured file services")

                        except exceptions.HttpResponseError as e:
                            if "ResourceTypeNotSupported" in e.message:
                                pass
                            else:
                                logging.error(f'error getting diagnostic settings for: { resource.name }, error: { e }')
                        except Exception as e:
                            logging.error(f'error getting diagnostic settings for: { resource.name }, error: { e }')

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["affected"] = list(set(results["affected"]))
        else:
            results["analysis"] = "no issues found"

        return results

    def monitor_2(self):
        # Activity Log Alerts(CIS)

        results = {
            "id" : "monitor_2",
            "ref" : "5.2",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "monitor",
            "name" : "Activity Log Alerts (CIS)",
            "affected": [],
            "analysis" : [], 
            "description" : "The account under review does not have Activity Log alerts configured. Activity logs provide auditing of all actions that occurred on resources. Use activity log alerts to be alerted when a specific event happens to a resource like a restart, a shutdown, or the creation or deletion of a resource. Service Health alerts and Resource Health alerts let you know when there's an issue with one of your services or resources.\nThe recommendations provided in this finding are intended to provide entry-level alerting for crucial activities on a tenant account. These recommended activities should be tuned to your needs. By default, each of these Activity Log Alerts tends to guide the reader to alerting at the 'Subscription-wide' level which will capture and alert on rules triggered by all resources and resource groups contained within a subscription. This is not an ideal rule set for Alerting within larger and more complex organizations.  \nWhile this finding provides recommendations for the creation of Activity Log Alerts specifically, Microsoft Azure supports four different types of alerts: \nMetric Alerts - Metric data is stored in the system already pre-computed. Metric alerts are useful when you want to be alerted about data that requires little or no manipulation. Use metric alerts if the data you want to monitor is available in metric data. \nLog Alerts - You can use log alerts to perform advanced logic operations on your data. If the data you want to monitor is available in logs, or requires advanced logic, you can use the robust features of Kusto Query Language (KQL) for data manipulation by using log alerts. \nActivity Log Alerts - Activity logs provide auditing of all actions that occurred on resources. Use activity log alerts to be alerted when a specific event happens to a resource like a restart, a shutdown, or the creation or deletion of a resource. Service Health alerts and Resource Health alerts let you know when there's an issue with one of your services or resources. \nSmart Detection Alerts - Smart detection on an Application Insights resource automatically warns you of potential performance problems and failure anomalies in your web application. You can migrate smart detection on your Application Insights resource to create alert rules for the different smart detection modules. ",
            "remediation" : "CIS recommend to configure activity log alert rules: \nCreate Policy Assignment \nDelete Policy Assignment \nCreate or Update Network Security Group \nDelete Network Security Group \nCreate or Update Security Solution \nDelete Security Solution \nCreate or Update SQL Server Firewall Rule \nDelete SQL Server Firewall Rule \nCreate or Update Public IP Address Rule \nDelete Public Ip Address Rule \nClaranet Cyber Security recommend the following additional rules: \nCreate or Update Load Balancer \nCreate or Update Virtual Machine \nCreate/Update Azure SQL Database \nCreate/Update Storage Account \nDeallocate Virtual Machine \nDelete Azure SQL Database \nDelete Key Vault \nDelete Load Balancer \nDelete Network Security Group Rule \nDelete Storage Account \nDelete Virtual Machine \nPower Off Virtual Machine \nRename Azure SQL Database \nUpdate Key Vault \nUpdate Security Policy \nCreate/Update MySQL Database \nCreate/Update Network Security Group Rule \nCreate/Update PostgreSQL Database \nDelete MySQL Database \nDelete PostgreSQL Database \nTo Configure an example alert, from Azure Portal  \nNavigate to the Monitor blade.  \nSelect Alerts.  \nSelect Create.  \nSelect Alert rule.  \nUnder Filter by subscription, choose a subscription.  \nUnder Filter by resource type, select relevant resource type \nUnder Filter by location, select All.  \nFrom the results, select the subscription.  \nSelect Done.  \nSelect the Condition tab.  \nUnder Signal name, click Create policy assignment (Microsoft.Authorization/policyAssignments).  \nSelect the Actions tab.  \nTo use an existing action group, click elect action groups. To create a new action group, click Create action group. Fill out the appropriate details for the selection.  \nSelect the Details tab.  \nSelect a Resource group, provide an Alert rule name and an optional Alert rule description.  \nClick Review +  \nMore Information: \nhttps://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-types ",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        rules = {
            "policy_assignments_write" : False,
            "policy_assignments_delete" : False,
            "network_security_group_write" : False,
            "network_security_group_delete" : False,
            "security_solutions_write" : False,
            "security_solutions_delete" : False,
            "sql_servers_firewall_rules_write" : False,
            "sql_servers_firewall_rules_delete" : False,
            "public_ip_addresses_write" : False,
            "public_ip_addresses_delete" : False
        }

        for subscription, activity_log_alerts in self.activity_log_alerts.items():
            for alert in activity_log_alerts:
                for condition in alert.condition.all_of:
                    if condition.equals == "Operationname=Microsoft.Authorization/policyAssignments/write":
                        rules["network_security_group_write"] = True
                    if condition.equals == "Operationname=Microsoft.Authorization/policyAssignments/delete":
                        rules["network_security_group_write"] = True
                    if condition.equals == "Microsoft.Network/networkSecurityGroups/write":
                        rules["network_security_group_write"] = True
                    if condition.equals == "Microsoft.Network/networkSecurityGroups/delete":
                        rules["network_security_group_delete"] = True
                    if condition.equals == "Operationname=Microsoft.Security/securitySolutions/write":
                        rules["network_security_group_delete"] = True
                    if condition.equals == "Operationname=Microsoft.Security/securitySolutions/delete":
                        rules["network_security_group_delete"] = True
                    if condition.equals == "Operationname=Microsoft.Sql/servers/firewallRules/write":
                        rules["network_security_group_delete"] = True
                    if condition.equals == "Operationname=Microsoft.Sql/servers/firewallRules/delete":
                        rules["network_security_group_delete"] = True
                    if condition.equals == "Operationname=Microsoft.Network/publicIPAddresses/write":
                        rules["network_security_group_delete"] = True
                    if condition.equals == "Operationname=Microsoft.Network/publicIPAddresses/delete":
                        rules["network_security_group_delete"] = True

            for rule, status in rules.items():
                if status == False:
                    results["analysis"].append(f"no activity log alert rules found for { rule }")
                    results["affected"].append(subscription)

                #Operationname=Microsoft.Authorization/policyAssignments/write
                #Operationname=Microsoft.Authorization/policyAssignments/delete
                #Operationname=Microsoft.Network/networkSecurityGroups/write
                #Operationname=Microsoft.Network/networkSecurityGroups/delete
                #Operationname=Microsoft.Security/securitySolutions/write
                #Operationname=Microsoft.Security/securitySolutions/delete
                #Operationname=Microsoft.Sql/servers/firewallRules/write
                #Operationname=Microsoft.Sql/servers/firewallRules/delete
                #Operationname=Microsoft.Network/publicIPAddresses/write
                #Operationname=Microsoft.Network/publicIPAddresses/delete

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["affected"] = list(set(results["affected"]))
        else:
            results["analysis"] = "no issues found"

        return results
