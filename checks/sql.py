from azure.mgmt.sql import SqlManagementClient
from checks.resource import resource
import logging

class sql(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.resource_groups = resource_groups
        self.resources = resources
        self.servers = self.get_servers()
        self.databases = self.get_databases()

    def get_servers(self):
        servers = {}
        for subscription, resource_groups in self.resources.items():
            results = {}
            client = SqlManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                servers_in_group = []
                for resource in resources:
                    if resource.type == "Microsoft.Sql/servers":
                        logging.info(f'getting sql server { resource.name }')
                        try:
                            servers_in_group.append(client.servers.get(server_name=resource.name, resource_group_name=resource_group))
                        except Exception as e:
                            logging.error(f'error getting sql server: { resource.name }, error: { e }')

                if servers_in_group:
                    results[resource_group] = servers_in_group
            if results:
                servers[subscription] = results
        return servers

    def get_databases(self):
        databases = {}
        for subscription, resource_groups in self.servers.items():
            results = {}
            client = SqlManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, servers in resource_groups.items():
                for server in servers:
                    databases_on_server = []
                    logging.info(f'getting sql databases for server: { server.name }')
                    try:
                        database_list = list(client.databases.list_by_server(server_name=server.name, resource_group_name=resource_group))
                    except Exception as e:
                        logging.error(f'error getting sql databases for server: { server.name }, error: { e }')
                    else:
                        for database in database_list:
                            try:
                                databases_on_server.append(client.databases.get(database_name=database.name, server_name=server.name, resource_group_name=resource_group))
                            except Exception as e:
                                logging.error(f'error getting sql database: { database.name }, error: { e }')

                        if databases_on_server:
                            results[server.name] = databases_on_server
            if results:
                databases[subscription] = results
        return databases

    def run(self):
        findings = []
        findings += [ self.sql_1() ]
        findings += [ self.sql_2() ]
        findings += [ self.sql_3() ]
        findings += [ self.sql_4() ]
        findings += [ self.sql_5() ]
        findings += [ self.sql_6() ]
        findings += [ self.sql_7() ]
        findings += [ self.sql_8() ]
        return findings

    def sql_1(self):
        # 

        results = {
            "id" : "sql_1",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "sql",
            "name" : "Azure SQL Servers",
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

        results["analysis"] = self.servers

        if results["analysis"]:
            results["affected"] = [ i for i, v in results["analysis"].items() ]
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "no sql servers found"

        return results

    def sql_2(self):
        # 

        results = {
            "id" : "sql_2",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "sql",
            "name" : "Azure SQL Databases",
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

        results["analysis"] = self.databases

        if results["analysis"]:
            results["affected"] = [ i for i, v in results["analysis"].items() ]
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "no sql databases found"

        return results

    def sql_3(self):
        # Ensure the Minimum TLS version for SQL Servers is set to Version 1.2

        results = {
            "id" : "sql_3",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "sql",
            "name" : "Ensure the Minimum TLS version for SQL Servers is set to Version 1.2",
            "affected": [],
            "analysis" : "",
            "description" : "TLS 1.0 is a legacy version and has known vulnerabilities. This minimum TLS\nversion can be configured to be later protocols such as TLS 1.2.\nRationale:\nTLS 1.0 has known vulnerabilities and has been replaced by later versions of the TLS\nprotocol. Continued use of this legacy protocol affects the security of data in transit.\nImpact:\nWhen set to TLS 1.2 all requests must leverage this version of the protocol. Applications\nleveraging legacy versions of the protocol will fail.",
            "remediation" : "Ensure SQL servers are using a minimum TLS version of 1.2",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "5.4",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, resource_groups in self.servers.items():
            for resource_group, servers in resource_groups.items():
                for server in servers:
                    if server.minimal_tls_version != "1.2":
                        results["affected"].append(server.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
        elif self.servers:
            results["analysis"] = "sql databases are using the latest tls version"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no sql servers found"

        return results

    def sql_4(self):
        # Ensure that 'Public Network Access' is `Disabled' for sql servers

        results = {
            "id" : "sql_4",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "sql",
            "name" : "Ensure that 'Public Network Access' is `Disabled' for sql servers",
            "affected": [],
            "analysis" : "",
            "description" : "Disallowing public network access for a storage account overrides the public access\nsettings for individual containers in that storage account for Azure Resource Manager\nDeployment Model storage accounts. Azure Storage accounts that use the classic\ndeployment model will be retired on August 31, 2024.\nRationale:\nThe default network configuration for a storage account permits a user with appropriate\npermissions to configure public network access to containers and blobs in a storage\naccount. Keep in mind that public access to a container is always turned off by default\nand must be explicitly configured to permit anonymous requests. It grants read-only\naccess to these resources without sharing the account key, and without requiring a\nshared access signature. It is recommended not to provide public network access to\nstorage accounts until, and unless, it is strongly desired. A shared access signature\ntoken or Azure AD RBAC should be used for providing controlled and timed access to\nblob containers.",
            "remediation" : "Ensure public network access is disabled",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, resource_groups in self.servers.items():
            for resource_group, servers in resource_groups.items():
                for server in servers:
                    if server.public_network_access != "Disabled":
                        results["affected"].append(server.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected sql servers are not using the latest tls version"
        elif self.servers:
            results["analysis"] = "sql servers are using the latest tls version"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no sql servers found"

        return results

    def sql_5(self):
        # Ensure that Microsoft Entra authentication is Configured for SQL Servers (CIS)

        results = {
            "id" : "sql_5",
            "ref" : "4.1.4",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "sql",
            "name" : "Ensure that Microsoft Entra authentication is Configured for SQL Servers (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Use Microsoft Entra authentication for authentication with SQL Database to manage\ncredentials in a single place.\nRationale:\nMicrosoft Entra authentication is a mechanism to connect to Microsoft Azure SQL\nDatabase and SQL Data Warehouse by using identities in the Microsoft Entra ID\ndirectory. With Entra ID authentication, identities of database users and other Microsoft\nservices can be managed in one central location. Central ID management provides a\nsingle place to manage database users and simplifies permission management.\n• It provides an alternative to SQL Server authentication.\n• Helps stop the proliferation of user identities across database servers.\n• Allows password rotation in a single place.\n• Customers can manage database permissions using external (Entra ID) groups.\n• It can eliminate storing passwords by enabling integrated Windows\nauthentication and other forms of authentication supported by Microsoft Entra.\n• Entra ID authentication uses contained database users to authenticate identities\nat the database level.\n• Entra ID supports token-based authentication for applications connecting to SQL\nDatabase.\n• Entra ID authentication supports ADFS (domain federation) or native\nuser/password authentication for a local Active Directory without domain\nsynchronization.\n• Entra ID supports connections from SQL Server Management Studio that use\nActive Directory Universal Authentication, which includes Multi-Factor\nAuthentication (MFA). MFA includes strong authentication with a range of easy\nverification options — phone call, text message, smart cards with pin, or mobile\napp notification.\nImpact:\nThis will create administrative overhead with user account and permission\nmanagement. For further security on these administrative accounts, you may want to\nconsider licensing which supports features like Multi Factor Authentication.",
            "remediation" : "From Azure Portal\n1. Go to SQL servers\n2. For each SQL server, click on Microsoft Entra admin\n3. Click on Set admin\n4. Select an admin\n5. Click Save",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, resource_groups in self.servers.items():
            for resource_group, servers in resource_groups.items():
                for server in servers:
                    if not server.administrators:
                        results["affected"].append(server.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected sql servers are not using Entra authentication"
        elif self.servers:
            results["analysis"] = "sql servers are using the Entra ID authentication"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no sql servers found"

        return results

    def sql_6(self):
        # Ensure that Microsoft Entra authentication is enforced for SQL Servers (CIS)

        results = {
            "id" : "sql_6",
            "ref" : "4.1.4",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "sql",
            "name" : "Ensure that Microsoft Entra authentication is enforced for SQL Servers",
            "affected": [],
            "analysis" : "",
            "description" : "Use Microsoft Entra authentication for authentication with SQL Database to manage\ncredentials in a single place.\nRationale:\nMicrosoft Entra authentication is a mechanism to connect to Microsoft Azure SQL\nDatabase and SQL Data Warehouse by using identities in the Microsoft Entra ID\ndirectory. With Entra ID authentication, identities of database users and other Microsoft\nservices can be managed in one central location. Central ID management provides a\nsingle place to manage database users and simplifies permission management.\n• It provides an alternative to SQL Server authentication.\n• Helps stop the proliferation of user identities across database servers.\n• Allows password rotation in a single place.\n• Customers can manage database permissions using external (Entra ID) groups.\n• It can eliminate storing passwords by enabling integrated Windows\nauthentication and other forms of authentication supported by Microsoft Entra.\n• Entra ID authentication uses contained database users to authenticate identities\nat the database level.\n• Entra ID supports token-based authentication for applications connecting to SQL\nDatabase.\n• Entra ID authentication supports ADFS (domain federation) or native\nuser/password authentication for a local Active Directory without domain\nsynchronization.\n• Entra ID supports connections from SQL Server Management Studio that use\nActive Directory Universal Authentication, which includes Multi-Factor\nAuthentication (MFA). MFA includes strong authentication with a range of easy\nverification options — phone call, text message, smart cards with pin, or mobile\napp notification.\nImpact:\nThis will create administrative overhead with user account and permission\nmanagement. For further security on these administrative accounts, you may want to\nconsider licensing which supports features like Multi Factor Authentication.",
            "remediation" : "From Azure Portal\n1. Go to SQL servers\n2. For each SQL server, click on Microsoft Entra admin\n3. Click on Set admin\n4. Select an admin\n5. Click Save",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, resource_groups in self.servers.items():
            for resource_group, servers in resource_groups.items():
                for server in servers:
                    if not server.administrators:
                        results["affected"].append(server.name)
                    elif server.administrators.azure_ad_only_authentication != True:
                        results["affected"].append(server.name)


        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected sql servers do not enforce using only Entra ID authentication"
        elif self.servers:
            results["analysis"] = "sql servers are enforcing the use of Entra ID authentication"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no sql servers found"

        return results

    def sql_7(self):
        # SQL Servers with Managed Identities Attached

        results = {
            "id" : "sql_7",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "sql",
            "name" : "SQL Servers with Managed Identity Attached",
            "affected": [],
            "analysis" : "",
            "description" : "Sql servers are using managed identities to access Azure resources. Review the RBAC roles, MS graph permissions and Azure AD roles assigned to the identity to ensure the principal of least privilege is being followed.",
            "remediation" : "ensure managed identities are only assigned to resources that required access to other Azure resources, and ensure privileges are granted following the principal of least privilege.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, resource_groups in self.servers.items():
            for resource_group, servers in resource_groups.items():
                for server in servers:
                    if server.identity:
                        results["affected"].append(server.name)
                    elif server.primary_user_assigned_identity_id:
                        results["affected"].append(server.name)
                    elif server.federated_client_id:
                        results["affected"].append(server.name)


        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected sql servers have a system or user assigned managed identity attached"
        elif self.servers:
            results["analysis"] = "sql servers do not have managed identities attached"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no sql servers found"

        return results

    def sql_8(self):
        # 

        results = {
            "id" : "sql_8",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "sql",
            "name" : "",
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

        for subscription, resource_groups in self.servers.items():
            for resource_group, servers in resource_groups.items():
                for server in servers:
                    print(server)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected sql servers have a system or user assigned managed identity attached"
        elif self.servers:
            results["analysis"] = "sql servers do not have managed identities attached"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no sql servers found"

        return results
