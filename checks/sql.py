from azure.mgmt.sql import SqlManagementClient
from checks.resource import resource
import logging
from azure.mgmt.sql.models import ServerBlobAuditingPolicy

class sql(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.resource_groups = resource_groups
        self.resources = resources
        self.servers = self.get_servers()
        self.databases = self.get_databases()
        self.server_audit_policies = self.get_server_audit_policies()
        self.firewall_rules = self.get_firewall_rules()
        self.transparant_data_encryption = self.get_transparant_data_encryption()

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

    def get_server_audit_policies(self):
        audit_policies = {}
        for subscription, resource_groups in self.resources.items():
            results = {}
            client = SqlManagementClient(credential=self.credential, subscription_id=subscription)
            #operations = client.operations.list()
            #for i in operations:
                #print(i.name)
            for resource_group, resources in resource_groups.items():
                audit_policies_server = []
                for resource in resources:
                    if resource.type == "Microsoft.Sql/servers":
                        logging.info(f'getting sql server { resource.name }')
                        try:
                            audit_policies_server.append(client.server_blob_auditing_policies.get(server_name=resource.name, resource_group_name=resource_group))
                        except Exception as e:
                            logging.error(f'error getting sql server audit policies: { resource.name }, error: { e }')
                        else:
                            if audit_policies_server:
                                results[resource.name] = audit_policies_server
            if results:
                audit_policies[subscription] = results
        return audit_policies

    def get_firewall_rules(self):
        firewall_rules = {}
        for subscription, resource_groups in self.resources.items():
            results = {}
            client = SqlManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                firewall_rules_server = []
                for resource in resources:
                    if resource.type == "Microsoft.Sql/servers":
                        logging.info(f'getting sql server { resource.name }')
                        try:
                            firewall_rules_server.append(client.firewall_rules.list_by_server(server_name=resource.name, resource_group_name=resource_group))
                        except Exception as e:
                            logging.error(f'error getting sql server: { resource.name }, error: { e }')
                        else:
                            if firewall_rules_server:
                                results[resource.name] = firewall_rules_server
            if results:
                firewall_rules[subscription] = results
        return firewall_rules

    def get_transparant_data_encryption(self):
        transparant_data_encryption = {}
        for subscription, resource_groups in self.servers.items():
            results = {}
            client = SqlManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, servers in resource_groups.items():
                for server in servers:
                    transparant_data_encryption[server.name] = {}
                    logging.info(f'getting sql databases for server: { server.name }')
                    try:
                        database_list = list(client.databases.list_by_server(server_name=server.name, resource_group_name=resource_group))
                    except Exception as e:
                        logging.error(f'error getting sql databases for server: { server.name }, error: { e }')
                    else:
                        for database in database_list:
                            if database.name != "master":
                                transparant_data_encryption[server.name][database.name] = []
                                try:
                                    transparant_data_encryption[server.name][database.name].append(client.transparent_data_encryptions.get(server_name=server.name, resource_group_name=resource_group, database_name=database.name, transparent_data_encryption_name="current"))
                                except Exception as e:
                                    logging.error(f'error getting sql database: { database.name }, error: { e }')

        return transparant_data_encryption

    def run(self):
        findings = []
        findings += [ self.sql_1() ]
        findings += [ self.sql_2() ]
        findings += [ self.sql_3() ]
        findings += [ self.sql_4() ]
        findings += [ self.sql_5() ]
        findings += [ self.sql_6() ]
        findings += [ self.sql_7() ]
        return findings

    def sql_1(self):
        # Ensure that 'Auditing' is set to 'On' (CIS)

        results = {
            "id" : "sql_1",
            "ref" : "4.1.1",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "sql",
            "name" : "Ensure that 'Auditing' is set to 'On' (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "The Azure platform allows a SQL server to be created as a service. Enabling auditing at the server level ensures that all existing and newly created databases on the SQL server instance are audited. Auditing policy applied on the SQL database does not override auditing policy and settings applied on the particular SQL server where the database is hosted.\nAuditing tracks database events and writes them to an audit log in the Azure storage account. It also helps to maintain regulatory compliance, understand database activity, and gain insight into discrepancies and anomalies that could indicate business concerns or suspected security violations",
            "remediation" : "From Azure Portal\n1. Go to SQL servers\n2. Select the SQL server instance\n\n3. Under Security, click Auditing\n4. Click the toggle next to Enable Azure SQL Auditing\n5. Select an Audit log destination\n6. Click Save",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, servers in self.server_audit_policies.items():
            for server, audit_policies in servers.items():
                for policy in audit_policies:
                    if policy.state == "Disabled":
                        results["affected"].append(server)

        if results["affected"]:
            results["analysis"] = "The affected SQL Server do no have audting enabled"
            results["pass_fail"] = "FAIL"
        elif self.servers:
            results["analysis"] = "SQL Servers have audit policies enabled"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no sql servers found"

        return results

    def sql_2(self):
        # Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP) (CIS)

        results = {
            "id" : "sql_2",
            "ref" : "4.1.2",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "sql",
            "name" : "Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP) (CIS)",
            "affected": [],
            "analysis" : [],
            "description" : "Ensure that no SQL Databases allow ingress from 0.0.0.0/0 (ANY IP). Azure SQL Server includes a firewall to block access to unauthorized connections. More granular IP addresses can be defined by referencing the range of addresses available from specific datacenters. By default, for a SQL server, a Firewall exists with StartIp of 0.0.0.0 and EndIP of 0.0.0.0 allowing access to all the Azure services. Additionally, a custom rule can be set up with StartIp of 0.0.0.0 and EndIP of 255.255.255.255 allowing access from ANY IP over the Internet. In order to reduce the potential attack surface for a SQL server, firewall rules should be defined with more granular IP addresses by referencing the range of addresses available from specific datacenters. \nDisabling Allow Azure services and resources to access this server will break all connections to SQL server and Hosted Databases unless custom IP specific rules are added in Firewall Policy.",
            "remediation" : "From Azure Portal\n1. Go to SQL servers\n2. For each SQL server\n3. Click on Networking\n4. Uncheck the checkbox for Allow Azure services and resources to access this server\n5. Set firewall rules to limit access to only authorized connections",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, servers in self.firewall_rules.items():
            for server, firewall_rules in servers.items():
                for rules in firewall_rules:
                    for rule in rules:
                        if rule.name == "AllowAllWindowsAzureIps":
                            results["affected"].append(server)
                            results["analysis"] = f"SQL Server { server } allows Azure services and resources access"
                        elif rule.start_ip_address == "0.0.0.0":
                            if rule.end_ip_address == "0.0.0.0":
                                results["affected"].append(server)
                                results["analysis"] = f"SQL Server { server } allows access from 0.0.0.0/0"

        if results["affected"]:
            results["pass_fail"] = "FAIL"
        elif self.servers:
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no sql servers found"

        return results

    def sql_3(self):
        # Ensure SQL server's Transparent Data Encryption (TDE) protector is encrypted with Customer-managed key (CIS)

        results = {
            "id" : "sql_3",
            "ref" : "4.1.3",
            "compliance" : "cis_v2.1.0",
            "level" : 2,
            "service" : "sql",
            "name" : "Ensure SQL server's Transparent Data Encryption (TDE) protector is encrypted with Customer-managed key (CIS)",
            "affected": [],
            "analysis" : [],
            "description" : "Transparent Data Encryption (TDE) with Customer-managed key support provides increased transparency and control over the TDE Protector, increased security with an HSM-backed external service, and promotion of separation of duties. With TDE, data is encrypted at rest with a symmetric key (called the database encryption key) stored in the database or data warehouse distribution. To protect this data encryption key (DEK) in the past, only a certificate that the Azure SQL Service managed could be used. Now, with Customer-managed key support for TDE, the DEK can be protected with an asymmetric key that is stored in the Azure Key Vault. The Azure Key Vault is a highly available and scalable cloud-based key store which offers central key management, leverages FIPS 140-2 Level 2 validated hardware security modules (HSMs), and allows separation of management of keys and data for additional security. Based on business needs or criticality of data/databases hosted on a SQL server, it is recommended that the TDE protector is encrypted by a key that is managed by the data owner (Customer-managed key). \nCustomer-managed key support for Transparent Data Encryption (TDE) allows user control of TDE encryption keys and restricts who can access them and when. Azure Key Vault, Azure’s cloud-based external key management system, is the first key management service where TDE has integrated support for Customer-managed keys. With Customer-managed key support, the database encryption key is protected by an asymmetric key stored in the Key Vault. The asymmetric key is set at the server level and inherited by all databases under that server. \nOnce TDE protector is encrypted with a Customer-managed key, it transfers entire responsibility of respective key management on to you, and hence you should be more careful about doing any operations on the particular key in order to keep data from corresponding SQL server and Databases hosted accessible. When deploying Customer Managed Keys, it is prudent to ensure that you also deploy an automated toolset for managing these keys (this should include discovery and key rotation), and Keys should be stored in an HSM or hardware backed keystore, such as Azure Key Vault. As far as toolsets go, check with your cryptographic key provider, as they may well provide one as an add-on to their service.",
            "remediation" : "From Azure Console\n1. Go to SQL servers For the desired server instance\n2. Click On Transparent data encryption\n3. Set Transparent data encryption to Customer-managed key\n4. Browse through your key vaults to Select an existing key or create a new key in the Azure Key Vault.\n5. Check Make selected key the default TDE protector",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for server, databases in self.transparant_data_encryption.items():
            for database, transparant_data_encryption in databases.items():
                for encryption in transparant_data_encryption:
                    if encryption.status == "Disabled":
                        results["affected"].append(database)
                        results["analysis"].append(f"SQL Server Database { database } does not have encryption enabled")

        if results["affected"]:
            results["pass_fail"] = "FAIL"
        elif self.servers:
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no sql servers found"

        return results

    def sql_4(self):
        # Ensure that Microsoft Entra authentication is Configured for SQL Servers (CIS)

        results = {
            "id" : "sql_4",
            "ref" : "4.1.4",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "sql",
            "name" : "Ensure that Microsoft Entra authentication is Configured for SQL Servers (CIS)",
            "affected": [],
            "analysis" : [],
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
                        results["analysis"].append(f"the sql server { server.name } is not using Entra authentication")
                    elif server.administrators.azure_ad_only_authentication != True:
                        results["affected"].append(server.name)
                        results["analysis"].append(f"the sql server { server.name } is using Entra authentication, but does not enforce its use.")

        if results["affected"]:
            results["pass_fail"] = "FAIL"
        elif self.servers:
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no sql servers found"

        return results

    def sql_5(self):
        # Ensure the Minimum TLS version for SQL Servers is set to Version 1.2

        results = {
            "id" : "sql_5",
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

    def sql_6(self):
        # Ensure that 'Public Network Access' is `Disabled' for sql servers

        results = {
            "id" : "sql_6",
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

