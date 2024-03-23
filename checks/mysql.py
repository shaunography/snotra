import azure.mgmt.rdbms.mysql as Mysql
import azure.mgmt.rdbms.mysql_flexibleservers as Mysql_flexible

import azure.core.exceptions as exceptions

import logging

class mysql(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.resource_groups = resource_groups
        self.resources = resources
        self.servers = self.get_servers()
        self.configurations = self.get_configurations()
        self.flexible_servers = self.get_flexible_servers()
        #self.databases = self.get_databases()
        #self.flexible_databases = self.get_flexible_databases()

    def get_servers(self):
        servers = {}
        for subscription, resource_groups in self.resources.items():
            results = {}
            client = Mysql.MySQLManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                servers_in_group = []
                for resource in resources:
                    if resource.type == "Microsoft.DBforMySQL/servers":
                        logging.info(f'getting mysql server { resource.name }')
                        try:
                            servers_in_group.append(client.servers.get(server_name=resource.name, resource_group_name=resource_group))
                        except Exception as e:
                            logging.error(f'error getting mysql server: { resource.name }, error: { e }')
                if servers_in_group:
                    results[resource_group] = servers_in_group
            if results:
                servers[subscription] = results
        return servers

    def get_configurations(self):
        configurations = {}
        for subscription, resource_groups in self.servers.items():
            results = {}
            client = Mysql.MySQLManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, servers in resource_groups.items():
                for server in servers:
                    configurations_on_server = []
                    logging.info(f'getting mysql configurations for server: { server.name }')
                    try:
                        configuration_list = list(client.configurations.list_by_server(server_name=server.name, resource_group_name=resource_group))
                    except Exception as e:
                        logging.error(f'error getting mysql configurations for server: { server.name }, error: { e }')
                    else:
                        for configuration in configuration_list:
                            try:
                                configurations_on_server.append(client.configurations.get(configuration_name=configuration.name, server_name=server.name, resource_group_name=resource_group))
                            except Exception as e:
                                logging.error(f'error getting mysql configuration: { configuration.name }, error: { e }')
                        if configurations_on_server:
                            results[server.name] = configurations_on_server
            if results:
                configurations[subscription] = results
        return configurations

    def get_flexible_servers(self):
        servers = {}
        for subscription, resource_groups in self.resources.items():
            results = {}
            client = Mysql_flexible.MySQLManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                servers_in_group = []
                for resource in resources:
                    if resource.type == "Microsoft.DBforMySQL/flexibleServers":
                        logging.info(f'getting mysql flexible server { resource.name }')
                        try:
                            servers_in_group.append(client.servers.get(server_name=resource.name, resource_group_name=resource_group))
                        except Exception as e:
                            logging.error(f'error getting mysql flexible server: { resource.name }, error: { e }')
                if servers_in_group:
                    results[resource_group] = servers_in_group
            if results:
                servers[subscription] = results
        return servers

    def get_databases(self):
        databases = {}
        for subscription, resource_groups in self.servers.items():
            results = {}
            client = Mysql.MySQLManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, servers in resource_groups.items():
                for server in servers:
                    databases_on_server = []
                    logging.info(f'getting mysql databases for server: { server.name }')
                    try:
                        database_list = list(client.databases.list_by_server(server_name=server.name, resource_group_name=resource_group))
                    except Exception as e:
                        logging.error(f'error getting mysql databases for server: { server.name }, error: { e }')
                    else:
                        for database in database_list:
                            try:
                                databases_on_server.append(client.databases.get(database_name=database.name, server_name=server.name, resource_group_name=resource_group))
                            except Exception as e:
                                logging.error(f'error getting mysql database: { database.name }, error: { e }')

                        if databases_on_server:
                            results[server.name] = databases_on_server
            if results:
                databases[subscription] = results
        return databases

    def get_flexible_databases(self):
        databases = {}
        for subscription, resource_groups in self.flexible_servers.items():
            results = {}
            client = Mysql_flexible.MySQLManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, servers in resource_groups.items():
                for server in servers:
                    databases_on_server = []
                    logging.info(f'getting mysql databases for flexible server: { server.name }')
                    try:
                        database_list = list(client.databases.list_by_server(server_name=server.name, resource_group_name=resource_group))
                    except Exception as e:
                        logging.error(f'error getting mysql databases for flexible server: { server.name }, error: { e }')
                    else:
                        for database in database_list:
                            try:
                                databases_on_server.append(client.databases.get(database_name=database.name, server_name=server.name, resource_group_name=resource_group))
                            except Exception as e:
                                logging.error(f'error getting mysql database: { database.name }, error: { e }')

                        if databases_on_server:
                            results[server.name] = databases_on_server
            if results:
                databases[subscription] = results
        return databases

    def run(self):
        findings = []
        findings += [ self.mysql_1() ]
        findings += [ self.mysql_2() ]
        findings += [ self.mysql_3() ]
        findings += [ self.mysql_4() ]
        findings += [ self.mysql_5() ]
        return findings

    def mysql_1(self):
        # Ensure 'Enforce SSL connection' is set to 'Enabled' for Standard MySQL Database Server (CIS)

        results = {
            "id" : "mysql_1",
            "ref" : "4.4.1",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "mysql",
            "name" : "Ensure 'Enforce SSL connection' is set to 'Enabled' for Standard MySQL Database Server (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Enable SSL connection on MYSQL Servers. SSL connectivity helps to provide a new layer of security by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.",
            "remediation" : "From Azure Portal\n1. Login to Azure Portal using https://portal.azure.com\n2. Go to Azure Database for MySQL servers\n3. For each database, click on Connection security\n4. In SSL settings, click on ENABLED to Enforce SSL connections",
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
                    if server.ssl_enforcement != "Enabled":
                        results["affected"].append(server.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected Mysql servers do enforce the use of SSL."
        elif self.servers:
            results["analysis"] = "Mysql servers are enforcing SSL connections"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no Mysql servers found"

        return results

    def mysql_2(self):
        # Ensure 'TLS Version' is set to 'TLSV1.2' (or higher) for MySQL flexible Database Server (CIS)

        results = {
            "id" : "mysql_2",
            "ref" : "4.4.2",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "mysql",
            "name" : "Ensure 'TLS Version' is set to 'TLSV1.2' (or higher) for MySQL flexible Database Server (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Ensure TLS version on MySQL flexible servers is set to use TLS version 1.2 or higher. TLS connectivity helps to provide a new layer of security by connecting database server to client applications using Transport Layer Security (TLS). Enforcing TLS connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.",
            "remediation" : "From Azure Portal\n1. Login to Azure Portal using https://portal.azure.com\n2. Go to Azure Database for MySQL flexible servers\n3. For each database, click on Server parameters under Settings\n4. In the search box, type in tls_version\n5. Click on the VALUE dropdown, and ensure only TLSV1.2 (or higher) is selected\nfor tls_version",
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
                    if server.minimal_tls_version != "TLS1_2":
                        results["affected"].append(server.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected Mysql servers do enforce the use of SSL."
        elif self.servers:
            results["analysis"] = "Mysql servers are enforcing SSL connections"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no Mysql servers found"

        return results

    def mysql_3(self):
        # Ensure that 'Public Network Access' is `Disabled' for MySQL servers

        results = {
            "id" : "mysql_3",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "mysql",
            "name" : "Ensure that 'Public Network Access' is `Disabled' for MySQL servers",
            "affected": [],
            "analysis" : "",
            "description" : "Disallowing public network access for a storage account overrides the public access\nsettings for individual containers in that storage account for Azure Resource Manager\nDeployment Model storage accounts. Azure Storage accounts that use the classic\ndeployment model will be retired on August 31, 2024.\nRationale:\nThe default network configuration for a storage account permits a user with appropriate\npermissions to configure public network access to containers and blobs in a storage\naccount. Keep in mind that public access to a container is always turned off by default\nand must be explicitly configured to permit anonymous requests. It grants read-only\naccess to these resources without sharing the account key, and without requiring a\nshared access signature. It is recommended not to provide public network access to\nstorage accounts until, and unless, it is strongly desired. A shared access signature\ntoken or Azure AD RBAC should be used for providing controlled and timed access to\nblob containers.",
            "remediation" : "Ensure public network access is disabled",
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
                    if server.public_network_access != "Disabled":
                        results["affected"].append(server.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected Mysql servers do enforce the use of SSL."
        elif self.servers:
            results["analysis"] = "Mysql servers are enforcing SSL connections"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no Mysql servers found"

        return results

    def mysql_4(self):
        # Ensure server parameter 'audit_log_enabled' is set to 'ON' for MySQL Database Server (CIS)

        results = {
            "id" : "mysql_4",
            "ref" : "4.4.3",
            "compliance" : "cis_v2.1.0",
            "level" : "N/A",
            "service" : "mysql",
            "name" : "Ensure server parameter 'audit_log_enabled' is set to 'ON' for MySQL Database Server (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Enable audit_log_enabled on MySQL Servers. Enabling audit_log_enabled helps MySQL Database to log items such as connection attempts to the server, DDL/DML access, and more. Log data can be used to identify, troubleshoot, and repair configuration errors and suboptimal performance. \nThere are further costs incurred for storage of logs. For high traffic databases these logs will be significant. Determine your organization's needs before enabling",
            "remediation" : "From Azure Portal\n1. Login to Azure Portal using https://portal.azure.com.\n2. Select Azure Database for MySQL Servers.\n3. Select a database.\n4. Under Settings, select Server parameters.\n5. Update audit_log_enabled parameter to ON\n6. Under Monitoring, select Diagnostic settings.\n7. Select + Add diagnostic setting.\n8. Provide a diagnostic setting name.\n9. Under Categories, select MySQL Audit Logs.\n10. Specify destination details.\n11. Click Save.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, servers in self.configurations.items():
            for server, configurations in servers.items():
                for configuration in configurations:
                    if configuration.name == "audit_log_enabled":
                        if configuration.value != "ON":
                            results["affected"].append(server)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected Mysql servers do not have the 'audit_log_enabled' parameter set to 'ON'."
        elif self.servers:
            results["analysis"] = "Mysql servers have the 'audit_log_enabled' parameter set to 'ON'."
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no Mysql servers found"

        return results

    def mysql_5(self):
        # Ensure server parameter 'audit_log_events' has 'CONNECTION' set for MySQL Database Server (CIS)

        results = {
            "id" : "mysql_4",
            "ref" : "4.4.3",
            "compliance" : "cis_v2.1.0",
            "level" : "N/A",
            "service" : "mysql",
            "name" : "Ensure server parameter 'audit_log_events' has 'CONNECTION' set for MySQL Database Server (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Set audit_log_enabled to include CONNECTION on MySQL Servers. Enabling CONNECTION helps MySQL Database to log items such as successful and failed connection attempts to the server. Log data can be used to identify, troubleshoot, and repair configuration errors and suboptimal performance. \nThere are further costs incurred for storage of logs. For high traffic databases these logs will be significant. Determine your organization's needs before enabling.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Select Azure Database for MySQL servers.\n3. Select a database.\n4. Under Settings, select Server parameters.\n5. Update audit_log_enabled parameter to ON.\n6. Update audit_log_events parameter to have at least CONNECTION checked.\n7. Click Save.\n8. Under Monitoring, select Diagnostic settings.\n9. Select + Add diagnostic setting.\n10. Provide a diagnostic setting name.\n11. Under Categories, select MySQL Audit Logs.\n12. Specify destination details.\n13. Click Save.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, servers in self.configurations.items():
            for server, configurations in servers.items():
                for configuration in configurations:
                    if configuration.name == "audit_log_events":
                        if configuration.value != "CONNECTION":
                            results["affected"].append(server)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected Mysql servers do not have the 'audit_log_events' parameter set to 'SESSION'."
        elif self.servers:
            results["analysis"] = "Mysql servers have the 'audit_log_events' parameter set to 'SESSION'."
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no Mysql servers found"

        return results
