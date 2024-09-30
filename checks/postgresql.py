import azure.mgmt.rdbms.postgresql as Postgresql
import azure.mgmt.rdbms.postgresql_flexibleservers as Postgresql_flexible

import azure.core.exceptions as exceptions

import logging

class postgresql(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.resource_groups = resource_groups
        self.resources = resources
        self.servers = self.get_servers()
        self.configurations = self.get_configurations()
        self.flexible_servers = self.get_flexible_servers()
        self.flexible_configurations = self.get_flexible_configurations()
        #self.databases = self.get_databases()
        #self.flexible_databases = self.get_flexible_databases()

    def get_servers(self):
        servers = {}
        for subscription, resource_groups in self.resources.items():
            results = {}
            client = Postgresql.PostgreSQLManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                servers_in_group = []
                for resource in resources:
                    if resource.type == "Microsoft.DBforPostgreSQL/servers":
                        logging.info(f'getting postgresql server { resource.name }')
                        try:
                            servers_in_group.append(client.servers.get(server_name=resource.name, resource_group_name=resource_group))
                        except Exception as e:
                            logging.error(f'error getting postgresql server: { resource.name }, error: { e }')

                if servers_in_group:
                    results[resource_group] = servers_in_group
            if results:
                servers[subscription] = results
        return servers

    def get_configurations(self):
        configurations = {}
        for subscription, resource_groups in self.servers.items():
            results = {}
            client = Postgresql.PostgreSQLManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, servers in resource_groups.items():
                for server in servers:
                    configurations_on_server = []
                    logging.info(f'getting postgresql configurations for server: { server.name }')
                    try:
                        configuration_list = list(client.configurations.list_by_server(server_name=server.name, resource_group_name=resource_group))
                    except Exception as e:
                        logging.error(f'error getting postgresql configurations for server: { server.name }, error: { e }')
                    else:
                        for configuration in configuration_list:
                            try:
                                configurations_on_server.append(client.configurations.get(configuration_name=configuration.name, server_name=server.name, resource_group_name=resource_group))
                            except Exception as e:
                                logging.error(f'error getting postgresql configuration: { configuration.name }, error: { e }')
                        if configurations_on_server:
                            results[server.name] = configurations_on_server
            if results:
                configurations[subscription] = results
        return configurations

    def get_flexible_servers(self):
        servers = {}
        for subscription, resource_groups in self.resources.items():
            results = {}
            client = Postgresql_flexible.PostgreSQLManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                servers_in_group = []
                for resource in resources:
                    if resource.type == "Microsoft.DBforPostgreSQL/flexibleServers":
                        logging.info(f'getting postgresql flexible server { resource.name }')
                        try:
                            servers_in_group.append(client.servers.get(server_name=resource.name, resource_group_name=resource_group))
                        except Exception as e:
                            logging.error(f'error getting postgresql flexible server: { resource.name }, error: { e }')

                if servers_in_group:
                    results[resource_group] = servers_in_group
            if results:
                servers[subscription] = results
        return servers

    def get_flexible_configurations(self):
        configurations = {}
        for subscription, resource_groups in self.flexible_servers.items():
            results = {}
            client = Postgresql_flexible.PostgreSQLManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, servers in resource_groups.items():
                for server in servers:
                    configurations_on_server = []
                    logging.info(f'getting postgres configurations for flexible server: { server.name }')
                    try:
                        configuration_list = list(client.configurations.list_by_server(server_name=server.name, resource_group_name=resource_group))
                    except Exception as e:
                        logging.error(f'error getting postgres configurations for flexible server: { server.name }, error: { e }')
                    else:
                        for configuration in configuration_list:
                            try:
                                configurations_on_server.append(client.configurations.get(configuration_name=configuration.name, server_name=server.name, resource_group_name=resource_group))
                            except Exception as e:
                                logging.error(f'error getting postgres configuration for flexible server: { configuration.name }, error: { e }')
                        if configurations_on_server:
                            results[server.name] = configurations_on_server
            if results:
                configurations[subscription] = results
        return configurations

    def get_databases(self):
        databases = {}
        for subscription, resource_groups in self.servers.items():
            results = {}
            client = Postgresql.PostgreSQLManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, servers in resource_groups.items():
                for server in servers:
                    databases_on_server = []
                    logging.info(f'getting postgresql databases for server: { server.name }')
                    try:
                        database_list = list(client.databases.list_by_server(server_name=server.name, resource_group_name=resource_group))
                    except Exception as e:
                        logging.error(f'error getting postgresql databases for server: { server.name }, error: { e }')
                    else:
                        for database in database_list:
                            try:
                                databases_on_server.append(client.databases.get(database_name=database.name, server_name=server.name, resource_group_name=resource_group))
                            except Exception as e:
                                logging.error(f'error getting postgresql database: { database.name }, error: { e }')

                        if databases_on_server:
                            results[server.name] = databases_on_server
            if results:
                databases[subscription] = results
        return databases

    def get_flexible_databases(self):
        databases = {}
        for subscription, resource_groups in self.flexible_servers.items():
            results = {}
            client = Postgresql_flexible.PostgreSQLManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, servers in resource_groups.items():
                for server in servers:
                    databases_on_server = []
                    logging.info(f'getting postgresql databases for flexible server: { server.name }')
                    try:
                        database_list = list(client.databases.list_by_server(server_name=server.name, resource_group_name=resource_group))
                    except Exception as e:
                        logging.error(f'error getting postgresql databases for flexible server: { server.name }, error: { e }')
                    else:
                        for database in database_list:
                            try:
                                databases_on_server.append(client.databases.get(database_name=database.name, server_name=server.name, resource_group_name=resource_group))
                            except Exception as e:
                                logging.error(f'error getting postgresql database: { database.name }, error: { e }')

                        if databases_on_server:
                            results[server.name] = databases_on_server
            if results:
                databases[subscription] = results
        return databases

    def run(self):
        findings = []
        findings += [ self.postgresql_1() ]
        findings += [ self.postgresql_2() ]
        findings += [ self.postgresql_3() ]
        findings += [ self.postgresql_4() ]
        findings += [ self.postgresql_5() ]
        findings += [ self.postgresql_6() ]
        findings += [ self.postgresql_7() ]
        return findings

    def postgresql_1(self):
        # Ensure 'Enforce SSL connection' is set to 'Enabled' for Standard Postgresql Database Server (CIS)

        results = {
            "id" : "postgresql_1",
            "ref" : "4.3.1",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "postgresql",
            "name" : "Ensure 'Enforce SSL connection' is set to 'Enabled' for Standard Postgresql Database Server (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Enable SSL connection on MYSQL Servers. SSL connectivity helps to provide a new layer of security by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.",
            "remediation" : "From Azure Portal\n1. Login to Azure Portal using https://portal.azure.com\n2. Go to Azure Database for Postgres servers\n3. For each database, click on Connection security\n4. In SSL settings, click on ENABLED to Enforce SSL connections",
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
            results["analysis"] = "the affected Postgresql servers do enforce the use of SSL."
        elif self.servers:
            results["analysis"] = "Postgresql servers are enforcing SSL connections"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no Postgresql servers found"
            results["pass_fail"] = "N/A"

        return results

    def postgresql_2(self):
        # Ensure Server Parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server (CIS)

        results = {
            "id" : "postgresql_2",
            "ref" : "4.3.2",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "postgresql",
            "name" : "Ensure Server Parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Enable log_checkpoints on PostgreSQL Servers. Enabling log_checkpoints helps the PostgreSQL Database to Log each checkpoint in turn generates query and error logs. However, access to transaction logs is not supported. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Go to Azure Database for PostgreSQL servers.\n3. For each database, click on Server parameters.\n4. Search for log_checkpoints.\n5. Click ON and save.",
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
                    if configuration.name == "log_checkpoints":
                        if configuration.value.upper() != "ON":
                            results["affected"].append(server)

        for subscription, servers in self.flexible_configurations.items():
            for server, configurations in servers.items():
                for configuration in configurations:
                    if configuration.name == "log_checkpoints":
                        if configuration.value.upper() != "ON":
                            results["affected"].append(server)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected Postgresql servers do not have the 'log_checkpoints' parameter set to 'ON'."
        elif self.servers or self.flexible_servers:
            results["analysis"] = "Postgresql servers have the 'log_checkpoints' parameter set to 'ON'."
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no Postgresql servers found"
            results["pass_fail"] = "N/A"

        return results

    def postgresql_3(self):
        # Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server (CIS)

        results = {
            "id" : "postgresql_3",
            "ref" : "4.3.3",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "postgresql",
            "name" : "Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Enable log_connections on PostgreSQL Servers. Enabling log_connections helps PostgreSQL Database to log attempted connection to the server, as well as successful completion of client authentication. Log data can be used to identify, troubleshoot, and repair configuration errors and suboptimal performance.",
            "remediation" : "From Azure Portal\n1. Login to Azure Portal using https://portal.azure.com.\n2. Go to Azure Database for PostgreSQL servers.\n3. For each database, click on Server parameters.\n4. Search for log_connections.\n5. Click ON and save.",
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
                    if configuration.name == "log_connections":
                        if configuration.value.upper() != "ON":
                            results["affected"].append(server)

        for subscription, servers in self.flexible_configurations.items():
            for server, configurations in servers.items():
                for configuration in configurations:
                    if configuration.name == "log_connections":
                        if configuration.value.upper() != "ON":
                            results["affected"].append(server)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected Postgresql servers do not have the 'log_connections' parameter set to 'ON'."
        elif self.servers or self.flexible_servers:
            results["analysis"] = "Postgresql servers have the 'log_connections' parameter set to 'ON'."
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no Postgresql servers found"
            results["pass_fail"] = "N/A"

        return results

    def postgresql_4(self):
        # Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server (CIS)

        results = {
            "id" : "postgresql_4",
            "ref" : "4.3.4",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "postgresql",
            "name" : "Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Enable log_disconnections on PostgreSQL Servers. Enabling log_disconnections helps PostgreSQL Database to Logs end of a session, including duration, which in turn generates query and error logs. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.\nEnabling this setting will enable a log of all disconnections. If this is enabled for a high traffic server, the log may grow exponentially.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu\n2. Go to Azure Database for PostgreSQL servers\n3. For each database, click on Server parameters\n4. Search for log_disconnections.\n5. Click ON and save.",
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
                    if configuration.name == "log_disconnections":
                        if configuration.value.upper() != "ON":
                            results["affected"].append(server)

        for subscription, servers in self.flexible_configurations.items():
            for server, configurations in servers.items():
                for configuration in configurations:
                    if configuration.name == "log_disconnections":
                        if configuration.value.upper() != "ON":
                            results["affected"].append(server)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected Postgresql servers do not have the 'log_disconnections' parameter set to 'ON'."
        elif self.servers or self.flexible_servers:
            results["analysis"] = "Postgresql servers have the 'log_disconnections' parameter set to 'ON'."
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no Postgresql servers found"
            results["pass_fail"] = "N/A"

        return results

    def postgresql_5(self):
        # Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server (CIS)

        results = {
            "id" : "postgresql_5",
            "ref" : "4.3.5",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "postgresql",
            "name" : "Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Enable connection_throttling on PostgreSQL Servers. Enabling connection_throttling helps the PostgreSQL Database to Set the verbosity of logged messages. This in turn generates query and error logs with respect to concurrent connections that could lead to a successful Denial of Service (DoS) attack by exhausting connection resources. A system can also fail or be degraded by an overload of legitimate users. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.",
            "remediation" : "From Azure Portal\n1. Login to Azure Portal using https://portal.azure.com.\n2. Go to Azure Database for PostgreSQL servers.\n3. For each database, click on Server parameters.\n4. Search for connection_throttling.\n5. Click ON and save",
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
                    if configuration.name == "connection_throttling":
                        if configuration.value.upper() != "ON":
                            results["affected"].append(server)

        for subscription, servers in self.flexible_configurations.items():
            for server, configurations in servers.items():
                for configuration in configurations:
                    if configuration.name == "connection_throttling":
                        if configuration.value.upper() != "ON":
                            results["affected"].append(server)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected Postgresql servers do not have the 'connection_throttling' parameter set to 'ON'."
        elif self.servers or self.flexible_servers:
            results["analysis"] = "Postgresql servers have the 'connection_throttling' parameter set to 'ON'."
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no Postgresql servers found"
            results["pass_fail"] = "N/A"

        return results

    def postgresql_6(self):
        # Ensure Server Parameter 'log_retention_days' is greater than 3 days for PostgreSQL Database Server (CIS)

        results = {
            "id" : "postgresql_6",
            "ref" : "4.3.6",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "postgresql",
            "name" : "Ensure Server Parameter 'log_retention_days' is greater than 3 days for PostgreSQL Database Server (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Ensure log_retention_days on PostgreSQL Servers is set to an appropriate value. Configuring log_retention_days determines the duration in days that Azure Database for PostgreSQL retains log files. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.\nConfiguring this setting will result in logs being retained for the specified number of days. If this is configured on a high traffic server, the log may grow quickly to occupy a large amount of disk space. In this case you may want to set this to a lower number.",
            "remediation" : "From Azure Portal\n1. From Azure Home select the Portal Menu.\n2. Go to Azure Database for PostgreSQL servers.\n3. For each database, click on Server parameters.\n4. Search for log_retention_days.\n5. Input a value between 4 and 7 (inclusive) and click Save.",
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
                    if configuration.name == "log_retention_days":
                        if int(configuration.value) < 3:
                            results["affected"].append(server)

        for subscription, servers in self.flexible_configurations.items():
            for server, configurations in servers.items():
                for configuration in configurations:
                    if configuration.name == "log_retention_days":
                        if int(configuration.value) < 3:
                            results["affected"].append(server)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected Postgresql servers do not have the 'log_retention_days' parameter set to greater than 3."
        elif self.servers or self.flexible_servers:
            results["analysis"] = "Postgresql servers have the 'log_retention_days' parameter set to greater than 3."
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no Postgresql servers found"
            results["pass_fail"] = "N/A"

        return results

    def postgresql_7(self):
        # Ensure that 'Public Network Access' is `Disabled' for postgressql servers

        results = {
            "id" : "postgresql_7",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "postgresql",
            "name" : "Ensure that 'Public Network Access' is `Disabled' for postgresql servers",
            "affected": [],
            "analysis" : "",
            "description" : "Disallowing public network access for a storage account overrides the public access\nsettings for individual containers in that storage account for Azure Resource Manager\nDeployment Model storage accounts. Azure Storage accounts that use the classic\ndeployment model will be retired on August 31, 2024.\nRationale:\nThe default network configuration for a storage account permits a user with appropriate\npermissions to configure public network access to containers and blobs in a storage\naccount. Keep in mind that public access to a container is always turned off by default\nand must be explicitly configured to permit anonymous requests. It grants read-only\naccess to these resources without sharing the account key, and without requiring a\nshared access signature. It is recommended not to provide public network access to\nstorage accounts until, and unless, it is strongly desired. A shared access signature\ntoken or Azure AD RBAC should be used for providing controlled and timed access to\nblob containers.",
            "remediation" : "Ensure public network access is disabled.",
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

        for subscription, resource_groups in self.flexible_servers.items():
            for resource_group, servers in resource_groups.items():
                for server in servers:
                    if server.network.public_network_access != "Disabled":
                        results["affected"].append(server.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected Postgresql servers have public network access enabled."
        elif self.servers or self.flexible_servers:
            results["analysis"] = "Postgresql servers do not have public network access enabled"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no Postgresql servers found"
            results["pass_fail"] = "N/A"

        return results
