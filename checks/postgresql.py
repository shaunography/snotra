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
        self.flexible_servers = self.get_flexible_servers()
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
        return findings

    def postgresql_1(self):
        # 

        results = {
            "id" : "postgresql_1",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "postgresql",
            "name" : "Postgresql Servers",
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
            results["analysis"] = "no postgresql servers found"

        return results

