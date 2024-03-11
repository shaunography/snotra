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
            servers[subscription] = {}
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
                    servers[subscription][resource_group] = servers_in_group

        return servers

    def get_databases(self):
        databases = {}
        for subscription, resource_groups in self.servers.items():
            databases[subscription] = {}
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
                            databases[subscription][server.name] = databases_on_server

        return databases

    def run(self):
        findings = []
        findings += [ self.sql_1() ]
        findings += [ self.sql_2() ]
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
