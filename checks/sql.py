from azure.mgmt.sql import SqlManagementClient
from checks.resource import resource
import logging

class sql(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.resource_groups = resource_groups
        self.servers = self.get_servers()
        #self.databases = self.get_databases()

    def get_servers(self):
        servers = {}
        for subscription in self.subscriptions:
            logging.info(f'getting sql servers in subscription: { subscription.display_name }')
            try:
                client= SqlManagementClient(credential=self.credential, subscription_id=subscription.subscription_id)
                servers[subscription.subscription_id] = list(client.servers.list())
            except Exception as e:
                logging.error(f'error getting sql servers in subscription: { subscription.display_name }, error: { e }')

        return servers

    def get_databases(self):
        databases = {}
        for subscription, servers in self.servers.items():
            client = SqlManagementClient(credential=self.credential, subscription_id=subscription)
            databases[subscription] = {}
            for server in servers:
                databases[subscription][server.name] = ""
                logging.info(f'getting sql server { server.name }')
                server_details = client.servers.get(server_name=server.name, resource_group_name=None)
                try:
                    response = client.databases.list_by_server(server_details.resource_group, server.name)
                    if response:
                        databases[subscription][server.name] = sql_client.databases.list_by_server(resource_group_name, server.name)
                except Exception as e:
                    logging.error(f'error getting virtual machines in resource group: { group.name }, error: { e }')

        return databases

    def run(self):
        findings = []
        findings += [ self.sql_1() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.sql_1() ]
        return findings

    def sql_1(self):
        # 

        results = {
            "id" : "sql_1",
            "ref" : "",
            "compliance" : "",
            "level" : 1,
            "service" : "sql",
            "name" : "Azure SQL  Servers",
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

        for subscription, servers in self.servers.items():
            for server in servers:
                results["affected"].append(server.name)

        if results["analysis"]:
            results["pass_fail"] = "INFO"
        else:
            results["pass_fail"] = "INFO"
            results["analysis"] = "no sql servers found"

        return results
