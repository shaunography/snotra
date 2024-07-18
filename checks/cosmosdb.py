from azure.mgmt.cosmosdb import CosmosDBManagementClient

import azure.core.exceptions as exceptions

import logging

class cosmosdb(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.resource_groups = resource_groups
        self.resources = resources
        self.accounts = self.get_accounts()
        self.mongo_db_databases = self.get_mongo_db_databases()
        #self.mongo_db_collections = self.get_mongo_db_collections()

    def get_accounts(self):
        accounts = {}
        for subscription in self.subscriptions:
            accounts[subscription.subscription_id] = ""
            client = CosmosDBManagementClient(credential=self.credential, subscription_id=subscription.subscription_id)
            try:
                accounts[subscription.subscription_id] = [account for account in client.database_accounts.list()]
            except Exception as e:
                logging.error(f'error cosmosdb accounts: { subscription.subscription_id }, error: { e }')
        return accounts


    def get_mongo_db_databases(self):
        mongo_db_databases = {}
        for subscription, resource_groups in self.resources.items():
            results = []
            client = CosmosDBManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.DocumentDB/databaseAccounts":
                        logging.info(f'getting mongo db databases { resource.name }')
                        try:
                            databases = client.mongo_db_resources.list_mongo_db_databases(account_name=resource.name, resource_group_name=resource_group)
                            for database in databases:
                                results.append(client.mongo_db_resources.get_mongo_db_database(database_name=database.name, account_name=resource.name, resource_group_name=resource_group))
                        except Exception as e:
                            logging.error(f'error getting mongo db databases: { resource.name }, error: { e }')
            if results:
                mongo_db_databases[subscription] = results
        return mongo_db_databases

    def get_mongo_db_collections(self):
        mongo_db_collections = {}
        for subscription, resource_groups in self.resources.items():
            results = []
            client = CosmosDBManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.DocumentDB/databaseAccounts":
                        logging.info(f'getting mongodb { resource.name }')
                        try:
                            collections = client.mongo_db_resources.list_mongo_db_collections(account_name=resource.name, resource_group_name=resource_group)
                            for collection in collections:
                                results.append(client.mongo_db_resources.get_mongo_db_collection(collection_name=collection.name, account_name=resource.name, resource_group_name=resource_group))
                        except Exception as e:
                            logging.error(f'error getting mongo db collections: { resource.name }, error: { e }')
            if results:
                mongo_db_collections[subscription] = results
        return mongo_db_collections


    def run(self):
        findings = []
        findings += [ self.cosmosdb_1() ]
        findings += [ self.cosmosdb_2() ]
        #findings += [ self.cosmosdb_3() ] # WIP
        findings += [ self.cosmosdb_4() ]
        return findings

    def cosmosdb_1(self):
        # Ensure That 'Firewalls & Networks' Is Limited to Use Selected Networks Instead of All Networks (CIS)

        results = {
            "id" : "cosmosdb_1",
            "ref" : "4.5.1",
            "compliance" : "cis_v2.1.0",
            "level" : 2,
            "service" : "cosmosdb",
            "name" : "Ensure That 'Firewalls & Networks' Is Limited to Use Selected Networks Instead of All Networks (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Limiting your Cosmos DB to only communicate on whitelisted networks lowers its attack footprint. Selecting certain networks for your Cosmos DB to communicate restricts the number of networks including the internet that can interact with what is stored within the database",
            "remediation" : "From Azure Portal\n1. Open the portal menu.\n2. Select the Azure Cosmos DB blade.\n3. Select a Cosmos DB account to audit.\n4. Select Networking.\n5. Under Public network access, select Selected networks.\n6. Under Virtual networks, select + Add existing virtual network or + Add a new virtual network.\n7. For existing networks, select subscription, virtual network, subnet and click Add. For new networks, provide a name, update the default values if required, and click Create.\n8. Click Save.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        azure_services = False

        for subscription, accounts in self.accounts.items():
            for account in accounts:
                if account.public_network_access == "Enabled":
                    if not account.ip_rules:
                        if not account.virtual_network_rules:
                            results["affected"].append(account.name)

                if account.network_acl_bypass == "AzureServices":
                    azure_services = True
                    results["affected"].append(account.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected cosmos db accounts allow public network access."
            if azure_services:
                results["analysis"] = "the affected cosmos db accounts allow public network access including azure services"
        elif self.accounts:
            results["analysis"] = "public network access is not allowed"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no cosmos db accounts in use"

        return results

    def cosmosdb_2(self):
        # Ensure the Minimum TLS version for Cosmos DB Accounts is set to Version 1.2

        results = {
            "id" : "cosmosdb_2",
            "ref" : "snotra",
            "compliance" : "n/a",
            "level" : "n/a",
            "service" : "cosmosdb",
            "name" : "Ensure the Minimum TLS version for Cosmos DB Accounts is set to Version 1.2",
            "affected": [],
            "analysis" : "",
            "description" : "TLS 1.0 is a legacy version and has known vulnerabilities. This minimum TLS\nversion can be configured to be later protocols such as TLS 1.2.\nRationale:\nTLS 1.0 has known vulnerabilities and has been replaced by later versions of the TLS\nprotocol. Continued use of this legacy protocol affects the security of data in transit.\nImpact:\nWhen set to TLS 1.2 all requests must leverage this version of the protocol. Applications\nleveraging legacy versions of the protocol will fail.",
            "remediation" : "Ensure Cosmos DB Accounts are using a minimum TLS version of 1.2",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "5.4",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, accounts in self.accounts.items():
            for account in accounts:
                if account.minimal_tls_version != "Tls12":
                    results["affected"].append(account.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected cosmos db accounts do not enforce TLS version 1.2."
        elif self.accounts:
            results["analysis"] = "cosmos db accounts are using TLS version 1.2"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no cosmos db accounts in use"

        return results

    def cosmosdb_3(self):
        # Ensure That Private Endpoints Are Used Where Possible (CIS)

        results = {
            "id" : "cosmosdb_3",
            "ref" : "4.5.2",
            "compliance" : "cis_v2.1.0",
            "level" : 2,
            "service" : "cosmosdb",
            "name" : "Ensure That Private Endpoints Are Used Where Possible (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Private endpoints limit network traffic to approved sources. For sensitive data, private endpoints allow granular control of which services can communicate with Cosmos DB and ensure that this network traffic is private. You set this up on a case by case basis for each service you wish to be connected.",
            "remediation" : "From Azure Portal\n1. Open the portal menu.\n2. Select the Azure Cosmos DB blade.\n3. Select the Azure Cosmos DB account.\n4. Select Networking.\n5. Select Private access.\n6. Click + Private Endpoint.\n7. Provide a Name.\n8. Click Next.\n9. From the Resource type drop down, select Microsoft.AzureCosmosDB/databaseAccounts.\n10. From the Resource drop down, select the Cosmos DB account.\n11. Click Next.\n12. Provide appropriate Virtual Network details.\n13. Click Next.\n14. Provide appropriate DNS details.\n15. Click Next.\n16. Optionally provide Tags.\n17. Click Next : Review + create.\n18. Click Create.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, accounts in self.accounts.items():
            for account in accounts:
                if account.public_network_access == "Enabled":
                    results["affected"].append(account.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected cosmos db accounts allow public network access."
        elif self.accounts:
            results["analysis"] = "public network access is not allowed"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no cosmos db accounts in use"

        return results

    def cosmosdb_4(self):
        # Use Entra ID Client Authentication and Azure RBAC where possible (CIS)

        results = {
            "id" : "cosmosdb_4",
            "ref" : "4.5.3",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "cosmosdb",
            "name" : "Use Entra ID Client Authentication and Azure RBAC where possible (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Cosmos DB can use tokens or Entra ID for client authentication which in turn will use Azure RBAC for authorization. Using Entra ID is significantly more secure because Entra ID handles the credentials and allows for MFA and centralized management, and the Azure RBAC better integrated with the rest of Azure.\nEntra ID client authentication is considerably more secure than token-based authentication because the tokens must be persistent at the client. Entra ID does not require this.",
            "remediation" : "Map all the resources that currently access to the Azure Cosmos DB account with keys or access tokens. Create an Entra ID identity for each of these resources: \n- For Azure resources, you can create a managed identity. You may choose between system-assigned and user-assigned managed identities. \n- For non-Azure resources, create an Entra ID identity. Grant each Entra ID identity the minimum permission it requires. When possible, we recommend you use one of the 2 built-in role definitions: Cosmos DB Built-in Data Reader or Cosmos DB Built-in Data Contributor. Validate that the new resource is functioning correctly. After new permissions are granted to identities, it may take a few hours until they propagate. When all resources are working correctly with the new identities, continue to the next step",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, accounts in self.accounts.items():
            for account in accounts:
                if account.disable_local_auth != "Enabled":
                    results["affected"].append(account.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected cosmos db accounts allow local authentication."
        elif self.accounts:
            results["analysis"] = "local authentication is not allowed"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no cosmos db accounts in use"

        return results
