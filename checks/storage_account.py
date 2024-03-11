from azure.mgmt.storage import StorageManagementClient
import logging

class storage_account(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.resource_groups = resource_groups
        self.resources = resources
        self.storage_accounts = self.get_storage_accounts()

    def get_storage_accounts(self):
        storage_accounts = {}
        for subscription, resource_groups in self.resources.items():
            storage_accounts[subscription] = []
            client = StorageManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.Storage/storageAccounts":
                        logging.info(f'getting storage account { resource.name }')
                        try:
                            storage_account = client.storage_accounts.get_properties(account_name=resource.name, resource_group_name=resource_group)
                            storage_accounts[subscription].append(storage_account)
                        except Exception as e:
                            logging.error(f'error getting storage account: { resource.name }, error: { e }')
        return storage_accounts

    def run(self):
        findings = []
        findings += [ self.storage_account_1() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.storage_account_1() ]
        return findings

    def storage_account_1(self):
        # 

        results = {
            "id" : "storage_account_1",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "storage_account",
            "name" : "Storage Accounts",
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

        results["analysis"] = self.storage_accounts

        if results["analysis"]:
            results["affected"] = [ i for i, v in results["analysis"].items() ]
            results["pass_fail"] = "INFO"
        else:
            results["pass_fail"] = "INFO"
            results["analysis"] = "no storage accounts found"

        return results
