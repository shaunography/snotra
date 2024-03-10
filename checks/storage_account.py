from azure.mgmt.storage import StorageManagementClient
import logging

class storage_account(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.storage_accounts = self.get_storage_accounts()

    def get_storage_accounts(self):
        storage_accounts = {}
        for subscription in self.subscriptions:
            logging.info(f'getting storage accounts in subscription: { subscription.display_name }')
            try:
                client= StorageManagementClient(credential=self.credential, subscription_id=subscription.subscription_id)
                storage_accounts[subscription.subscription_id] = list(client.storage_accounts.list())
            except Exception as e:
                logging.error(f'error getting storage accounts in subscription: { subscription.display_name }, error: { e }')

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
            "ref" : "",
            "compliance" : "",
            "level" : 1,
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

        for subscription, storage_accounts in self.storage_accounts.items():
            for storage_account in storage_accounts:
                results["affected"].append(storage_account.name)

        if results["analysis"]:
            results["pass_fail"] = "INFO"
        else:
            results["pass_fail"] = "INFO"
            results["analysis"] = "no storage accounts found"

        return results
