from azure.mgmt.keyvault import KeyVaultManagementClient
import logging

#from utils.utils import describe_regions
#from utils.utils import list_subscriptions

class keyvault(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.vaults = self.get_vaults()

    def get_vaults(self):
        vaults = {}
        for subscription in self.subscriptions:
            logging.info(f'getting key vaults in subscription: { subscription.display_name }')
            try:
                client= KeyVaultManagementClient(credential=self.credential, subscription_id=subscription.subscription_id)
                vaults[subscription.subscription_id] = list(client.vaults.list())
            except Exception as e:
                logging.error(f'error getting key vaults in subscription: { subscription.display_name }, error: { e }')

        return vaults

    def run(self):
        findings = []
        findings += [ self.keyvault_1() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.keyvault_1() ]
        return findings

    def keyvault_1(self):
        # 

        results = {
            "id" : "keyvault_1",
            "ref" : "",
            "compliance" : "",
            "level" : 1,
            "service" : "keyvault",
            "name" : "Azure Key Vaults",
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

        results["analysis"] = self.vaults

        for subscription, vaults in self.vaults.items():
            for vault in vaults:
                results["affected"].append(vault.name)

        if results["analysis"]:
            results["pass_fail"] = "INFO"
        else:
            results["pass_fail"] = "INFO"
            results["analysis"] = "no key vaults found"

        return results
