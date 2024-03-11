from azure.mgmt.keyvault import KeyVaultManagementClient
import logging

class keyvault(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.resource_groups = resource_groups
        self.resources = resources
        self.vaults = self.get_vaults()

    def get_vaults(self):
        vaults = {}
        for subscription, resource_groups in self.resources.items():
            vaults[subscription] = []
            client = KeyVaultManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.KeyVault/vaults":
                        logging.info(f'getting key vault { resource.name }')
                        try:
                            vault = client.vaults.get(vault_name=resource.name, resource_group_name=resource_group)
                            vaults[subscription].append(vault)
                        except Exception as e:
                            logging.error(f'error getting key vault: { resource.name }, error: { e }')
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
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
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

        if results["analysis"]:
            results["affected"] = [ i for i, v in results["analysis"].items() ]
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "no key vaults found"

        return results
