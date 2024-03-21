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
            results = []
            client = KeyVaultManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.KeyVault/vaults":
                        logging.info(f'getting key vault { resource.name }')
                        try:
                            vault = client.vaults.get(vault_name=resource.name, resource_group_name=resource_group)
                            results.append(vault)
                        except Exception as e:
                            logging.error(f'error getting key vault: { resource.name }, error: { e }')
            if results:
                vaults[subscription] = results
        return vaults

    def run(self):
        findings = []
        findings += [ self.keyvault_1() ]
        findings += [ self.keyvault_2() ]
        findings += [ self.keyvault_3() ]
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

    def keyvault_2(self):
        # Key Vault Lacking Network Access Restrictions

        results = {
            "id" : "keyvault_2",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "keyvault",
            "name" : "Key Vault Lacking Network Access Restrictions",
            "affected": [],
            "analysis" : {},
            "description" : "The subscription under review contained resources which did not implement network level access restrictions (Firewall rules) and therefore allowed unrestricted traffic from the public internet. This configuration impacted the security posture of the cloud environment and increased the risk of unauthorized data exposure.  By default resources in Azure do not implement a firewall to restrict network level access, therefore all users, applications, and services including those on the public internet could potentially communicate with resources  hosted within a subscription at the network layer. Although often protected by authentication, the lack of network restrictions increased the attack surface of the resources and the wider Azure environment. An attacker able to compromise valid credentials could use those credentials to interact with the service from clients on any network or from other Azure tenancies.  To restrict access to Storage Accounts and provide a greater defence in depth for stored data, it is recommended to use private endpoints that only permit access from internal Azure Virtual Networks and/or configure Firewall rules following the principle of least privilege to only allow access from trusted networks and IP addresses.",
            "remediation" : "The affected resources should be configured to restrict network access to the internal virtual private networks. Where external access is required for legitimate purposes, access should be restricted to a subset of whitelisted public IP addresses. \nAdditionally, where external access is not required, organisations should consider implementing a private endpoint connection to facilitate a secure connection between internal services whilst removing the requirement to use public infrastructure. When a private endpoint is configured all traffic between resources is transmitted over the Azure backbone ‘Azure PrivateLink’ network using virtual private IP addresses reducing the exposure of sensitive data. \nTo configure firewall rules within the Azure Portal:\nGo to resource.\nFor each resource, click on the settings menu called ‘Networking’.\nEnsure that you have elected to allow access from Selected networks.\nAdd rules to allow traffic from specific networks and IPs as required. \nClick Save to apply your changes.\nIf you want to limit access at the SQL Server database level consider also implementing an additional layer of database level firewall rules.",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "5.4",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, key_vaults in self.vaults.items():
            for key_vault in key_vaults:
                if key_vault.properties.public_network_access == "Enabled":
                    results["affected"].append(key_vault.name)

        if results["affected"]:
            results["analysis"] = "the affected key vaults have public network access enabled"
            results["pass_fail"] = "FAIL"
        elif self.vaults:
            results["analysis"] = "key vaults do not have public network access enabled"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no key vaults found"


        return results

    def keyvault_3(self):
        # Ensure the Key Vault is Recoverable (CIS)

        results = {
            "id" : "keyvault_3",
            "ref" : "8.5",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "keyvault",
            "name" : "Ensure the Key Vault is Recoverable (CIS)",
            "affected": [],
            "analysis" : {},
            "description" : "The Key Vault contains object keys, secrets, and certificates. Accidental unavailability of a Key Vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the Key Vault objects. It is recommended the Key Vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data, including storage accounts, SQL databases, and/or dependent services provided by Key Vault objects (Keys, Secrets, Certificates) etc. This may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user. There could be scenarios where users accidentally run delete/purge commands on Key Vault or an attacker/malicious user deliberately does so in order to cause disruption. Deleting or purging a Key Vault leads to immediate data loss, as keys encrypting data and secrets/certificates allowing access/services will become non-accessible. There is a Key Vault property that plays a role in permanent unavailability of a Key Vault: enablePurgeProtection: Setting this parameter to 'true' for a Key Vault ensures that even if Key Vault is deleted, Key Vault itself or its objects remain recoverable for the next 90 days. Key Vault/objects can either be recovered or purged (permanent deletion) during those 90 days. If no action is taken, the key vault and its objects will subsequently be purged. Enabling the enablePurgeProtection parameter on Key Vaults ensures that Key Vaults and their objects cannot be deleted/purged permanently",
            "remediation" : "To enable 'Do Not Purge' and 'Soft Delete' for a Key Vault:\nFrom Azure Portal\n1. Go to Key Vaults\n2. For each Key Vault\n3. Click Properties\n4. Ensure the status of Purge protection reads Enable purge protection (enforce\na mandatory retention period for deleted vaults and vault objects).\nNote, once enabled you cannot disable it.", 
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "5.4",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, key_vaults in self.vaults.items():
            for key_vault in key_vaults:
                if key_vault.properties.enable_soft_delete != True:
                    if key_vault.properties.enable_purge_protection != True:
                        results["affected"].append(key_vault.name)

        if results["affected"]:
            results["analysis"] = "the affected key vaults do not have soft delete and purge protection enabled"
            results["pass_fail"] = "FAIL"
        elif self.vaults:
            results["analysis"] = "key vaults have soft delete and purge protection enabled"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no key vaults found"

        return results
