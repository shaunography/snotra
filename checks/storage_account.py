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
        findings += [ self.storage_account_2() ]
        findings += [ self.storage_account_3() ]
        findings += [ self.storage_account_4() ]
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

    def storage_account_2(self):
        # Ensure that 'Secure transfer required' is set to 'Enabled' (CIS)

        results = {
            "id" : "storage_account_2",
            "ref" : "3.1",
            "compliance" : "cis_v3.1.0",
            "level" : 1,
            "service" : "storage_account",
            "name" : "Ensure that 'Secure transfer required' is set to 'Enabled' (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "The secure transfer option enhances the security of a storage account by only allowing\nrequests to the storage account by a secure connection. For example, when calling\nREST APIs to access storage accounts, the connection must use HTTPS. Any requests\nusing HTTP will be rejected when 'secure transfer required' is enabled. When using the\nAzure files service, connection without encryption will fail, including scenarios using\nSMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client.\nBecause Azure storage doesn’t support HTTPS for custom domain names, this option is\nnot applied when using a custom domain name.",
            "remediation" : "From Azure Portal\n1. Go to Storage Accounts\n2. For each storage account, go to Configuration\n3. Set Secure transfer required to Enabled",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, storage_accounts in self.storage_accounts.items():
            for storage_account in storage_accounts:
                if storage_account.enable_https_traffic_only == False:
                    results["affected"].append(storage_account.name)

        if results["affected"]:
            results["analysis"] = "the affected storage accounts do not enforce the use of HTTPS"
            results["pass_fail"] = "FAIL"
        elif self.storage_accounts:
            results["pass_fail"] = "PASS"
            results["analysis"] = "storage acounts enforce secure transfer"
        else:
            results["analysis"] = "no storage accounts in use"

        return results

    def storage_account_3(self):
        # Ensure that 'Public Network Access' is `Disabled' for storage accounts (CIS)

        results = {
            "id" : "storage_account_3",
            "ref" : "3.7",
            "compliance" : "cis_v3.1.0",
            "level" : 1,
            "service" : "storage_account",
            "name" : "Ensure that 'Public Network Access' is `Disabled' for storage accounts (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Disallowing public network access for a storage account overrides the public access\nsettings for individual containers in that storage account for Azure Resource Manager\nDeployment Model storage accounts. Azure Storage accounts that use the classic\ndeployment model will be retired on August 31, 2024.\nRationale:\nThe default network configuration for a storage account permits a user with appropriate\npermissions to configure public network access to containers and blobs in a storage\naccount. Keep in mind that public access to a container is always turned off by default\nand must be explicitly configured to permit anonymous requests. It grants read-only\naccess to these resources without sharing the account key, and without requiring a\nshared access signature. It is recommended not to provide public network access to\nstorage accounts until, and unless, it is strongly desired. A shared access signature\ntoken or Azure AD RBAC should be used for providing controlled and timed access to\nblob containers.",
            "remediation" : "From Azure Portal\nFirst, follow Microsoft documentation and create shared access signature tokens for\nyour blob containers. Then,\n1. Go to Storage Accounts\n2. For each storage account, under the Security + networking section, click\nNetworking\n3. Set Public Network Access to Disabled.",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N ",
            "cvss_score" : "5.4",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, storage_accounts in self.storage_accounts.items():
            for storage_account in storage_accounts:
                if storage_account.public_network_access != "Disabled":
                    results["affected"].append(storage_account.name)

        if results["affected"]:
            results["analysis"] = "the affected storage accounts have public network access enabled"
            results["pass_fail"] = "FAIL"
        elif self.storage_accounts:
            results["pass_fail"] = "PASS"
            results["analysis"] = "storage acounts do not have public network access enabled"
        else:
            results["analysis"] = "no storage accounts in use"

        return results

    def storage_account_4(self):
        # Ensure that 'Public Network Access' is `Disabled' for storage accounts (CIS)

        results = {
            "id" : "storage_account_4",
            "ref" : "3.15",
            "compliance" : "cis_v3.1.0",
            "level" : 1,
            "service" : "storage_account",
            "name" : "Ensure the Minimum TLS version for storage accounts is set to Version 1.2 (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "In some cases, Azure Storage sets the minimum TLS version to be version 1.0 by\ndefault. TLS 1.0 is a legacy version and has known vulnerabilities. This minimum TLS\nversion can be configured to be later protocols such as TLS 1.2.\nRationale:\nTLS 1.0 has known vulnerabilities and has been replaced by later versions of the TLS\nprotocol. Continued use of this legacy protocol affects the security of data in transit.\nImpact:\nWhen set to TLS 1.2 all requests must leverage this version of the protocol. Applications\nleveraging legacy versions of the protocol will fail.",
            "remediation" : "From Azure Console\n1. Login to Azure Portal using https://portal.azure.com\n2. Go to Storage Accounts\n3. Click on each Storage Account\n4. Under Setting section, Click on Configuration\n5. Set the minimum TLS version to be Version 1.2",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N ",
            "cvss_score" : "5.4",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, storage_accounts in self.storage_accounts.items():
            for storage_account in storage_accounts:
                if storage_account.minimum_tls_version != "TLS1_2":
                    results["affected"].append(storage_account.name)

        if results["affected"]:
            results["analysis"] = "the affected storage accounts do not have minimum TLS version set to 1.2"
            results["pass_fail"] = "FAIL"
        elif self.storage_accounts:
            results["pass_fail"] = "PASS"
            results["analysis"] = "storage acounts are using TLS version 1.2"
        else:
            results["analysis"] = "no storage accounts in use"

        return results
