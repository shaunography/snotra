from azure.mgmt.storage import StorageManagementClient
from azure.storage.blob import BlobServiceClient

from datetime import date
from datetime import datetime, timezone
from datetime import timedelta

import logging

class storage_account(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.resource_groups = resource_groups
        self.resources = resources
        self.storage_accounts = self.get_storage_accounts()
        self.containers = self.get_containers()

    def get_storage_accounts(self):
        storage_accounts = {}
        for subscription, resource_groups in self.resources.items():
            results = []
            client = StorageManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.Storage/storageAccounts":
                        logging.info(f'getting storage account { resource.name }')
                        try:
                            storage_account = client.storage_accounts.get_properties(account_name=resource.name, resource_group_name=resource_group)
                            results.append(storage_account)
                        except Exception as e:
                            logging.error(f'error getting storage account: { resource.name }, error: { e }')
            if results:
                storage_accounts[subscription] = results
        return storage_accounts

    def get_containers(self):
        containers = {}
        for subscription, resource_groups in self.resources.items():
            results = {}
            client = StorageManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.Storage/storageAccounts":
                        logging.info(f'getting containers for storage account { resource.name }')
                        try:
                            blob_client = BlobServiceClient(credential=self.credential, account_url=f"https://{resource.name}.blob.core.windows.net")
                            results[resource.name] = blob_client.list_containers()
                        except Exception as e:
                            logging.error(f'error getting containers for storage account: { resource.name }, error: { e }')
            if results:
                containers[subscription] = results
        return containers

    def run(self):
        findings = []
        findings += [ self.storage_account_1() ]
        findings += [ self.storage_account_2() ]
        findings += [ self.storage_account_3() ]
        #findings += [ self.storage_account_4() ]
        findings += [ self.storage_account_5() ]
        findings += [ self.storage_account_6() ]
        findings += [ self.storage_account_7() ]
        findings += [ self.storage_account_8() ]
        findings += [ self.storage_account_9() ]
        findings += [ self.storage_account_10() ]
        findings += [ self.storage_account_11() ]
        findings += [ self.storage_account_12() ]
        findings += [ self.storage_account_13() ]
        findings += [ self.storage_account_14() ]
        findings += [ self.storage_account_15() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.storage_account_1() ]
        return findings


    def storage_account_1(self):
        # Ensure that 'Secure transfer required' is set to 'Enabled' (CIS)

        results = {
            "id" : "storage_account_1",
            "ref" : "3.1",
            "compliance" : "cis_v3.1.0",
            "level" : 1,
            "service" : "storage_account",
            "name" : "Ensure that 'Secure transfer required' is set to 'Enabled' (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "The secure transfer option enhances the security of a storage account by only allowing requests to the storage account by a secure connection. For example, when calling REST APIs to access storage accounts, the connection must use HTTPS. Any requests using HTTP will be rejected when 'secure transfer required' is enabled. When using the Azure files service, connection without encryption will fail, including scenarios using SMB 2.1, SMB 3.0 without encryption, and some flavors of the Linux SMB client.Because Azure storage doesn’t support HTTPS for custom domain names, this option is not applied when using a custom domain name.",
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

    def storage_account_2(self):
        # Ensure that ‘Enable Infrastructure Encryption’ for Each Storage Account in Azure Storage is Set to ‘enabled’ (CIS)

        results = {
            "id" : "storage_account_2",
            "ref" : "3.2",
            "compliance" : "cis_v3.1.0",
            "level" : 2,
            "service" : "storage_account",
            "name" : "Ensure that ‘Enable Infrastructure Encryption’ for Each Storage Account in Azure Storage is Set to ‘enabled’ (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Enabling encryption at the hardware level on top of the default software encryption for Storage Accounts accessing Azure storage solutions. Azure Storage automatically encrypts all data in a storage account at the network levelusing 256-bit AES encryption, which is one of the strongest, FIPS 140-2-compliant blockciphers available. Customers who require higher levels of assurance that their data issecure can also enable 256-bit AES encryption at the Azure Storage infrastructure levelfor double encryption. Double encryption of Azure Storage data protects against ascenario where one of the encryption algorithms or keys may be compromised.Similarly, data is encrypted even before network transmission and in all backups. In thisscenario, the additional layer of encryption continues to protect your data. For the mostsecure implementation of key based encryption, it is recommended to use a CustomerManaged asymmetric RSA 2048 Key in Azure Key Vault.\nThe read and write speeds to the storage will be impacted if both default encryption and Infrastructure Encryption are checked, as a secondary form of encryption requires more resource overhead for the cryptography of information. This performance impact should be considered in an analysis for justifying use of the feature in your environment. Customer-managed keys are recommended for the most secure implementation, leading to overhead of key management. The key will also need to be backed up in a secure location, as loss of the key will mean loss of the information in the storage.",
            "remediation" : "Infrastructure encryption can only be enabled on storage account creation.\nFrom Azure Portal\n1. During Storage Account creation, in the Encryption tab, check the box next to\nEnable infrastructure encryption.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, storage_accounts in self.storage_accounts.items():
            for storage_account in storage_accounts:
                if storage_account.encryption.require_infrastructure_encryption != True:
                    results["affected"].append(storage_account.name)

        if results["affected"]:
            results["analysis"] = "the affected storage accounts do not hahve infrastructure encryption enabled"
            results["pass_fail"] = "FAIL"
        elif self.storage_accounts:
            results["pass_fail"] = "PASS"
            results["analysis"] = "storage acounts are using infrastructure encryption"
        else:
            results["analysis"] = "no storage accounts in use"

        return results

    def storage_account_3(self):
        # Ensure that Storage Account Access Keys are Periodically Regenerated (CIS)

        results = {
            "id" : "storage_account_3",
            "ref" : "3.3,3,4",
            "compliance" : "cis_v3.1.0",
            "level" : 2,
            "service" : "storage_account",
            "name" : "Ensure that Storage Account Access Keys are Periodically Regenerated (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "For increased security, regenerate storage account access keys periodically. When a storage account is created, Azure generates two 512-bit storage access keys which are used for authentication when the storage account is accessed. Rotating these keys periodically ensures that any inadvertent access or exposure does not result from the compromise of these keys.\nCryptographic key rotation periods will vary depending on your organization's security requirements and the type of data which is being stored in the Storage Account. For example, PCI DSS mandates that cryptographic keys be replaced or rotated 'regularly,' and advises that keys for static data stores be rotated every 'few months.' For the purposes of this recommendation, 90 days will prescribed for the reminder. Review and adjustment of the 90 day period is recommended, and may even be necessary. Your organization's security requirements should dictate the appropriate setting.\nRegenerating access keys can affect services in Azure as well as the organization's applications that are dependent on the storage account. All clients who use the access key to access the storage account must be updated to use the new key.",
            "remediation" : "It is recomended that a reminder is configured to each storage account to rotate keys on a regular schedule.For the purposes of this recommendation, 90 days will prescribed for the reminder. Review and adjustment of the 90 day period is recommended, and may even be necessary. Your organization's security requirements should dictate the appropriate setting. From Azure Portal\n1. Go to Storage Accounts\n2. For each Storage Account with outdated keys, go to Access keys\n3. Click Rotate key next to the outdated key, then click Yes to the prompt confirming\nthat you want to regenerate the access key.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, storage_accounts in self.storage_accounts.items():
            for storage_account in storage_accounts:
                if not storage_account.key_creation_time.key1 or not storage_account.key_creation_time.key2:
                    results["affected"].append(storage_account.name)
                else:
                    # get storage account created more than 90 days ago
                    if storage_account.creation_time < (datetime.now(timezone.utc) - timedelta(days=90)):
                        # check if key creation time is the same as the storage account creation time
                        if storage_account.key_creation_time.key1.date() == storage_account.creation_time.date() or storage_account.key_creation_time.key2.date() == storage_account.creation_time.date():
                            results["affected"].append(storage_account.name)
                        elif storage_account.key_creation_time.key1 < (datetime.now(timezone.utc) - timedelta(days=90)) or storage_account.key_creation_time.key2 < (datetime.now(timezone.utc) - timedelta(days=90)):
                            results["affected"].append(storage_account.name)

        if results["affected"]:
            results["analysis"] = "the affected storage accounts have access keys that have not been recently rotated"
            results["pass_fail"] = "FAIL"
        elif self.storage_accounts:
            results["pass_fail"] = "PASS"
            results["analysis"] = "storage acounts are access keys that have been recently rotated"
        else:
            results["analysis"] = "no storage accounts in use"

        return results

    def storage_account_5(self):
        # Ensure that 'Public Network Access' is `Disabled' for storage accounts (CIS)

        results = {
            "id" : "storage_account_5",
            "ref" : "3.7",
            "compliance" : "cis_v3.1.0",
            "level" : 1,
            "service" : "storage_account",
            "name" : "Ensure that 'Public Network Access' is `Disabled' for storage accounts (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Disallowing public network access for a storage account overrides the public access settings for individual containers in that storage account for Azure Resource Manager Deployment Model storage accounts. Azure Storage accounts that use the classic deployment model will be retired on August 31, 2024. The default network configuration for a storage account permits a user with appropriate permissions to configure public network access to containers and blobs in a storage account. Keep in mind that public access to a container is always turned off by default and must be explicitly configured to permit anonymous requests. It grants read-only access to these resources without sharing the account key, and without requiring a shared access signature. It is recommended not to provide public network access to storage accounts until, and unless, it is strongly desired. A shared access signature token or Azure AD RBAC should be used for providing controlled and timed access to blob containers.",
            "remediation" : "From Azure Portal\nFirst, follow Microsoft documentation and create shared access signature tokens for\nyour blob containers. Then,\n1. Go to Storage Accounts\n2. For each storage account, under the Security + networking section, click Networking\n3. Set Public Network Access to Disabled.",
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

    def storage_account_6(self):
        # Ensure Default Network Access Rule for Storage Accounts is Set to Deny (CIS)

        results = {
            "id" : "storage_account_6",
            "ref" : "3.8",
            "compliance" : "cis_v3.1.0",
            "level" : 1,
            "service" : "storage_account",
            "name" : "Ensure Default Network Access Rule for Storage Accounts is Set to Deny (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Restricting default network access helps to provide a new layer of security, since storage accounts accept connections from clients on any network. To limit access to selected networks, the default action must be changed.\nStorage accounts should be configured to deny access to traffic from all networks (including internet traffic). Access can be granted to traffic from specific Azure Virtual networks, allowing a secure network boundary for specific applications to be built. Access can also be granted to public internet IP address ranges to enable connections from specific internet or on-premises clients. When network rules are configured, only applications from allowed networks can access a storage account. When calling from an allowed network, applications continue to require proper authorization (a valid access key or SAS token) to access the storage account.\nAll allowed networks will need to be whitelisted on each specific network, creating administrative overhead. This may result in loss of network connectivity, so do not turn on for critical resources during business hours.",
            "remediation" : "From Azure Console\n1. Go to Storage Accounts\n2. For each storage account, Click on the Networking blade\n3. Click the Firewalls and virtual networks heading.\n4. Ensure that you have elected to allow access from Selected networks\n5. Add rules to allow traffic from specific network.\n6. Click Save to apply your changes.",
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
                    if not storage_account.network_rule_set.ip_rules:
                        if not storage_account.network_rule_set.virtual_network_rules:
                            results["affected"].append(storage_account.name)

        if results["affected"]:
            results["analysis"] = "the affected storage accounts allow access from all networks"
            results["pass_fail"] = "FAIL"
        elif self.storage_accounts:
            results["pass_fail"] = "PASS"
            results["analysis"] = "storage acounts do not allow access from all networks"
        else:
            results["analysis"] = "no storage accounts in use"

        return results

    def storage_account_7(self):
        # Ensure 'Allow Azure services on the trusted services list to access this storage account' is Enabled for Storage Account Access (CIS)

        results = {
            "id" : "storage_account_7",
            "ref" : "3.9",
            "compliance" : "cis_v3.1.0",
            "level" : 2,
            "service" : "storage_account",
            "name" : "Ensure 'Allow Azure services on the trusted services list to access this storage account' is Enabled for Storage Account Access (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Some Azure services that interact with storage accounts operate from networks that can't be granted access through network rules. To help this type of service work as intended, allow the set of trusted Azure services to bypass the network rules. These services will then use strong authentication to access the storage account. If the Allowtrusted Azure services exception is enabled, the following services are granted accessto the storage account: Azure Backup, Azure Site Recovery, Azure DevTest Labs,Azure Event Grid, Azure Event Hubs, Azure Networking, Azure Monitor, and Azure SQLData Warehouse (when registered in the subscription).Turning on firewall rules for storage account will block access to incoming requests fordata, including from other Azure services. We can re-enable this functionality byenabling 'Trusted Azure Services' through networking exceptions.\nThis creates authentication credentials for services that need access to storageresources so that services will no longer need to communicate via network request.\nThere may be a temporary loss of communication as you set each Storage Account. Itis recommended to not do this on mission-critical resources during business hours.",
            "remediation" : "From Azure Portal\n1. Go to Storage Accounts\n2. For each storage account, Click on the Networking blade\n3. Click on the Firewalls and virtual networks heading.\n4. Ensure that Enabled from selected virtual networks and IP addresses is\nselected.\n5. Under the 'Exceptions' label, enable check box for Allow Azure services on the\ntrusted services list to access this storage account.\n6. Click Save to apply your changes.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, storage_accounts in self.storage_accounts.items():
            for storage_account in storage_accounts:
                if not storage_account.network_rule_set.bypass == "AzureServices":
                    results["affected"].append(storage_account.name)

        if results["affected"]:
            results["analysis"] = "the affected storage accounts do not allow access from azure services"
            results["pass_fail"] = "FAIL"
        elif self.storage_accounts:
            results["pass_fail"] = "PASS"
            results["analysis"] = "storage acounts allow access from azure services"
        else:
            results["analysis"] = "no storage accounts in use"

        return results


    def storage_account_8(self):
        # Ensure Private Endpoints are used to access Storage Accounts (CIS)

        results = {
            "id" : "storage_account_8",
            "ref" : "3.10",
            "compliance" : "cis_v3.1.0",
            "level" : 1,
            "service" : "storage_account",
            "name" : "Ensure Private Endpoints are used to access Storage Accounts (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Use private endpoints for your Azure Storage accounts to allow clients and services to securely access data located over a network via an encrypted Private Link. To do this, the private endpoint uses an IP address from the VNet for each service. Network traffic between disparate services securely traverses encrypted over the VNet. This VNet can also link addressing space, extending your network and accessing resources on it. Similarly, it can be a tunnel through public networks to connect remote infrastructures together. This creates further security through segmenting network traffic and preventing outside sources from accessing it.",
            "remediation" : "If storage account are only used internally, then consider implementing private endpoint for container access, and removed all other network access to provide greater defence in depth and data confidentiality.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, storage_accounts in self.storage_accounts.items():
            for storage_account in storage_accounts:
                if not storage_account.private_endpoint_connections:
                    results["affected"].append(storage_account.name)


        if results["affected"]:
            results["analysis"] = "the affected storage accounts do no have private endpoint connections configured"
            results["pass_fail"] = "FAIL"
        elif self.storage_accounts:
            results["pass_fail"] = "PASS"
            results["analysis"] = "storage acounts have private endpoint connections configured"
        else:
            results["analysis"] = "no storage accounts in use"

        return results

    def storage_account_9(self):
        # Ensure that Shared Access Signature Tokens Expire Within an Hour (CIS)(Manual)

        results = {
            "id" : "storage_account_9",
            "ref" : "3.11",
            "compliance" : "cis_v3.1.0",
            "level" : 1,
            "service" : "storage_account",
            "name" : "Ensure Soft Delete is Enabled for Azure Containers and Blob Storage (CIS)(Manual)",
            "affected": [],
            "analysis" : "",
            "description" : "The Azure Storage blobs contain data like ePHI or Financial, which can be secret or personal. Data that is erroneously modified or deleted by an application or other storage account user will cause data loss or unavailability. It is recommended that both Azure Containers with attached Blob Storage and standalone containers with Blob Storage be made recoverable by enabling the soft delete configuration. This is to save and recover data when blobs or blob snapshots are deleted.\nContainers and Blob Storage data can be incorrectly deleted. An attacker/malicious user may do this deliberately in order to cause disruption. Deleting an Azure Storage blob causes immediate data loss. Enabling this configuration for Azure storage ensures that even if blobs/data were deleted from the storage account, Blobs/data objects are recoverable for a particular time which is set in the 'Retention policies,' ranging from 7 days to 365 days.\nAdditional storage costs may be incurred as snapshots are retained",
            "remediation" : "From Azure Portal\n1. From the Azure home page, open the hamburger menu in the top left or click on the arrow pointing right with 'More services' underneath.\n2. Select Storage.\n3. Select Storage Accounts.\n4. For each Storage Account, navigate to Data protection in the left scroll column.\n5. Check soft delete for both blobs and containers. Set the retention period to a sufficient length for your organization",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["analysis"] = self.storage_accounts

        results["affected"] = [ i.id for i in self.subscriptions ]
        results["analysis"] = "From Azure Portal:\n1. From the Azure home page, open the hamburger menu in the top left or click on the arrow pointing right with 'More services' underneath.\n2. Select Storage.\n3. Select Storage Accounts.\n4. For each Storage Account, navigate to Data protection in the left scroll column.\n5. Ensure that soft delete is checked for both blobs and containers. Also check if the retention period is a sufficient length for your organization"
        results["pass_fail"] = "INFO"

        return results

    def storage_account_10(self):
        # Ensure that Shared Access Signature Tokens Expire Within an Hour (CIS)(Manual)

        results = {
            "id" : "storage_account_10",
            "ref" : "3.12",
            "compliance" : "cis_v3.1.0",
            "level" : 2,
            "service" : "storage_account",
            "name" : "Ensure Storage for Critical Data are Encrypted with Customer Managed Keys (CMK) (CIS)(Manual)",
            "affected": [],
            "analysis" : "",
            "description" : "Enable sensitive data encryption at rest using Customer Managed Keys (CMK) rather than Microsoft Managed keys. \nBy default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. If you want to control and manage this encryption key yourself, however, you can specify a customer-managed key. That key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault. \nIf the key expires by setting the 'activation date' and 'expiration date', the user must rotate the key manually. Using Customer Managed Keys may also incur additional man-hour requirements to create, store, manage, and protect the keys as needed.",
            "remediation" : "From Azure Portal\n1. Go to Storage Accounts\n2. For each storage account, go to Encryption\n3. Set Customer Managed Keys\n4. Select the Encryption key and enter the appropriate setting value\n5. Click Save",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["analysis"] = self.storage_accounts

        results["affected"] = [ i.id for i in self.subscriptions ]
        results["analysis"] = "From Azure Console:\n1. Go to Storage Accounts\n2. For each storage account, go to Encryption\n3. Ensure that Encryption type is set to Customer Managed Keys"
        results["pass_fail"] = "INFO"

        return results

    def storage_account_11(self):
        # Ensure the Minimum TLS version for storage accounts is set to Version 1.2 (CIS)

        results = {
            "id" : "storage_account_11",
            "ref" : "3.15",
            "compliance" : "cis_v3.1.0",
            "level" : 1,
            "service" : "storage_account",
            "name" : "Ensure the Minimum TLS version for storage accounts is set to Version 1.2 (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "In some cases, Azure Storage sets the minimum TLS version to be version 1.0 by default. TLS 1.0 is a legacy version and has known vulnerabilities. This minimum TLS version can be configured to be later protocols such as TLS 1.2. TLS 1.0 has known vulnerabilities and has been replaced by later versions of the TLS protocol. Continued use of this legacy protocol affects the security of data in transit. Impact: When set to TLS 1.2 all requests must leverage this version of the protocol. Applications leveraging legacy versions of the protocol will fail.",
            "remediation" : "From Azure Console\n1. Login to Azure Portal using https://portal.azure.com\n2. Go to Storage Accounts\n3. Click on each Storage Account\n4. Under Setting section, Click on Configuration\n5. Set the minimum TLS version to be Version 1.2",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
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

    def storage_account_12(self):
        # Ensure 'Cross Tenant Replication' is not enabled (CIS)

        results = {
            "id" : "storage_account_12",
            "ref" : "3.16",
            "compliance" : "cis_v3.1.0",
            "level" : 1,
            "service" : "storage_account",
            "name" : "Ensure 'Cross Tenant Replication' is not enabled (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Cross Tenant Replication in Azure allows data to be replicated across multiple Azure tenants. While this feature can be beneficial for data sharing and availability, it also poses a significant security risk if not properly managed. Unauthorized data access, data leakage, and compliance violations are potential risks. Disabling Cross Tenant Replication ensures that data is not inadvertently replicated across different tenant boundaries without explicit authorization. Disabling Cross Tenant Replication minimizes the risk of unauthorized data access and ensures that data governance policies are strictly adhered to. This control is especially critical for organizations with stringent data security and privacy requirements, as it prevents the accidental sharing of sensitive information.",
            "remediation" : "From Azure Portal\n1. Navigate to Storage Accounts\n2. For each storage account, on the left blade under Data Management, click on\nObject replication\n3. Click on Advanced settings and untick Allow cross-tenant replication\n4. Click on OK",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, storage_accounts in self.storage_accounts.items():
            for storage_account in storage_accounts:
                if storage_account.allow_cross_tenant_replication == True:
                    results["affected"].append(storage_account.name)

        if results["affected"]:
            results["analysis"] = "the affected storage accounts cross tenant replication enabled"
            results["pass_fail"] = "FAIL"
        elif self.storage_accounts:
            results["pass_fail"] = "PASS"
            results["analysis"] = "storage acounts do not have cross tenant replication enabled"
        else:
            results["analysis"] = "no storage accounts in use"

        return results

    def storage_account_13(self):
        # Ensure that `Allow Blob Anonymous Access` is set to `Disabled`(CIS)

        results = {
            "id" : "storage_account_13",
            "ref" : "3.17",
            "compliance" : "cis_v3.1.0",
            "level" : 1,
            "service" : "storage_account",
            "name" : "Ensure that `Allow Blob Anonymous Access` is set to `Disabled`(CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "The Azure Storage setting ‘Allow Blob Anonymous Access’ (aka allowBlobPublicAccess) controls whether anonymous access is allowed for blob data in a storage account. When this property is set to True, it enables public read access to blob data, which can be convenient for sharing data but may carry security risks. When set to False, it disallows public access to blob data, providing a more secure storage environment. If 'Allow Blob Anonymous Access' is enabled, blobs can be accessed by adding the blob name to the URL to see the contents. An attacker can enumerate a blob using methods, such as brute force, and access them. Exfiltration of data by brute force enumeration of items from a storage account may occur if this setting is set to 'Enabled'. Impact: Additional consideration may be required for exceptional circumstances where elements of a storage account require public accessibility. In these circumstances, it is highly recommended that all data stored in the public facing storage account be reviewed for sensitive or potentially compromising data, and that sensitive or compromising data is never stored in these storage accounts.",
            "remediation" : "From Azure Portal:\n1. Open the Storage Accounts blade\n2. Click on a Storage Account\n3. In the storage account menu pane, under the Settings section, click Configuration.\n4. Under Allow Blob Anonymous Access, select Disabled.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, storage_accounts in self.storage_accounts.items():
            for storage_account in storage_accounts:
                if storage_account.allow_blob_public_access == True:
                    results["affected"].append(storage_account.name)

        if results["affected"]:
            results["analysis"] = "the affected storage accounts allow blob public access"
            results["pass_fail"] = "FAIL"
        elif self.storage_accounts:
            results["pass_fail"] = "PASS"
            results["analysis"] = "storage acounts do not allow blob public access"
        else:
            results["analysis"] = "no storage accounts in use"

        return results

    def storage_account_14(self):
        # Storage Account Allows Anonymous/Public Container Access

        results = {
            "id" : "storage_account_14",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "storage_account",
            "name" : "Storage Account Allows Anonymous/Public Container Access",
            "affected": [],
            "analysis" : {},
            "description" : "The affected storage accounts allow public access to one or more containers and its blobs. Public access grants read-only access to these resources without sharing the account key, and without requiring a shared access signature. This means that any user that knows the name of the storage account and container can list the contents and access files without authentication, potentially resulting in the disclosure of sensitive information. It is recommended that a shared access signature token is used for providing controlled and timed access to blob containers if this is required.",
            "remediation" : "It is recommended that public access is removed from the affected storage accounts, if public access is required then shared access tokens should be used. \nGo to Storage Accounts \nTo disable public access in the Azure console: \nFor each storage account, go to Containers under Blob Service \nFor each container, click Access policy. \nSet Public access level to Private (no anonymous access) \nAlternatively, you can disable public access at the storage account level which will apply to all containers \nGo to Storage Accounts \nFor each storage account, go to Allow Blob public access in Configuration. \nSet Disabled if no anonymous access is needed on the storage account.",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, storage_accounts in self.storage_accounts.items():
            for storage_account in storage_accounts:
                vulnerable = []
                if storage_account.allow_blob_public_access == True:
                    containers = self.containers[subscription][storage_account.name]
                    try:
                        for container in containers:
                            if container.public_access == "container":
                                results["affected"].append(storage_account.name)
                                vulnerable.append(container.name)
                    except Exception as e:
                        logging.error(f'error getting containers for account: { storage_account.name }, error: { e }')


                    if vulnerable:
                        results["analysis"][storage_account.name] = vulnerable

        if results["affected"]:
            results["pass_fail"] = "FAIL"
        elif self.storage_accounts:
            results["pass_fail"] = "PASS"
            results["analysis"] = "storage acounts do not allow container public access"
        else:
            results["analysis"] = "no storage accounts in use"

        return results

    def storage_account_15(self):
        # Storage Account Allows Anonymous/Public Blob Access

        results = {
            "id" : "storage_account_15",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "storage_account",
            "name" : "Storage Account Allows Anonymous/Public Blob Access",
            "affected": [],
            "analysis" : "",
            "description" : "The affected storage accounts allow public access to one or more containers and its blobs. Public access grants read-only access to these resources without sharing the account key, and without requiring a shared access signature. This means that any user that knows the name of the storage account and container can list the contents and access files without authentication, potentially resulting in the disclosure of sensitive information. It is recommended that a shared access signature token is used for providing controlled and timed access to blob containers if this is required.",
            "remediation" : "It is recommended that public access is removed from the affected storage accounts, if public access is required then shared access tokens should be used. \nGo to Storage Accounts \nTo disable public access in the Azure console: \nFor each storage account, go to Containers under Blob Service \nFor each container, click Access policy. \nSet Public access level to Private (no anonymous access) \nAlternatively, you can disable public access at the storage account level which will apply to all containers \nGo to Storage Accounts \nFor each storage account, go to Allow Blob public access in Configuration. \nSet Disabled if no anonymous access is needed on the storage account.",
            "impact" : "medium",
            "probability" : "medium",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "5.3",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, storage_accounts in self.storage_accounts.items():
            for storage_account in storage_accounts:
                vulnerable = []
                if storage_account.allow_blob_public_access == True:
                    containers = self.containers[subscription][storage_account.name]
                    try:
                        for container in containers:
                            if container.public_access == "blob":
                                results["affected"].append(storage_account.name)
                                vulnerable.append(container.name)
                    except Exception as e:
                        logging.error(f'error getting containers for account: { storage_account.name }, error: { e }')

                    if vulnerable:
                        results["analysis"][storage_account.name] = vulnerable

        if results["affected"]:
            results["pass_fail"] = "FAIL"
        elif self.storage_accounts:
            results["pass_fail"] = "PASS"
            results["analysis"] = "storage acounts do not allow blob public access"
        else:
            results["analysis"] = "no storage accounts in use"

        return results




