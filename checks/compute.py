from azure.mgmt.compute import ComputeManagementClient
from checks.resource import resource
import logging

from datetime import date
from datetime import datetime, timezone
from datetime import timedelta

class compute(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.resource_groups = resource_groups
        self.resources = resources
        self.virtual_machines = self.get_virtual_machines()
        self.disks = self.get_disks()
        self.snapshots = self.get_snapshots()
        self.virtual_machine_extensions = self.get_virtual_machine_extensions()

    def get_virtual_machines(self):
        virtual_machines = {}
        for subscription, resource_groups in self.resources.items():
            results = []
            client = ComputeManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.Compute/virtualMachines":
                        logging.info(f'getting virtual machine { resource.name }')
                        try:
                            virtual_machine = client.virtual_machines.get(vm_name=resource.name, resource_group_name=resource_group)
                            results.append(virtual_machine)
                        except Exception as e:
                            logging.error(f'error getting virtual machine: { resource.name }, error: { e }')

            if results:
                virtual_machines[subscription] = results
        return virtual_machines

    def get_virtual_machine_extensions(self):
        virtual_machine_extensions = {}
        for subscription, resource_groups in self.resources.items():
            results = {}
            client = ComputeManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.Compute/virtualMachines":
                        logging.info(f'getting virtual machine { resource.name }')
                        results[resource.name] = []
                        try:
                            extensions = client.virtual_machine_extensions.list(vm_name=resource.name, resource_group_name=resource_group)
                            for extension in extensions.value:
                                extention_details = client.virtual_machine_extensions.get(resource_group, resource.name, extension.name)
                                results[resource.name].append(extention_details)
                        except Exception as e:
                            logging.error(f'error getting virtual machine: { resource.name }, error: { e }')
            if results:
                virtual_machine_extensions[subscription] = results

        return virtual_machine_extensions

    def get_disks(self):
        disks = {}
        for subscription, resource_groups in self.resources.items():
            results = []
            client = ComputeManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.Compute/disks":
                        logging.info(f'getting disk { resource.name }')
                        try:
                            disk = client.disks.get(disk_name=resource.name, resource_group_name=resource_group)
                            results.append(disk)
                        except Exception as e:
                            logging.error(f'error getting disk: { resource.name }, error: { e }')
            if results:
                disks[subscription] = results
        return disks

    def get_snapshots(self):
        snapshots = {}
        for subscription, resource_groups in self.resources.items():
            results = []
            client = ComputeManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.Compute/snapshots":
                        logging.info(f'getting snapshot { resource.name }')
                        try:
                            snapshot = client.snapshots.get(snapshot_name=resource.name, resource_group_name=resource_group)
                            results.append(snapshot)
                        except Exception as e:
                            logging.error(f'error getting snapshot: { resource.name }, error: { e }')
            if results:
                snapshots[subscription] = results
        return snapshots

    def run(self):
        findings = []
        findings += [ self.compute_1() ]
        findings += [ self.compute_2() ]
        findings += [ self.compute_3() ]
        findings += [ self.compute_4() ]
        findings += [ self.compute_5() ]
        findings += [ self.compute_6() ]
        findings += [ self.compute_7() ]
        findings += [ self.compute_8() ]
        findings += [ self.compute_9() ]
        findings += [ self.compute_10() ]
        findings += [ self.compute_11() ]
        findings += [ self.compute_12() ]
        findings += [ self.compute_13() ]
        findings += [ self.compute_14() ]
        findings += [ self.compute_15() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.compute_1() ]
        return findings

    def compute_1(self):
        # 

        results = {
            "id" : "compute_1",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "compute",
            "name" : "Virtual Machines",
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

        results["analysis"] = self.virtual_machines

        if results["analysis"]:
            results["affected"] = [ i for i, v in results["analysis"].items() ]
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "no virtual machines found"
            results["pass_fail"] = "N/A"

        return results

    def compute_2(self):
        # Ensure Virtual Machines are utilizing Managed Disks (CIS)

        results = {
            "id" : "compute_2",
            "ref" : "7.2",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "compute",
            "name" : "Ensure Virtual Machines are utilizing Managed Disks (CIS)",
            "affected": [],
            "analysis" : {},
            "description" : "Migrate blob-based VHDs to Managed Disks on Virtual Machines to exploit the default features of this configuration. The features include: 1. Default Disk Encryption 2. Resilience, as Microsoft will managed the disk storage and move around if underlying hardware goes faulty 3. Reduction of costs over storage accounts Managed disks are by default encrypted on the underlying hardware, so no additional encryption is required for basic protection. It is available if additional encryption is required. Managed disks are by design more resilient that storage accounts. For ARM-deployed Virtual Machines, Azure Adviser will at some point recommend moving VHDs to managed disks both from a security and cost management perspective.",
            "remediation" : "From Azure Portal\n1. Using the search feature, go to Virtual Machines\n2. Select the virtual machine you would like to convert\n3. Select Disks in the menu for the VM\n4. At the top select Migrate to managed disks\n5. You may follow the prompts to convert the disk and finish by selecting Migrate to\nstart the process\nNOTE VMs will be stopped and restarted after migration is complete",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, virtual_machines in self.virtual_machines.items():
            for virtual_machine in virtual_machines:

                if not virtual_machine.storage_profile.os_disk.managed_disk:
                    results["affected"].append(virtual_machine.name)
                    results["analysis"][virtual_machine.name] = virtual_machine.storage_profile.os_disk.name

                for disk in virtual_machine.storage_profile.data_disks:
                    if not disk.managed_disk:
                        results["affected"].append(virtual_machine.name)
                        results["analysis"][virtual_machine.name] = disk.name

        if results["affected"]:
            results["affected"] = set(results["affected"])
            results["pass_fail"] = "FAIL"
        elif self.virtual_machines:
            results["analysis"] = "no unmanaged disks found"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no virtual machines in use"
            results["pass_fail"] = "N/A"

        return results

    def compute_3(self):
        # Ensure that 'OS and Data' disks are encrypted with Customer Managed Key (CMK) (CIS)

        results = {
            "id" : "compute_3",
            "ref" : "7.3",
            "compliance" : "cis_v2.1.0",
            "level" : 2,
            "service" : "compute",
            "name" : "Ensure that 'OS and Data' disks are encrypted with Customer Managed Key (CMK) (CIS)",
            "affected": [],
            "analysis" : {},
            "description" : "Ensure that OS disks (boot volumes) and data disks (non-boot volumes) are encrypted with CMK (Customer Managed Keys). Customer Managed keys can be either ADE or Server Side Encryption (SSE). Rationale: Encrypting the IaaS VM's OS disk (boot volume) and Data disks (non-boot volume) ensures that the entire content is fully unrecoverable without a key, thus protecting the volume from unwanted reads. PMK (Platform Managed Keys) are enabled by default in Azure-managed disks and allow encryption at rest. CMK is recommended because it gives the customer the option to control which specific keys are used for the encryption and decryption of the disk. The customer can then change keys and increase security by disabling them instead of relying on the PMK key that remains unchanging. There is also the option to increase security further by using automatically rotating keys so that access to disk is ensured to be limited. Organizations should evaluate what their security requirements are, however, for the data stored on the disk. For high-risk data using CMK is a must, as it provides extra steps of security. If the data is low risk, PMK is enabled by default and provides sufficient data security.",
            "remediation" : "From Azure Portal\nNote: Disks must be detached from VMs to have encryption changed.\n1. Go to Virtual machines\n2. For each virtual machine, go to Settings\n3. Click on Disks\n4. Click the ellipsis (...), then click Detach to detach the disk from the VM\n5. Now search for Disks and locate the unattached disk\n6. Click the disk then select Encryption\n7. Change your encryption type, then select your encryption set\n8. Click Save\n9. Go back to the VM and re-attach the disk",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, disks in self.disks.items():
            for disk in disks:
                if disk.encryption.type == "EncryptionAtRestWithPlatformKey":
                    results["affected"].append(disk.name)

        if results["affected"]:
            results["analysis"] = "the affected disks are not encrypted with a customer managed key (cmk)"
            results["pass_fail"] = "FAIL"
        elif self.disks:
            results["analysis"] = "disks are encrypted with customer managed keys"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no disks in use"
            results["pass_fail"] = "N/A"

        return results

    def compute_4(self):
        # unencrpyted disks

        results = {
            "id" : "compute_4",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "compute",
            "name" : "Unencrpyted Disks",
            "affected": [],
            "analysis" : {},
            "description" : "The subscription contains disks which are not encryted. Encrypting managed disks ensures that its entire content is fully unrecoverable without a key and thus protects the volume from unwarranted reads.Even if the disk is not attached to any of the VMs, there is always a risk where a compromised user account with administrative access to VM service can mount/attach these data disks, which may lead to sensitive information disclosure and tampering.",
            "remediation" : "Ensure all disks are encrypted, and consider using Customer Managed Keys (CMK) for additional security.",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, disks in self.disks.items():
            for disk in disks:
                if not disk.encryption:
                    results["affected"].append(disk.name)

        if results["affected"]:
            results["analysis"] = "the affected disks are not encrypted"
            results["pass_fail"] = "FAIL"
        elif self.disks:
            results["analysis"] = "no unencrypted disks found"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no disks in use"
            results["pass_fail"] = "N/A"

        return results

    def compute_5(self):
        # disks with public network access enabled

        results = {
            "id" : "compute_5",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "compute",
            "name" : "Disks With Public Network Access Enabled",
            "affected": [],
            "analysis" : {},
            "description" : "The subscription under review contained resources which did not implement network level access restrictions (Firewall rules) and therefore allowed unrestricted traffic from the public internet. This configuration impacted the security posture of the cloud environment and increased the risk of unauthorized data exposure.\nBy default resources in Azure do not implement a firewall to restrict network level access, therefore all users, applications, and services including those on the public internet could potentially communicate with resources  hosted within a subscription at the network layer. Although often protected by authentication, the lack of network restrictions increased the attack surface of the resources and the wider Azure environment. An attacker able to compromise valid credentials could use those credentials to interact with the service from clients on any network or from other Azure tenancies.",
            "remediation" : "The affected resources should be configured to restrict network access to the internal virtual private networks. Where external access is required for legitimate purposes, access should be restricted to a subset of whitelisted public IP addresses.\nAdditionally, where external access is not required, organisations should consider implementing a private endpoint connection to facilitate a secure connection between internal services whilst removing the requirement to use public infrastructure. When a private endpoint is configured all traffic between resources is transmitted over the Azure backbone ‘Azure PrivateLink’ network using virtual private IP addresses reducing the exposure of sensitive data.\nTo configure firewall rules within the Azure Portal:\n•	Go to resource.\n•	For each resource, click on the settings menu called ‘Networking’.\n•	Ensure that you have elected to allow access from Selected networks.\n•	Add rules to allow traffic from specific networks and IPs as required.\n•	Click Save to apply your changes.\n",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "5.4",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, disks in self.disks.items():
            for disk in disks:
                if disk.public_network_access != "Disabled":
                    results["affected"].append(disk.name)

        if results["affected"]:
            results["analysis"] = "the affected disks have public network access enabled"
            results["pass_fail"] = "FAIL"
        elif self.disks:
            results["analysis"] = "disks do not have public network access enabled"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no disks in use"
            results["pass_fail"] = "N/A"

        return results

    def compute_6(self):
        # unattached disks

        results = {
            "id" : "compute_6",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "compute",
            "name" : "Unattached Disks",
            "affected": [],
            "analysis" : {},
            "description" : "The account contains Virtual Machine Disks that are not attached to any resources and are therefore likely no longer required. To maintain the hygiene of your subscription, lower costs and reduce the risk  of sensitive data disclosure it is recommended that all unused virtual machine disks are deleted.",
            "remediation" : "Determine if the affect virtual disk is required and if not delete it.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, disks in self.disks.items():
            for disk in disks:
                if disk.disk_state == "Unattached":
                    results["affected"].append(disk.name)

        if results["affected"]:
            results["analysis"] = "the affected disks are not attached to any resources and are therfore not being used"
            results["pass_fail"] = "FAIL"
        elif self.disks:
            results["analysis"] = "no unattached disks found"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no disks in use"
            results["pass_fail"] = "N/A"

        return results

    def compute_7(self):
        # Ensure that 'Unattached disks' are encrypted with Customer Managed Key (CMK) (CIS)

        results = {
            "id" : "compute_7",
            "ref" : "7.4",
            "compliance" : "cis_v2.1.0",
            "level" : 2,
            "service" : "compute",
            "name" : "Ensure that 'Unattached disks' are encrypted with Customer Managed Key (CMK) (CIS)",
            "affected": [],
            "analysis" : {},
            "description" : "Ensure that unattached disks in a subscription are encrypted with a Customer Managed\nKey (CMK). Managed disks are encrypted by default with Platform-managed keys. Using Customer-managed keys may provide an additional level of security or meet an organization's\nregulatory requirements. Encrypting managed disks ensures that its entire content is\nfully unrecoverable without a key and thus protects the volume from unwarranted reads.\nEven if the disk is not attached to any of the VMs, there is always a risk where a\ncompromised user account with administrative access to VM service can mount/attach\nthese data disks, which may lead to sensitive information disclosure and tampering.",
            "remediation" : "If data stored in the disk is no longer useful, refer to Azure documentation to delete\nunattached data disks at:\n-https://docs.microsoft.com/en-us/rest/api/compute/disks/delete\n-https://docs.microsoft.com/en-us/cli/azure/disk?view=azure-cli-latest#az-\ndisk-delete\nIf data stored in the disk is important, To encrypt the disk refer azure documentation at:\n-https://docs.microsoft.com/en-us/azure/virtual-machines/disks-enable-\ncustomer-managed-keys-portal\n-https://docs.microsoft.com/en-\nus/rest/api/compute/disks/update#encryptionsettings",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, disks in self.disks.items():
            for disk in disks:
                if disk.disk_state == "Unattached":
                    if disk.encryption.type == "EncryptionAtRestWithPlatformKey":
                        results["affected"].append(disk.name)

        if results["affected"]:
            results["analysis"] = "the affected unattached disks are not encrypted with a customer managed key (cmk)"
            results["pass_fail"] = "FAIL"
        elif self.disks:
            results["analysis"] = "no encrypted unattached disks found"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no disks in use"
            results["pass_fail"] = "N/A"

        return results

    def compute_8(self):
        # Ensure that Only Approved Extensions Are Installed (CIS)

        results = {
            "id" : "compute_8",
            "ref" : "7.5",
            "compliance" : "cis_v2.1.0",
            "level" : 1,
            "service" : "compute",
            "name" : "Ensure that Only Approved Extensions Are Installed (CIS)",
            "affected": [],
            "analysis" : {},
            "description" : "For added security, only install organization-approved extensions on VMs. Azure virtual machine extensions are small applications that provide post-deployment configuration and automation tasks on Azure virtual machines. These extensions run with administrative privileges and could potentially access anything on a virtual machine. The Azure Portal and community provide several such extensions. Each organization should carefully evaluate these extensions and ensure that only those that are approved for use are actually implemented.",
            "remediation" : "From Azure Portal\n1. Go to Virtual machines\n2. For each virtual machine, go to Settings\n3. Click on Extensions + applications\n4. If there are unapproved extensions, uninstall them.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, virtual_machines in self.virtual_machine_extensions.items():
            for virtual_machine, extensions in virtual_machines.items():
                results["affected"].append(virtual_machine)
                results["analysis"][virtual_machine] = {}
                for extension in extensions:
                    results["analysis"][virtual_machine] = extension.name

        if results["affected"]:
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "no virtual machines in use"
            results["pass_fail"] = "N/A"

        return results


    def compute_9(self):
        # virtual machines with user data

        results = {
            "id" : "compute_9",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "compute",
            "name" : "Virtual Machines With User Data",
            "affected": [],
            "analysis" : {},
            "description" : "User data allows you to pass your own scripts or metadata to your virtual machine. This data can be viewed by Azure users and can be retrieved from the Azure Instance Metadata Service (IMDS). Therefore, user data should not be used to store secrets or sensitive data. This check simply lists the virtual machines that are using user data and the contents of said data. This list should be reviewed to ensure it does not contain sensitive information.",
            "remediation" : "Do not sotre secres or sensitive data in virtual machine user data.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, virtual_machines in self.virtual_machines.items():
            for virtual_machine in virtual_machines:
                if virtual_machine.user_data:
                    results["affected"].append(virtual_machine.name)
                    results["analysis"][virtual_machine.name] = virtual_machine.user_data


        if results["affected"]:
            results["pass_fail"] = "INFO"
        elif self.virtual_machines:
            results["analysis"] = "no user data found"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no virtual machines in use"
            results["pass_fail"] = "N/A"

        return results

    def compute_10(self):
        # Stopped Virtual Machines

        results = {
            "id" : "compute_10",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "compute",
            "name" : "Stopped Virtual Machines",
            "affected": [],
            "analysis" : "",
            "description" : "The subscription contains virtual machines which are in the stopped state. When you are logged in to the operating system of an Azure VM, you can issue a command to shut down the server. This will kick you out of the OS and stop all processes, but will maintain the allocated hardware (including the IP addresses currently assigned). If you find the VM in the Azure console, you’ll see the state listed as 'Stopped'. When a machine is in this state you are still being charged by the hour for this instance. The other way to stop your virtual machine is through Azure itself, whether that’s through the console, Powershell, or the Azure CLI. When you stop a VM through Azure, rather than through the OS, it goes into a 'Stopped (deallocated)' state. This means that any non-static public IPs will be released, but you’ll also stop paying for the VM’s compute costs. This is a great way to save money on your Azure costs when you don’t need those VMs running",
            "remediation" : "To reduce the cost of your environment review the list of stopped Virtual Machines and deallocate or delete them as required.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, resource_groups in self.resources.items():
            client = ComputeManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    if resource.type == "Microsoft.Compute/virtualMachines":
                        logging.info(f'getting instance view for virtual machine { resource.name }')
                        try:
                            instance_view = client.virtual_machines.instance_view(vm_name=resource.name, resource_group_name=resource_group)
                            for status in instance_view.statuses:
                                if status.code == "PowerState/stopped":
                                    results["affected"].append(resource.name)
                        except Exception as e:
                            logging.error(f'error getting instance view for virtual machine: { resource.name }, error: { e }')


        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected virtual machines are in a stopped but not deallocated state"
        elif self.virtual_machines:
            results["analysis"] = "no stopped virtual machines found"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no virtual machines in use"
            results["pass_fail"] = "N/A"

        return results

    def compute_11(self):
        # Snapshots with public network acces enabled

        results = {
            "id" : "compute_11",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "compute",
            "name" : "Snapshots With Public Network Access Enabled",
            "affected": [],
            "analysis" : "",
            "description" : "The subscription under review contained resources which did not implement network level access restrictions (Firewall rules) and therefore allowed unrestricted traffic from the public internet. This configuration impacted the security posture of the cloud environment and increased the risk of unauthorized data exposure.\nBy default resources in Azure do not implement a firewall to restrict network level access, therefore all users, applications, and services including those on the public internet could potentially communicate with resources  hosted within a subscription at the network layer. Although often protected by authentication, the lack of network restrictions increased the attack surface of the resources and the wider Azure environment. An attacker able to compromise valid credentials could use those credentials to interact with the service from clients on any network or from other Azure tenancies.",
            "remediation" : "The affected resources should be configured to restrict network access to the internal virtual private networks. Where external access is required for legitimate purposes, access should be restricted to a subset of whitelisted public IP addresses.\nAdditionally, where external access is not required, organisations should consider implementing a private endpoint connection to facilitate a secure connection between internal services whilst removing the requirement to use public infrastructure. When a private endpoint is configured all traffic between resources is transmitted over the Azure backbone ‘Azure PrivateLink’ network using virtual private IP addresses reducing the exposure of sensitive data.\nTo configure firewall rules within the Azure Portal:\n•	Go to resource.\n•	For each resource, click on the settings menu called ‘Networking’.\n•	Ensure that you have elected to allow access from Selected networks.\n•	Add rules to allow traffic from specific networks and IPs as required.\n•	Click Save to apply your changes.\n",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "5.4",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, snapshots in self.snapshots.items():
            for snapshot in snapshots:
                if snapshot.public_network_access != "Disabled":
                    results["affected"].append(snapshot.name)

        if results["affected"]:
            results["analysis"] = "the affected snapshots have public network access enabled"
            results["pass_fail"] = "FAIL"
        elif self.snapshots:
            results["analysis"] = "snapshots do not have public network access enabled"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no snapshots in use"
            results["pass_fail"] = "N/A"

        return results

    def compute_12(self):
        # Old Snapshots

        results = {
            "id" : "compute_12",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "compute",
            "name" : "Old Snapshots",
            "affected": [],
            "analysis" : "",
            "description" : "The account under review contains old Virtual Machine Disk snapshots. A snapshot is a read-only copy of a virtual machine disk. Each VM disk snapshot stored within your Azure cloud account is adding charges to your monthly bill, regardless whether the snapshot is being used or not. Deleting older snapshots do not affect the ability to restore the disk data from the later snapshots which allows you to keep just the necessary backup data and help lower your Azure cloud costs.",
            "remediation" : "Review the affected snapshots and delete any that are no longer required.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, snapshots in self.snapshots.items():
            for snapshot in snapshots:
                # get snapshots created more than 6 months ago
                if snapshot.time_created < (datetime.now(timezone.utc) - timedelta(days=183)):
                    results["affected"].append(snapshot.name)

        if results["affected"]:
            results["analysis"] = "the affected snapshots were created longer than 6 months ago"
            results["pass_fail"] = "FAIL"
        elif self.snapshots:
            results["analysis"] = "no old snapshots found"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no snapshots in use"
            results["pass_fail"] = "N/A"

        return results

    def compute_13(self):
        # unencrypted snapshots

        results = {
            "id" : "compute_13",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "compute",
            "name" : "Unencrypted Snapshots",
            "affected": [],
            "analysis" : "",
            "description" : "The subscription contains snapshots which are not encryted. Encrypting managed disks ensures that its entire content is fully unrecoverable without a key and thus protects the volume from unwarranted reads.Even if the disk is not attached to any of the VMs, there is always a risk where a compromised user account with administrative access to VM service can mount/attach these data disks, which may lead to sensitive information disclosure and tampering.",
            "remediation" : "ensure snapshots are encrypted.",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, snapshots in self.snapshots.items():
            for snapshot in snapshots:
                # get snapshots created more than 6 months ago
                if not snapshot.encryption:
                    results["affected"].append(snapshot.name)

        if results["affected"]:
            results["analysis"] = "the affected snapshots are not encrypted"
            results["pass_fail"] = "FAIL"
        elif self.snapshots:
            results["analysis"] = "snapshots are encrypted"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no snapshots in use"
            results["pass_fail"] = "N/A"

        return results

    def compute_14(self):
        # Ensure that snapshots are encrypted with Customer Managed Key (CMK) (CIS)

        results = {
            "id" : "compute_14",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "compute",
            "name" : "Ensure that snapshots are encrypted with Customer Managed Key (CMK) (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "The subscription contains disks which are not encryted. Managed disks are encrypted by default with Platform-managed keys. Using Customer-managed keys may provide an additional level of security or meet an organization's regulatory requirements. Encrypting managed disks ensures that its entire content is fully unrecoverable without a key and thus protects the volume from unwarranted reads.Even if the disk is not attached to any of the VMs, there is always a risk where a compromised user account with administrative access to VM service can mount/attach these data disks, which may lead to sensitive information disclosure and tampering.",
            "remediation" : "Ensure snapshots are encrypted.",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, snapshots in self.snapshots.items():
            for snapshot in snapshots:
                if snapshot.encryption.type == "EncryptionAtRestWithPlatformKey":
                    results["affected"].append(snapshot.name)

        if results["affected"]:
            results["analysis"] = "the affected snapshots are not encrypted with a customer managed key (cmk)"
            results["pass_fail"] = "FAIL"
        elif self.disks:
            results["analysis"] = "snapshot are encrypted with customer managed keys"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no disks in use"
            results["pass_fail"] = "N/A"

        return results

    def compute_15(self):
        # Key Based SSH Authentication Not Enforced

        results = {
            "id" : "compute_15",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "compute",
            "name" : "Key Based SSH Authentication Not Enforced",
            "affected": [],
            "analysis" : "",
            "description" : "The subscription under review contained Linux Virtual Machines which permitted password-based SSH authentication. This configuration increased the risk of malicious users gaining unauthorised access to hosts via password guessing attacks.\nPermitting password-based SSH authentication for access to hosts can be convenient for users, however the use of passwords increases the attack surface of the host and is a common target for attackers attempting to compromise infrastructure. Attackers can attempt to leverage password guessing attacks using techniques such as brute-force, dictionary, or password spraying methods – in which an attacker uses a list of known passwords against several hosts and services – in an effort to gain access to the host.",
            "remediation" : "It is recommended that key-based authentication is enforced as the default access method. Password-based SSH access should be disabled by updating the following elements within the SSH configuration file, which can be found in ‘/etc/ssh/sshd_config’:\nChallengeResponseAuthentication no \nPasswordAuthentication no \nUsePAM no \nIt is also recommended that the following lines are configured to ensure Root account access to hosts via SSH is also disabled: \nPermitRootLogin no \nPermitRootLogin prohibit-password \nWhere root access is required this should be provided after the login by adding administrators to the sudoers file, and enforcing password requirements for issuing the sudo command.  \nUsers who require access to the host should create strong, password-protected SSH key-pairs with the corresponding public key added to the host’s authorised key-file. In sensitive environments where the strongest authentication mechanisms are required certificate-based authentication should be considered. SSH certificates further secure the login process by using public key pairs, whilst also requiring an x.509 certificate to verify each key’s identity. The additional overhead of implementing certificates should be weighed against the sensitive of the infrastructure deployed within the environment.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, virtual_machines in self.virtual_machines.items():
            for virtual_machine in virtual_machines:
                try:
                    if virtual_machine.os_profile.linux_configuration:
                        if virtual_machine.os_profile.linux_configuration.disable_password_authentication == False:
                            results["affected"].append(virtual_machine.name)
                except AttributeError:
                    pass

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected virtual machines allow password based SSH authentication"
        elif self.virtual_machines:
            results["analysis"] = "virtual machines are using key based ssh authentication"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no virtual machines in use"
            results["pass_fail"] = "N/A"

        return results

    #def compute_10(self):
        ## Ensure Trusted Launch is enabled on Virtual Machines (CIS)
#
        #results = {
            #"id" : "compute_9",
            #"ref" : "7.9",
            #"compliance" : "cis_v2.1.0",
            #"level" : 1,
            #"service" : "compute",
            #"name" : "Ensure Trusted Launch is enabled on Virtual Machines (CIS)",
            #"affected": [],
            #"analysis" : "",
            #"description" : "When Secure Boot and vTPM are enabled together, they provide a strong foundation\nfor protecting your VM from boot attacks. For example, if an attacker attempts to replace\nthe bootloader with a malicious version, Secure Boot will prevent the VM from booting. If\nthe attacker is able to bypass Secure Boot and install a malicious bootloader, vTPM can\nbe used to detect the intrusion and alert you.\nRationale:\nSecure Boot and vTPM work together to protect your VM from a variety of boot attacks,\nincluding bootkits, rootkits, and firmware rootkits. Not enabling Trusted Launch in Azure\nVM can lead to increased vulnerability to rootkits and boot-level malware, reduced\nability to detect and prevent unauthorized changes to the boot process, and a potential\ncompromise of system integrity and data security.\nImpact:\nSecure Boot and vTPM are not currently supported for Azure Generation 1 VMs.\nIMPORTANT: Before enabling Secure Boot and vTPM on a Generation 2 VM which\ndoes not already have both enabled, it is highly recommended to create a restore point\nof the VM prior to remediation.",
            #"remediation" : "From Azure Portal\n1. Go to Virtual Machines\n2. For each VM, under Settings, click on Configuration on the left blade\n3. Under Security Type, select 'Trusted Launch Virtual Machines'\n4. Make sure Enable Secure Boot & Enable vTPM are checked\n5. Click on Apply.\nNote: Trusted launch on existing virtual machines (VMs) is currently not supported for\nAzure Generation 1 VMs",
            #"impact" : "info",
            #"probability" : "info",
            #"cvss_vector" : "N/A",
            #"cvss_score" : "N/A",
            #"pass_fail" : ""
        #}
#
        #logging.info(results["name"]) 
#
        #for subscription, resource_groups in self.resources.items():
            #client = ComputeManagementClient(credential=self.credential, subscription_id=subscription)
            #for resource_group, resources in resource_groups.items():
                #for resource in resources:
                    #if resource.type == "Microsoft.Compute/virtualMachines":
                        #logging.info(f'getting instance view for virtual machine { resource.name }')
                        #try:
                            #instance_view = client.virtual_machines.instance_view(vm_name=resource.name, resource_group_name=resource_group)
                            #for status in instance_view.statuses:
                                #print(status)
                        #except Exception as e:
                            #logging.error(f'error getting instance view for virtual machine: { resource.name }, error: { e }')
#
#
        #if results["affected"]:
            #results["pass_fail"] = "FAIL"
            #results["analysis"] = "the affected virtual machiones do not have trusted launch enabled"
        #elif self.virtual_machines:
            #results["analysis"] = "no virtual machines in use"
            #results["pass_fail"] = "PASS"
        #else:
            #results["analysis"] = "all virtual machines have trusted launch enabled"
#
        #return results
