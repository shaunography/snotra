from azure.mgmt.containerservice import ContainerServiceClient

import azure.core.exceptions as exceptions

import logging

class containerservice(object):

    def __init__(self, credential, subscriptions, resource_groups, resources):
        self.credential = credential
        self.subscriptions = subscriptions
        self.resource_groups = resource_groups
        self.resources = resources
        self.clusters = self.get_clusters()

    def get_clusters(self):
        clusters = {}
        for subscription, resource_groups in self.resources.items():
            results = {}
            client = ContainerServiceClient(credential=self.credential, subscription_id=subscription)
            for resource_group, resources in resource_groups.items():
                clusters_in_group = []
                for resource in resources:
                    if resource.type == "Microsoft.ContainerService/managedClusters":
                        logging.info(f'getting eks cluster { resource.name }')
                        try:
                            clusters_in_group.append(client.managed_clusters.get(resource_name=resource.name, resource_group_name=resource_group))
                        except Exception as e:
                            logging.error(f'error getting eks cluster: { resource.name }, error: { e }')
                if clusters_in_group:
                    results[resource_group] = clusters_in_group
            if results:
                clusters[subscription] = results
        return clusters

    def run(self):
        findings = []
        findings += [ self.containerservice_1() ]
        findings += [ self.containerservice_2() ]
        findings += [ self.containerservice_3() ]
        #findings += [ self.containerservice_4() ]
        return findings


    def containerservice_1(self):
        # Ensure that 'Public Network Access' is `Disabled' for EKS clusters

        results = {
            "id" : "containerservice_1",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "containerservice",
            "name" : "Ensure that 'Public Network Access' is `Disabled' for AKS Clusters",
            "affected": [],
            "analysis" : "",
            "description" : "The account being reviewed was found to contain an AKS cluster that doesn’t have any network level access restrictions in place and therefore allows unrestricted traffic from the public internet.\nMaster security In AKS, the Kubernetes master components are part of the managed service provided by Microsoft. Each AKS cluster has its own single-tenanted, dedicated Kubernetes master to provide the API Server, Scheduler, etc. This master is managed and maintained by Microsoft.\nBy default, the Kubernetes API server uses a public IP address and a fully qualified domain name (FQDN). You can limit access to the API server endpoint using authorized IP ranges. You can also create a fully private cluster to limit API server access to your virtual network. You can control access to the API server using Kubernetes role-based access control (Kubernetes RBAC) and Azure RBAC.\nAlthough protected with authentication to minimise the attack Surface of your account and provide greater defence in depth it is recommended to either use a private clusters that only permit access from internal Azure Virtual Networks and or configure a set of authorized IP ranges following the principle of least privilege and only allow access from trusted networks and IP addresses.",
            "remediation" : "Configure the affected Clusters to be Private and block public access from the internet, if internet access is required configure a set of authorized IP ranges following the principle of least privilege and only allow access from trusted IP addresses.",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "5.4",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, resource_groups in self.clusters.items():
            for resource_group, clusters in resource_groups.items():
                for cluster in clusters:
                    if cluster.public_network_access != "Disabled":
                        results["affected"].append(cluster.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected clusters allow public network access"
        elif self.clusters:
            results["analysis"] = "AKS clusters do not allow public network access"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no clusters found"

        return results

    def containerservice_2(self):
        # Outdated/Unsuported Version of Kubernetes In Use

        results = {
            "id" : "containerservice_2",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "containerservice",
            "name" : "Outdated/Unsuported Version of Kubernetes In Use",
            "affected": [],
            "analysis" : "",
            "description" : "The version of Azure Kubernetes Service (AKS) is out of date and no longer supported by Azure. As software packages often receive updates to fix bugs, add features and patch security vulnerabilities it is recommended that the Kubernetes version is patched to the latest stable version as soon as possible after each release. Outdated and unpatched clusters may enable an attacker to exploit known vulnerabilities to gain unauthorized access to the cluster, steal sensitive information, or launch a denial-of-service attack. The lack of security patches and updates also increased the risk of new vulnerabilities being discovered and exploited against the cluster in the future.",
            "remediation" : "The Kubernetes version should be updated to the most recent stable version, which at the time of the assessment was 1.25. (Note – 1.26 General Availability was due one month after the assessment was completed in Feb 2023).\nTo prevent software version issues from recurring, it is recommended that a centralised patch management process be implemented to ensure security fixes and patches are installed as they are released. This should include both the version of Kubernetes as well as the software versions of supporting containers and application images deployed within the cluster.  \nThe latest available versions of AKS can be found on the AKS documentation website. It is also important to consider the end-of-life (EOL) of a version before installing it and maintain versions that are still actively supported by Azure. Additionally, it is recommended to validate that any deployed addons and dependent services are compatible with the new version before deploying to production. \nMore Information \nAzure Kubernetes Service (AKS) documentation - https://docs.microsoft.com/en-us/azure/aks/ \nAzure Kubernetes Service (AKS) supported Kubernetes version - https://learn.microsoft.com/en-us/azure/aks/supported-kubernetes-versions?tabs=azure-cli \nAzure Kubernetes Service (AKS) release notes - https://github.com/Azure/AKS/releases \nAzure Kubernetes Service (AKS) upgrade guide - https://learn.microsoft.com/en-us/azure/aks/upgrade-cluster?tabs=azure-cli ",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "5.4",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, resource_groups in self.clusters.items():
            for resource_group, clusters in resource_groups.items():
                for cluster in clusters:
                    if cluster.current_kubernetes_version == "1.26" or cluster.current_kubernetes_version == "1.25":
                        results["affected"].append(cluster.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected clusters are running and out of date version (1.25, 1.26) of Kubernetes"
        elif self.clusters:
            results["analysis"] = "clusters are running an up to date version of Kubernetes"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no clusters found"

        return results

    def containerservice_3(self):
        # local accounts

        results = {
            "id" : "containerservice_3",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "containerservice",
            "name" : "Local Accounts",
            "affected": [],
            "analysis" : "",
            "description" : "Local account access is enabled on the affected clusters. When you deploy an AKS cluster, local accounts are enabled by default. Even when you enable RBAC or Microsoft Entra integration, --admin access still exists as a non-auditable backdoor option. It is recomended to remove all local account access and use Entra ID RBAC integraton.",
            "remediation" : "Disable local account cluster access.\nMore information:\nhttps://learn.microsoft.com/en-us/azure/aks/manage-local-accounts-managed-azure-ad",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "5.4",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, resource_groups in self.clusters.items():
            for resource_group, clusters in resource_groups.items():
                for cluster in clusters:
                    if cluster.disable_local_accounts != True:
                        results["affected"].append(cluster.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = "the affected clusters allow local kubernetes user accounts"
        elif self.clusters:
            results["analysis"] = "AKS clusters do not allow local accounts"
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no clusters found"

        return results

    def containerservice_4(self):
        # local accounts

        results = {
            "id" : "containerservice_3",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "containerservice",
            "name" : "RBAC??",
            "affected": [],
            "analysis" : "",
            "description" : "",
            "remediation" : "",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "5.4",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        for subscription, resource_groups in self.clusters.items():
            for resource_group, clusters in resource_groups.items():
                for cluster in clusters:
                    print("cluster")
                    print(cluster)
                    if cluster.enable_rbac != True: 
                        results["affected"].append(cluster.name)

        if results["affected"]:
            results["pass_fail"] = "FAIL"
            results["analysis"] = ""
        elif self.clusters:
            results["analysis"] = ""
            results["pass_fail"] = "PASS"
        else:
            results["analysis"] = "no clusters found"

        return results
