from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.resource import PolicyClient

import logging

class resource(object):

    def __init__(self, credential, subscription):
        self.credential = credential
        if subscription:
            self.subscriptions = [ i for i in self.get_subscriptions() if i.subscription_id == subscription ]
        else:
            self.subscriptions = self.get_subscriptions()
        self.resource_groups = self.get_resource_groups()
        self.resources = self.get_resources()
        self.deployments = self.get_deployments()
        self.policy_definitions = self.get_policy_definitions()
        self.policy_assignments = self.get_policy_assignments()

    def get_subscriptions(self):
        return list(SubscriptionClient(self.credential).subscriptions.list())

    def get_resource_groups(self):
        groups = {}
        for subscription in self.subscriptions:
            logging.info(f'getting resource groups in subscription: { subscription.display_name }')
            try:
                client= ResourceManagementClient(credential=self.credential, subscription_id=subscription.subscription_id)
                results = list(client.resource_groups.list())
            except Exception as e:
                logging.error(f'error getting resource groups in subscription: { subscription.display_name }, error: { e }')
            else:
                if results:
                    groups[subscription.subscription_id] = results
        return groups

    def get_resources(self):
        resources = {}

        for subscription in self.subscriptions:
            results = {}
            try:
                for group in self.resource_groups[subscription.subscription_id]:
                    logging.info(f'getting resources in resource group { group.name }')
                    try:
                        client = ResourceManagementClient(credential=self.credential, subscription_id=subscription.subscription_id)
                        response = list(client.resources.list_by_resource_group(group.name, expand = "createdTime,changedTime"))
                        if response:
                            results[group.name] = response
                    except Exception as e:
                        logging.error(f'error getting resources in resource group: { group.name }, error: { e }')
                if results:
                    resources[subscription.subscription_id] = results
            except KeyError:
                logging.error(f'error subscription { subscription.subscription_id } has no resource groups')

        return resources

    def get_policy_definitions(self):
        policy_definitions = {}
        for subscription in self.subscriptions:
            client = PolicyClient(credential=self.credential, subscription_id=subscription.subscription_id)
            try:
                policy_definitions[subscription.subscription_id] = client.policy_definitions.list()
            except Exception as e:
                logging.error(f'error getting policy_definitions: , error: { e }')
        return policy_definitions

    def get_policy_assignments(self):
        policy_assignments = {}
        for subscription in self.subscriptions:
            client = PolicyClient(credential=self.credential, subscription_id=subscription.subscription_id)
            try:
                policy_assignments[subscription.subscription_id] = client.policy_assignments.list()
            except exception as e:
                logging.error(f'error getting policy_assignments: , error: { e }')
        return policy_assignments

    def get_deployments(self):
        deployments = {}
        for subscription, resource_groups in self.resource_groups.items():
            results = {}
            client = ResourceManagementClient(credential=self.credential, subscription_id=subscription)
            for resource_group in resource_groups:
                logging.info(f'getting deployments in resource group: { resource_group.name }')
                try:
                    deployments_list = client.deployments.list_by_resource_group(resource_group.name)
                except exception as e:
                    logging.error(f'error getting deployments in resource group { resource_group.name }, error: { e }')
                else:
                    try:
                        deployments_list_extended = [ client.deployments.get(resource_group_name=resource_group.name, deployment_name=deployment.name) for deployment in deployments_list ]
                        if deployments_list_extended:
                            results[resource_group.name] = deployments_list_extended
                    except exception as e:
                        logging.error(f'error getting deployment { deployment.name }: , error: { e }')
            if results:
                deployments[subscription] = results

        return deployments

    def run(self):
        findings = []
        findings += [ self.resource_1() ]
        findings += [ self.resource_2() ]
        findings += [ self.resource_3() ]
        findings += [ self.resource_4() ]
        #findings += [ self.resource_5() ]
        #findings += [ self.resource_6() ]
        return findings


    def resource_1(self):
        # 

        results = {
            "id" : "resource_1",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "resource",
            "name" : "Resource Groups",
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

        results["analysis"] = self.resource_groups

        for subscription, groups in self.resource_groups.items():
            for group in groups:
                results["affected"].append(group.name)

        if results["analysis"]:
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "no resource groups found"


        return results

    def resource_2(self):
        # 

        results = {
            "id" : "resource_2",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "resource",
            "name" : "All Resources",
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

        results["analysis"] = self.resources

        for subscription, resource_groups in self.resources.items():
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    results["affected"].append(resource.name)

        if results["analysis"]:
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "no resources found"


        return results

    def resource_3(self):
        # 

        results = {
            "id" : "resource_3",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "resource",
            "name" : "Resource Types",
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

        results["analysis"]  = {}

        for subscription, resource_groups in self.resources.items():
            types = []
            for resource_group, resources in resource_groups.items():
                for resource in resources:
                    types.append(resource.type)

            results["analysis"][subscription] = list(set(types))

        if results["analysis"]:
            results["affected"] = [ i for i, v in results["analysis"].items() ]
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "no resources found"


        return results

    def resource_4(self):
        # Secrets in Resource Group Deployment History (Manual)(Review Analysis Section for Sensitive Data, Delete If None Found)

        results = {
            "id" : "resource_4",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "resource",
            "name" : "Secrets in Resource Group Deployment History (Manual)(Review Analysis Section for Sensitive Data)",
            "affected": [],
            "analysis" : "",
            "description" : "The account under review was found to contain clear text secrets in a resource groups deployment history. Resources deployed via ARM and ARM Templates are captures in the resource groups deployment history including any parameters configured during deployment. If any of these parameters contain sensitive information this could be exposed to users with read access to the resource group. Attackers with a foothold on the tenant could use this information to potentially pivot access azure resources or elevate privileges within Azure AD and or Azure RBAC.",
            "remediation" : "Minimise the use of parameters but when required “securestring“ should be used for all passwords and secrets.\nMore Information\nhttps://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/best-practices",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            "cvss_score" : "6.5",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["analysis"]  = {}

        for subscription, resource_groups in self.deployments.items():
            for resource_group, deployments in resource_groups.items():
                results["analysis"][resource_group] = {}
                for deployment in deployments:
                    results["analysis"][resource_group]["parameters"] = deployment.properties.parameters
                    results["analysis"][resource_group]["outputs"] = deployment.properties.outputs

        if results["analysis"]:
            results["affected"] = [ i for i, v in results["analysis"].items() ]
            results["pass_fail"] = "INFO"
        else:
            results["analysis"] = "no deployments found"

        return results

    def resource_5(self):
        # 

        results = {
            "id" : "resource_5",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "resource",
            "name" : "",
            "affected": [],
            "analysis" : "",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["analysis"]  = {}

        for subscription, policy_definitions in self.policy_definitions.items():
            for policy_definition in policy_definitions:
                print(policy_definition)

        #self.policy_assignments = self.get_policy_assignments()

        #if results["analysis"]:
            #results["affected"] = [ i for i, v in results["analysis"].items() ]
            #results["pass_fail"] = "INFO"
        #else:
            #results["analysis"] = "no deployments found"

        return results

    def resource_6(self):
        # 

        results = {
            "id" : "resource_6",
            "ref" : "snotra",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "resource",
            "name" : "",
            "affected": [],
            "analysis" : "",
            "description" : "",
            "remediation" : "",
            "impact" : "",
            "probability" : "",
            "cvss_vector" : "",
            "cvss_score" : "",
            "pass_fail" : ""
        }

        logging.info(results["name"]) 

        results["analysis"]  = {}

        for subscription, policy_assignments in self.policy_assignments.items():
            for policy_assignment in policy_assignments:
                print(policy_assignment)

        #self.policy_assignments = self.get_policy_assignments()

        #if results["analysis"]:
            #results["affected"] = [ i for i, v in results["analysis"].items() ]
            #results["pass_fail"] = "INFO"
        #else:
            #results["analysis"] = "no deployments found"

        return results
