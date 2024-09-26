import boto3
import logging

from utils.utils import describe_regions
from utils.utils import get_account_id

from datetime import date
from datetime import timedelta

class ecs(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)
        self.account_id = get_account_id(session)
        self.task_definitions = self.get_task_definitions()

    def run(self):
        findings = []
        findings += [ self.ecs_1() ]
        return findings

    def get_task_definitions(self):
        task_definitions = {}
        logging.info("getting task definitions")
        for region in self.regions:
            task_definitions[region] = []
            client = self.session.client('ecs', region_name=region)
            try:
                task_definition_arns = client.list_task_definitions()["taskDefinitionArns"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting task_definitions - %s" % e.response["Error"]["Code"])
            else:
                for arn in task_definition_arns:
                    task_definitions[region].append(client.describe_task_definition(taskDefinition=arn)["taskDefinition"])

        return task_definitions

    def ecs_1(self):
        # Amazon ECS task definitions should have secure networking modes and user definitions

        results = {
            "id" : "ecs_1",
            "ref" : "ECS.1",
            "compliance" : "FSBP",
            "level" : "N/A",
            "service" : "ecs",
            "name" : "Amazon ECS task definitions should have secure networking modes and user definitions",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether an active Amazon ECS task definition with host networking mode has privileged or user container definitions. The control fails for task definitions that have host network mode and container definitions of privileged=false, empty and user=root, or empty. This control only evaluates the latest active revision of an Amazon ECS task definition. The purpose of this control is to ensure that access is defined intentionally when you run tasks that use the host network mode. If a task definition has elevated privileges, it is because you have chosen that configuration. This control checks for unexpected privilege escalation when a task definition has host networking enabled, and you don't choose elevated privileges.",
            "remediation" : "For information about how to update a task definition, see Updating a task definition in the Amazon Elastic Container Service Developer Guide. When you update a task definition, it doesn't update running tasks that were launched from the previous task definition. To update a running task, you must redeploy the task with the new task definition.\nMore Information\nhttps://docs.aws.amazon.com/AmazonECS/latest/developerguide/update-task-definition.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, task_definitions in self.task_definitions.items():
                for task_definition in task_definitions:
                    print(task_definition)
                    #if task_definition["imageScanningConfiguration"]["scanOnPush"] == False:
                        #results["affected"].append("{} ({})".format(task_definition["task_definitionName"], region))


        if results["affected"]:
            results["analysis"] = ""
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No failing repositories found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

