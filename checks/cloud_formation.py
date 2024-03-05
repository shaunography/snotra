import boto3
import json
import re
import logging

from utils.utils import get_account_id
from utils.utils import describe_regions

class cloud_formation(object):

    def __init__(self, session):
        self.session = session
        self.account_id = get_account_id(session)
        self.regions = describe_regions(session)
        self.stacks = self.get_stacks()

    def run(self):
        findings = []
        findings += [ self.cloud_formation_1() ]
        findings += [ self.cloud_formation_2() ]
        findings += [ self.cloud_formation_3() ]
        return findings

    def cis(self):
        findings = []
        return findings

    def get_stacks(self):
        # list stacks
        logging.info("Getting Stacks")
        stacks = {}
        for region in self.regions:
            client = self.session.client('cloudformation', region_name=region)
            try:
                stacks[region]= client.describe_stacks()["Stacks"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting stacks - %s" % e.response["Error"]["Code"])
        return stacks

    
    def cloud_formation_1(self):
        # CLoudFormation stack output (check for secrets)

        results = {
            "id" : "cloud_formation_1",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "cloudformation",
            "name" : "CloudFormation Stacks Output (Check For Secrets)",
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
        output = {}

        for region, stacks in self.stacks.items():
            for stack in stacks:
                try:
                    output[stack["StackName"]] = stack["Outputs"]
                except KeyError:
                    pass
                else:
                    results["affected"].append(stack["StackName"])

        if results["affected"]:
            results["analysis"] = output
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "Indexes are enabled in all regions"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results
    
    def cloud_formation_2(self):
        # CLoudFormation stacks without termination protection

        results = {
            "id" : "cloud_formation_2",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "cloudformation",
            "name" : "CloudFormation Stacks Do Not Have Termination Protection Enabled",
            "affected": [],
            "analysis" : "",
            "description" : "The affected Cloudformation stacks do not have termination protection enabled. Without termination protection critical cloudformation stacks can be accidently deleted resulting in potential loss of data integrity and availability",
            "remediation" : "Ensure termination protection is enabled for the cloudformation stacks.\nMore Informaiton\nhttps://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-protect-stacks.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, stacks in self.stacks.items():
            for stack in stacks:
                try:
                    parent_id = stack["ParentId"]
                except KeyError:
                    try:
                        termination_protection = stack["EnableTerminationProtection"]
                    except KeyError:
                        results["affected"].append("{} ({})". format(stack["StackName"], region))


        if results["affected"]:
            results["analysis"] = "The affected CloudFormation Stacks do not have termination protection enabled"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "All Stacks have termination protection enabled"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def cloud_formation_3(self):
        # Role passed to CloudFormation Stack

        results = {
            "id" : "cloud_formation_3",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "cloudformation",
            "name" : "Role Passed To CLoud Formation Stack",
            "affected": [],
            "analysis" : "",
            "description" : "Passing a role to CloudFormation stacks may result in privilege escalation because IAM users with privileges within the CloudFormation scope implicitly inherit the stack's role's permissions. Consequently, it should be ensured that the IAM privileges assigned to the stack's role follow the principle of least privilege.",
            "remediation" : "Review the affected roles and ensure the principal of least privilege has been applied",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        roles = []

        for region, stacks in self.stacks.items():
            for stack in stacks:
                try:
                    role_arn = stack["RoleARN"]
                except KeyError:
                    pass
                else:
                    roles.append(role_arn)
                    results["affected"].append("{} ({})". format(stack["StackName"], region))


        if results["affected"]:
            results["analysis"] = "The affected Stacks have an IAM Role assigned, review the following list of roles for potential shadow admin abuse and applying the principle of least privilege: {}".format(", ".join(set(roles)))
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "All Stacks have termination protection enabled"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results
