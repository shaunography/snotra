import boto3
import json
import re
import logging

from utils.utils import get_account_id
from utils.utils import describe_regions

class code_build(object):

    def __init__(self, session):
        self.session = session
        self.account_id = get_account_id(session)
        self.regions = describe_regions(session)
        self.projects = self.list_projects()

    def run(self):
        findings = []
        findings += [ self.code_build_1() ]
        return findings

    def cis(self):
        findings = []
        return findings

    def list_projects(self):
        # list projects
        logging.info("Getting Projects")
        projects = {}
        for region in self.regions:
            client = self.session.client('codebuild', region_name=region)
            try:
                projects[region]= client.list_projects()["projects"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting projects - %s" % e.response["Error"]["Code"])
        return projects

    
    def code_build_1(self):
        # code build environment variables (check for secrets)

        results = {
            "id" : "codebuild_1",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "codebuild",
            "name" : "Codebuild Projects Environment Variables (Check For Secrets)",
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
        batch_projects= {}
        environment = {}

        for region, projects in self.projects.items():
            client = self.session.client('codebuild', region_name=region)
            if projects:
                try:
                    batch_projects = client.batch_get_projects(names=projects)["projects"]
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting batch projects - %s" % e.response["Error"]["Code"])
                else:
                    for project in batch_projects:
                        environment[project["name"]] = {}
                        environment[project["name"]]["environmentVariables"] = project["environment"]["environmentVariables"]
                        results["affected"].append(project["name"])

        if results["affected"]:
            results["analysis"] = json.dumps(environment)
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "Indexes are enabled in all regions"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results
    
