import boto3
import json
import re
import logging

from utils.utils import get_account_id
from utils.utils import describe_regions

class ssm(object):

    def __init__(self, session):
        self.session = session
        self.account_id = get_account_id(session)
        self.regions = describe_regions(session)
        self.parameters = self.get_parameters()

    def run(self):
        findings = []
        findings += [ self.ssm_1() ]
        return findings

    def cis(self):
        findings = []
        return findings

    def get_parameters(self):
        # list parameters
        logging.info("Getting Parameters")
        parameters = {}
        for region in self.regions:
            client = self.session.client('ssm', region_name=region)
            try:
                parameters[region]= client.describe_parameters()["Parameters"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting parameters - %s" % e.response["Error"]["Code"])
        return parameters

    
    def ssm_1(self):
        # ssm parameter store parameters (check for secrets)

        results = {
            "id" : "ssm_1",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "ssm",
            "name" : "SSM Parameter Store Parameters (Check For Secrets)",
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
        parameter_values = {}

        for region, parameters in self.parameters.items():
            client = self.session.client('ssm', region_name=region)
            for parameter in parameters:
                try:
                    parameter_values[parameter["Name"]] = client.get_parameter(Name=parameter["Name"])["Parameter"]
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting parameter - %s" % e.response["Error"]["Code"])
                else:
                    results["affected"].append(parameter["Name"])

        if results["affected"]:

            output_json = {}
            for name, values in parameter_values.items():
                output_json[name] = {}
                output_json[name]["type"] = values["Type"]
                output_json[name]["value"] = values["Value"]

            results["analysis"] = json.dumps(output_json)
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No parameters found"
            results["pass_fail"] = "PASS"

        return results
    
