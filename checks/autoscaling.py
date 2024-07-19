import boto3
import logging
import json

from utils.utils import describe_regions
from utils.utils import get_account_id

from datetime import date
from datetime import timedelta

class autoscaling(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)
        self.account_id = get_account_id(session)
        self.auto_scaling_groups = self.get_auto_scaling_groups()

    def run(self):
        findings = []
        findings += [ self.autoscaling_1() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.autoscaling_1() ]
        return findings

    def get_auto_scaling_groups(self):
        auto_scaling_groups = {}
        logging.info("getting auto scaling groups")
        for region in self.regions:
            client = self.session.client('autoscaling', region_name=region)
            try:
                auto_scaling_groups[region] = client.describe_auto_scaling_groups()["AutoScalingGroups"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting auto scaling groups - %s" % e.response["Error"]["Code"])
        return auto_scaling_groups
    

    def autoscaling_1(self):
        # Ensure EC2 Auto Scaling Groups Propagate Tags to EC2 Instances that it launches (CIS)

        results = {
            "id" : "autoscaling_1",
            "ref" : "2.14",
            "compliance" : "cis_compute",
            "level" : 1,
            "service" : "autoscaling",
            "name" : "Ensure EC2 Auto Scaling Groups Propagate Tags to EC2 Instances that it launches (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Tags can help with managing, identifying, organizing, searching for, and filtering resources. Additionally, tags can help with security and compliance. Tags can be propagated from an Auto Scaling group to the EC2 instances that it launches. Without tags, EC2 instances created via Auto Scaling can be without tags and could be out of compliance with security policy.",
            "remediation" : "AWS Console\n1. Login to AWS Console using https://console.aws.amazon.com\n2. Click All services and click EC2 under Compute.\n3. Select Auto Scaling Groups.\n4. Click Edit for each Auto Scaling Group.\n5. Check the Tag new instances Box for the Auto Scaling Group.\n6. Click Update.\n7. Repeat Steps 1-6 for each AWS Region used",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, groups in self.auto_scaling_groups.items():
            for group in groups:
                for tag in group["Tags"]:
                    if tag["PropagateAtLaunch"] == False:
                        results["affected"].append("{}({})".format(group["AutoScalingGroupName"], region))

        if results["affected"]:
            results["analysis"] = "The affected auto scaling groups do not propogate tags to launched instances"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No failing auto scaling groups found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results


