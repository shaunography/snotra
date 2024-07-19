import boto3
import json
import re
import logging

from utils.utils import get_account_id
from utils.utils import describe_regions

class organizations(object):

    def __init__(self, session):
        self.session = session
        #self.regions = describe_regions(session)
        self.client = self.get_client()
        self.tag_policies = self.list_tag_policies()
        self.account_id = get_account_id(session)

    def run(self):
        findings = []
        findings += [ self.organizations_1() ]
        findings += [ self.organizations_2() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.organizations_1() ]
        findings += [ self.organizations_2() ]
        return findings

    def list_tag_policies(self):
        logging.info("Getting Tag Policies")
        try:
            return self.client.list_policies(Filter="TAG_POLICY")["Policies"]
        except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting tag policies - %s" % e.response["Error"]["Code"])
                if e.response["Error"]["Code"] == "AccessDeniedException":
                    return "AccessDeniedException"

    #def list_tag_policies(self):
        #tag_policies = {}
        #logging.info("Getting Tag Policies")
        #for region in self.regions:
            #client = self.session.client('organizations', region_name=region)
            #try:
                #security_groups[region] = client.list_policies(Filter="TAG_POLICY")["Policies"]
            #except boto3.exceptions.botocore.exceptions.ClientError as e:
                #logging.error("Error getting tag policies - %s" % e.response["Error"]["Code"])
        #return tag_policies
    
    def get_client(self):
        # returns boto3 organizations client
        return self.session.client('organizations', region_name="global")

    def organizations_1(self):
        # Ensure Tag Policies are Enabled (CIS)

        results = {
            "id" : "organizations_1",
            "ref" : "2.3",
            "compliance" : "cis_compute",
            "level" : 1,
            "service" : "organizations",
            "name" : "Ensure Tag Policies are Enabled (CIS)",
            "affected": [],
            "analysis" : "",
            "description" : "Tag policies help you standardize tags on all tagged resources across your organization. You can use tag policies to define tag keys (including how they should be capitalized) and their allowed values.",
            "remediation" : "From the Console: You must sign in as an IAM user, assume an IAM role, or sign in as the root user (not recommended) in the organization’s management account.\n1. Login to AWS Organizations using https://console.aws.amazon.com/organizations/\n2. In the Left pane click on Policies\n3. Click on Tag policies\n4. Click on Enable Tag Policies\n5. The page is update with a list of the Available policies and the ability to create one.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        if not self.tag_policies:
            results["affected"].append(self.account_id)
            results["analysis"] = "No tag policies have been created"
            results["pass_fail"] = "FAIL"
        elif self.tag_policies == "AccessDeniedException":
            results["affected"].append(self.account_id)
            results["analysis"] = "AccessDeniedException"
            results["pass_fail"] = "INFO"

        return results
    
    def organizations_2(self):
        # Ensure an Organizational EC2 Tag Policy has been Created (CIS)

        results = {
            "id" : "organizations_2",
            "ref" : "2.4",
            "compliance" : "cis_compute",
            "level" : 1,
            "service" : "organizations",
            "name" : "Ensure an Organizational EC2 Tag Policy has been Created (CIS)(Manual)",
            "affected": [],
            "analysis" : "",
            "description" : "A tag policy enables you to define tag compliance rules to help you maintain consistency in the tags attached to your organization's resources. You can use an EC2 tag policy to enforce your tag strategy across all of your EC2 resources.",
            "remediation" : "From the Console: You must sign in as an IAM user, assume an IAM role, or sign in as the root user (not recommended) in the organization’s management account. To create a tag policy\n1. Login to the AWS Organizations using https://console.aws.amazon.com/organizations/\n2. Left hand side Click on Policies\n3. Under Support policy types click on Tag policies\n4. Under Available policies click on Create policy\n5. Enter policy name\n6. Enter policy description (Indicate this is the EC2 tag policy)\n7. For New tag key 1, specify the name of a tag key to add.\n8. For Tag key capitalization compliance select the box for Use the capitalization to enable this option mandating a specific capitalization for the tag key using this policy.\n9. For Resource types to enforce check the box for Prevent non-compliant operations for this tag\n10. Click on Specify resource types\n11. Expand EC2\n12. Select ec2:image, ec2:instance, ec2:reserved-instances\n13. Click Save changes\n14. Click Create policy",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "n/a",
            "cvss_score" : "n/a",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        if not self.tag_policies:
            results["affected"].append(self.account_id)
            results["analysis"] = "No tag policies have been created"
            results["pass_fail"] = "FAIL"
        elif self.tag_policies == "AccessDeniedException":
            results["affected"].append(self.account_id)
            results["analysis"] = "AccessDeniedException"
            results["pass_fail"] = "INFO"
        elif self.tag_policies:
            results["affected"].append(self.account_id)
            results["analysis"] = "Tag policies have been create please review to determine if a EC2 policy exists"
            results["pass_fail"] = "INFO"

        return results
