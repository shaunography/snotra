import boto3
import logging

from utils.utils import describe_regions
from utils.utils import get_account_id

from datetime import date
from datetime import timedelta

class ecr(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)
        self.account_id = get_account_id(session)

    def run(self):
        findings = []
        findings += [ self.ecr_1() ]
        return findings
    
    def ecr_1(self):
        # ECR Image Scan on Push is not Enabled

        results = {
            "id" : "ecr_1",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "ecr",
            "name" : "ECR Image Scan on Push is not Enabled",
            "affected": [],
            "analysis" : "",
            "description" : "Amazon ECR image scanning helps in identifying software vulnerabilities in your container images. Amazon ECR uses the Common Vulnerabilities and Exposures (CVEs) database from the open source CoreOS Clair project and provides you with a list of scan findings. You can review the scan findings for information about the security of the container images that are being deployed. You can manually scan container images stored in Amazon ECR, or you can configure your repositories to scan images when you push them to a repository. The last completed image scan findings can be retrieved for each image. Amazon ECR sends an event to Amazon EventBridge (formerly called CloudWatch Events) When a new repository is configured to scan on push, all new images pushed to the repository will be scanned. Results from the last completed image scan can then be retrieved.",
            "remediation" : "Enable scan on push for all repositories in the affected account. More Information: https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html#scanning-repository",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region in self.regions:
            client = self.session.client('ecr', region_name=region)
            repositories = client.describe_repositories()["repositories"]
            for repository in repositories:
                if repository["imageScanningConfiguration"]["scanOnPush"] == False:
                    results["affected"].append(repository["repositoryName"])


        if results["affected"]:
            results["analysis"] = "The affected repositories do not have Scan On Push enabled"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No failing repositories found"
            results["pass_fail"] = "PASS"

        return results

