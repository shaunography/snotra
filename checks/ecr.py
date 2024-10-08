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
        self.repositories = self.get_repositories()

    def run(self):
        findings = []
        findings += [ self.ecr_1() ]
        findings += [ self.ecr_2() ]
        findings += [ self.ecr_3() ]
        return findings

    def get_repositories(self):
        repositories = {}
        logging.info("getting repositories")
        for region in self.regions:
            client = self.session.client('ecr', region_name=region)
            try:
                repositories[region] = client.describe_repositories()["repositories"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting repositories - %s" % e.response["Error"]["Code"])
        return repositories

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

        for region, repositories in self.repositories.items():
                for repository in repositories:
                    if repository["imageScanningConfiguration"]["scanOnPush"] == False:
                        results["affected"].append("{} ({})".format(repository["repositoryName"], region))


        if results["affected"]:
            results["analysis"] = "The affected repositories do not have Scan On Push enabled"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No failing repositories found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def ecr_2(self):
        # ECR repositories without a lifecycle policy

        results = {
            "id" : "ecr_2",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "ecr",
            "name" : "ECR Image Repositories Do Not Have a LifeCycle Policy Applied",
            "affected": [],
            "analysis" : "",
            "description" : "The affected Repositories do not have a Lifecycle policy, Amazon ECR repositories run the risk of retaining a larfe number of container images, resulting in unnecessary cost.",
            "remediation" : "It is recomended to review the affected repositories and apply a suitable lifecycle policy to minimise storage requirements and costs\nMore Information\nhttps://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, repositories in self.repositories.items():
            client = self.session.client('ecr', region_name=region)
            for repository in repositories:
                try:
                    lifecycle_policy = client.get_lifecycle_policy(repositoryName=repository["repositoryName"])["lifecyclePolicyText"]
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    if e.response["Error"]["Code"] == "LifecyclePolicyNotFoundException":
                        results["affected"].append("{} ({})".format(repository["repositoryName"], region))
                    else:
                        logging.error("Error getting lifecycle policy- %s" % e.response["Error"]["Code"])



        if results["affected"]:
            results["analysis"] = "The affected repositories do not have a life cycle policy"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No failing repositories found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def ecr_3(self):
        # ECR private repositories should have tag immutability configured

        results = {
            "id" : "ecr_3",
            "ref" : "ECR.2",
            "compliance" : "FSBP",
            "level" : "N/A",
            "service" : "ecr",
            "name" : "ECR private repositories should have tag immutability configured",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether a private ECR repository has tag immutability enabled. This control fails if a private ECR repository has tag immutability disabled. This rule passes if tag immutability is enabled and has the value IMMUTABLE. Amazon ECR Tag Immutability enables customers to rely on the descriptive tags of an image as a reliable mechanism to track and uniquely identify images. An immutable tag is static, which means each tag refers to a unique image. This improves reliability and scalability as the use of a static tag will always result in the same image being deployed. When configured, tag immutability prevents the tags from being overridden, which reduces the attack surface.",
            "remediation" : "To create a repository with immutable tags configured or to update the image tag mutability settings for an existing repository, see Image tag mutability in the Amazon Elastic Container Registry User Guide.\nMore Information\nhttps://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, repositories in self.repositories.items():
            for repository in repositories:
                if repository["imageTagMutability"] != "IMMUTABLE":
                    results["affected"].append("{} ({})".format(repository["repositoryName"], region))

        if results["affected"]:
            results["analysis"] = "The affected repositories do not have tag immutability enabled"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No failing repositories found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results
