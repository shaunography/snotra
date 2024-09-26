import boto3
import json
import re
import logging

from utils.utils import get_account_id
from utils.utils import describe_regions

class cloudfront(object):

    def __init__(self, session):
        self.session = session
        self.account_id = get_account_id(session)
        self.regions = describe_regions(session)
        self.distributions = self.get_distributions()

    def run(self):
        findings = []
        findings += [ self.cloudfront_1() ]
        findings += [ self.cloudfront_2() ]
        findings += [ self.cloudfront_3() ]
        findings += [ self.cloudfront_4() ]
        findings += [ self.cloudfront_5() ]
        findings += [ self.cloudfront_6() ]
        findings += [ self.cloudfront_7() ]
        findings += [ self.cloudfront_8() ]
        findings += [ self.cloudfront_9() ]
        findings += [ self.cloudfront_10() ]
        findings += [ self.cloudfront_11() ]
        findings += [ self.cloudfront_12() ]
        return findings

    def cis(self):
        findings = []
        return findings

    def get_distributions(self):
        # list distrbutions
        logging.info("Getting Distributions")
        client = self.session.client('cloudfront')
        distributions = []
        distributions_details = []

        try:
            current_distributions = client.list_distributions()["DistributionList"]
        except boto3.exceptions.botocore.exceptions.ClientError as e:
            logging.error("Error getting distributions - %s" % e.response["Error"]["Code"])
        except boto3.exceptions.botocore.exceptions.EndpointConnectionError:
            logging.error("Error getting distributions - EndpointConnectionError")
        else:
            for i in current_distributions["Items"]:
                distributions.append(i)
            is_truncated = current_distributions["IsTruncated"]
            while is_truncated == True:
                try:
                    current_distributions = self.client.list_distributions(Scope="AWS", Marker=current_distributions["Marker"])
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting distributions - %s" % e.response["Error"]["Code"])
                except boto3.exceptions.botocore.exceptions.EndpointConnectionError:
                    logging.error("Error getting distributions - EndpointConnectionError")
                else:
                    for i in current_distributions["Items"]:
                        distributions.append(i)
                    is_truncated = current_distributions["IsTruncated"]

            try:
                for distribution in distributions:
                    distributions_details.append(client.get_distribution(Id=distribution["Id"])["Distribution"])
                        
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting distribution - %s" % e.response["Error"]["Code"])
            except boto3.exceptions.botocore.exceptions.EndpointConnectionError:
                logging.error("Error getting distributions - EndpointConnectionError")

        return distributions_details

    def check_bucket(self, bucket_name):
        client =  self.session.client('s3')
        try:
            client.head_bucket(Bucket=bucket_name)
            return True
        except boto3.exceptions.botocore.exceptions.ClientError as e:
            error_code = int(e.response['Error']['Code'])
            if error_code == 403:
                # Private Bucket
                return True
            elif error_code == 404:
                # does not exist
                return False
        except boto3.exceptions.botocore.exceptions.EndpointConnectionError:
            logging.error("Error checking bucket - EndpointConnectionError")

    def cloudfront_1(self):
        # CloudFront distributions should have a default root object configured

        results = {
            "id" : "cloudfront_1",
            "ref" : "CloudFront.1",
            "compliance" : "FSPB",
            "level" : "N/A",
            "service" : "cloudfront",
            "name" : "CloudFront distributions should have a default root object configured",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether an Amazon CloudFront distribution is configured to return a specific object that is the default root object. The control fails if the CloudFront distribution does not have a default root object configured. A user might sometimes request the distribution's root URL instead of an object in the distribution. When this happens, specifying a default root object can help you to avoid exposing the contents of your web distribution.",
            "remediation" : "To configure a default root object for a CloudFront distribution, see How to specify a default root object in the Amazon CloudFront Developer Guide.\nMore Information\nhttps://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/DefaultRootObject.html#DefaultRootObjectHowToDefine",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for distribution in self.distributions:
            try:
                if not distribution["DistributionConfig"]["DefaultRootObject"]:
                    results["affected"].append(distribution["Id"])
            except KeyError:
                pass


        if results["affected"]:
            results["analysis"] = "The affected cloudfront distributions do not have a default root object configured"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "no issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results
    
    def cloudfront_2(self):
        # CloudFront distributions should require encryption in transit

        results = {
            "id" : "cloudfront_2",
            "ref" : "CloudFront.3",
            "compliance" : "FSPB",
            "level" : "N/A",
            "service" : "cloudfront",
            "name" : "CloudFront distributions should require encryption in transit",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether an Amazon CloudFront distribution requires viewers to use HTTPS directly or whether it uses redirection. The control fails if ViewerProtocolPolicy is set to allow-all for defaultCacheBehavior or for cacheBehaviors. HTTPS (TLS) can be used to help prevent potential attackers from using person-in-the-middle or similar attacks to eavesdrop on or manipulate network traffic. Only encrypted connections over HTTPS (TLS) should be allowed. Encrypting data in transit can affect performance. You should test your application with this feature to understand the performance profile and the impact of TLS.",
            "remediation" : "To encrypt a CloudFront distribution in transit, see Requiring HTTPS for communication between viewers and CloudFront in the Amazon CloudFront Developer Guide.\nMore Information\nhttps://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-viewers-to-cloudfront.html",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for distribution in self.distributions:
            try:
                if distribution["DistributionConfig"]["DefaultCacheBehavior"]["ViewerProtocolPolicy"] == "allow-all":
                    results["affected"].append(distribution["Id"])
            except KeyError:
                pass

            try:
                for item in distribution["DistributionConfig"]["CacheBehaviors"]["Items"]:
                    if item["ViewerProtocolPolicy"] == "allow-all":
                        results["affected"].append(distribution["Id"])
            except KeyError:
                pass

        if results["affected"]:
            results["analysis"] = "The affected distrbution IDs do not enforce encryption in transit."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def cloudfront_3(self):
        # CloudFront distributions should have origin failover configured

        results = {
            "id" : "cloudfront_3",
            "ref" : "CloudFront.4",
            "compliance" : "FSPB",
            "level" : "N/A",
            "service" : "cloudfront",
            "name" : "CloudFront distributions should have origin failover configured",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether an Amazon CloudFront distribution is configured with an origin group that has two or more origins. CloudFront origin failover can increase availability. Origin failover automatically redirects traffic to a secondary origin if the primary origin is unavailable or if it returns specific HTTP response status codes.",
            "remediation" : "To configure origin failover for a CloudFront distribution, see Creating an origin group in the Amazon CloudFront Developer Guide.\nMore Information\nhttps://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/high_availability_origin_failover.html#concept_origin_groups.creating",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for distribution in self.distributions:
            try:
                if distribution["DistributionConfig"]["OriginGroups"]["Quantity"] == 0:
                    results["affected"].append(distribution["Id"])
            except KeyError:
                pass


        if results["affected"]:
            results["analysis"] = "The affected distribution IDs do not have an origin groups configured."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def cloudfront_4(self):
        # CloudFront distributions should have logging enabled

        results = {
            "id" : "cloudfront_4",
            "ref" : "CloudFront.5",
            "compliance" : "FSPB",
            "level" : "N/A",
            "service" : "cloudfront",
            "name" : "CloudFront distributions should have logging enabled",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether server access logging is enabled on CloudFront distributions. The control fails if access logging is not enabled for a distribution. CloudFront access logs provide detailed information about every user request that CloudFront receives. Each log contains information such as the date and time the request was received, the IP address of the viewer that made the request, the source of the request, and the port number of the request from the viewer. These logs are useful for applications such as security and access audits and forensics investigation. For additional guidance on how to analyze access logs, see Querying Amazon CloudFront logs in the Amazon Athena User Guide.",
            "remediation" : "To configure access logging for a CloudFront distribution, see Configuring and using standard logs (access logs) in the Amazon CloudFront Developer Guide.\nMore Information\nhttps://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for distribution in self.distributions:
            try:
                if distribution["DistributionConfig"]["Logging"]["Enabled"] == False:
                    results["affected"].append(distribution["Id"])
            except KeyError:
                pass


        if results["affected"]:
            results["analysis"] = "The affected distribution ids do not have logging enabled"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def cloudfront_5(self):
        # CloudFront distributions should have WAF enabled

        results = {
            "id" : "cloudfront_5",
            "ref" : "CloudFront.6",
            "compliance" : "FSPB",
            "level" : "N/A",
            "service" : "cloudfront",
            "name" : "CloudFront distributions should have WAF enabled",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether CloudFront distributions are associated with either AWS WAF Classic or AWS WAF web ACLs. The control fails if the distribution is not associated with a web ACL. AWS WAF is a web application firewall that helps protect web applications and APIs from attacks. It allows you to configure a set of rules, called a web access control list (web ACL), that allow, block, or count web requests based on customizable web security rules and conditions that you define. Ensure your CloudFront distribution is associated with an AWS WAF web ACL to help protect it from malicious attacks.",
            "remediation" : "To associate an AWS WAF web ACL with a CloudFront distribution, see Using AWS WAF to control access to your content in the Amazon CloudFront Developer Guide.\nMore Information\nhttps://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-awswaf.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for distribution in self.distributions:
            try:
                if not distribution["DistributionConfig"]["WebACLId"]:
                    results["affected"].append(distribution["Id"])
            except KeyError:
                pass


        if results["affected"]:
            results["analysis"] = "The affected distribution ids do not have logging enabled"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def cloudfront_6(self):
        # CloudFront distributions should use custom SSL/TLS certificates

        results = {
            "id" : "cloudfront_6",
            "ref" : "CloudFront.7",
            "compliance" : "FSPB",
            "level" : "N/A",
            "service" : "cloudfront",
            "name" : "CloudFront distributions should use custom SSL/TLS certificates",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether CloudFront distributions are using the default SSL/TLS certificate CloudFront provides. This control passes if the CloudFront distribution uses a custom SSL/TLS certificate. This control fails if the CloudFront distribution uses the default SSL/TLS certificate. Custom SSL/TLS allow your users to access content by using alternate domain names. You can store custom certificates in AWS Certificate Manager (recommended), or in IAM.",
            "remediation" : "To add an alternate domain name for a CloudFront distribution using a custom SSL/TLS certificate, see Adding an alternate domain name in the Amazon CloudFront Developer Guide.\nMore Information\nhttps://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/CNAMEs.html#CreatingCNAME",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for distribution in self.distributions:
            try:
                if distribution["DistributionConfig"]["ViewerCertificate"]["CloudFrontDefaultCertificate"] == True:
                    results["affected"].append(distribution["Id"])
            except KeyError:
                pass


        if results["affected"]:
            results["analysis"] = "The affected distribution ids are using a default cloudfront certificate"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def cloudfront_7(self):
        # CloudFront distributions should use SNI to serve HTTPS requests

        results = {
            "id" : "cloudfront_7",
            "ref" : "CloudFront.8",
            "compliance" : "FSPB",
            "level" : "N/A",
            "service" : "cloudfront",
            "name" : "CloudFront distributions should use SNI to serve HTTPS requests",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks if Amazon CloudFront distributions are using a custom SSL/TLS certificate and are configured to use SNI to serve HTTPS requests. This control fails if a custom SSL/TLS certificate is associated but the SSL/TLS support method is a dedicated IP address. Server Name Indication (SNI) is an extension to the TLS protocol that is supported by browsers and clients released after 2010. If you configure CloudFront to serve HTTPS requests using SNI, CloudFront associates your alternate domain name with an IP address for each edge location. When a viewer submits an HTTPS request for your content, DNS routes the request to the IP address for the correct edge location. The IP address to your domain name is determined during the SSL/TLS handshake negotiation; the IP address isn't dedicated to your distribution.",
            "remediation" : "To configure a CloudFront distribution to use SNI to serve HTTPS requests, see Using SNI to Serve HTTPS Requests (works for Most Clients) in the CloudFront Developer Guide.\nMore Information\nhttps://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cnames-https-dedicated-ip-or-sni.html#cnames-https-sni",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for distribution in self.distributions:
            try:
                if distribution["DistributionConfig"]["ViewerCertificate"]["SSLSupportMethod"] != "sni-only":
                    results["affected"].append(distribution["Id"])
            except KeyError:
                pass

        if results["affected"]:
            results["analysis"] = "The affected distribution ids are not enforcing the use of SNI"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def cloudfront_8(self):
        # CloudFront distributions should encrypt traffic to custom origins

        results = {
            "id" : "cloudfront_8",
            "ref" : "CloudFront.9",
            "compliance" : "FSPB",
            "level" : "N/A",
            "service" : "cloudfront",
            "name" : "CloudFront distributions should encrypt traffic to custom origins",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks if Amazon CloudFront distributions are encrypting traffic to custom origins. This control fails for a CloudFront distribution whose origin protocol policy allows 'http-only'. This control also fails if the distribution's origin protocol policy is 'match-viewer' while the viewer protocol policy is 'allow-all'. HTTPS (TLS) can be used to help prevent eavesdropping or manipulation of network traffic. Only encrypted connections over HTTPS (TLS) should be allowed.",
            "remediation" : "To update the Origin Protocol Policy to require encryption for a CloudFront connection, see Requiring HTTPS for communication between CloudFront and your custom origin in the Amazon CloudFront Developer Guide.\nMore Information\nhttps://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-custom-origin.html",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        affected_ids = []

        for distribution in self.distributions:
            try:
                for origin in distribution["DistributionConfig"]["Origins"]["Items"]:
                    if origin["CustomOriginConfig"]["OriginProtocolPolicy"] != "https-only":
                        affected_ids.append(distribution["Id"])
            except KeyError:
                pass

        results["affected"] = list(set(affected_ids))

        if results["affected"]:
            results["analysis"] = "The affected distribution ids have an origin that does not encrypt traffic to custom origins"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def cloudfront_9(self):
        # CloudFront distributions should not use deprecated SSL protocols between edge locations and custom origins

        results = {
            "id" : "cloudfront_9",
            "ref" : "CloudFront.9",
            "compliance" : "FSPB",
            "level" : "N/A",
            "service" : "cloudfront",
            "name" : "CloudFront distributions should not use deprecated SSL protocols between edge locations and custom origins",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks if Amazon CloudFront distributions are using deprecated SSL protocols for HTTPS communication between CloudFront edge locations and your custom origins. This control fails if a CloudFront distribution has a CustomOriginConfig where OriginSslProtocols includes SSLv3. In 2015, the Internet Engineering Task Force (IETF) officially announced that SSL 3.0 should be deprecated due to the protocol being insufficiently secure. It is recommended that you use TLSv1.2 or later for HTTPS communication to your custom origins.",
            "remediation" : "To update the Origin SSL Protocols for a CloudFront distribution, see Requiring HTTPS for communication between CloudFront and your custom origin in the Amazon CloudFront Developer Guide.\nMore Information\nhttps://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-custom-origin.html",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        affected_ids = []

        for distribution in self.distributions:
            try:
                for origin in distribution["DistributionConfig"]["Origins"]["Items"]:
                    protocols = origin["CustomOriginConfig"]["OriginSslProtocols"]["Items"]
                    if "SSLv3" in protocols:
                        affected_ids.append(distribution["Id"])
                    if "TLSv1" in protocols:
                        affected_ids.append(distribution["Id"])
                    if "TLSv1.1" in protocols:
                        affected_ids.append(distribution["Id"])
            except KeyError:
                pass

        results["affected"] = list(set(affected_ids))

        if results["affected"]:
            results["analysis"] = "The affected distribution ids have an origin that does not use the latest and most secure versions of TLS"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def cloudfront_10(self):
        # CloudFront distributions should not point to non-existent S3 origins

        results = {
            "id" : "cloudfront_10",
            "ref" : "CloudFront.12",
            "compliance" : "FSPB",
            "level" : "N/A",
            "service" : "cloudfront",
            "name" : "CloudFront distributions should not point to non-existent S3 origins",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether Amazon CloudFront distributions are pointing to non-existent Amazon S3 origins. The control fails for a CloudFront distribution if the origin is configured to point to a non-existent bucket. This control only applies to CloudFront distributions where an S3 bucket without static website hosting is the S3 origin. When a CloudFront distribution in your account is configured to point to a non-existent bucket, a malicious third party can create the referenced bucket and serve their own content through your distribution. We recommend checking all origins regardless of routing behavior to ensure that your distributions are pointing to appropriate origins.",
            "remediation" : "To modify a CloudFront distribution to point to a new origin, see Updating a distribution in the Amazon CloudFront Developer Guide.\nMore Information\nhttps://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/HowToUpdateDistribution.html",
            "impact" : "high",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cvss_score" : "7.4",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        affected_ids = []

        for distribution in self.distributions:
            try:
                for origin in distribution["DistributionConfig"]["Origins"]["Items"]:
                    if origin["S3OriginConfig"]:
                        try:
                            bucket = re.match("([a-z-.]+)\.s3\.amazonaws\.com", origin["DomainName"]).groups()[0]
                        except AttributeError:
                            pass
                        try:
                            bucket = re.match("([a-z-.]+)\.s3\..*amazonaws\.com", origin["DomainName"]).groups()[0]
                        except AttributeError:
                            pass
                        if not self.check_bucket(bucket):
                            affected_ids.append(distribution["Id"])
            except KeyError:
                pass

        results["affected"] = list(set(affected_ids))

        if results["affected"]:
            results["analysis"] = "The affected distribution ids are using an S3 origin that is pointint to a non existent S3 bucket"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def cloudfront_11(self):
        # CloudFront distributions should use origin access control

        results = {
            "id" : "cloudfront_11",
            "ref" : "CloudFront.13",
            "compliance" : "FSPB",
            "level" : "N/A",
            "service" : "cloudfront",
            "name" : "CloudFront distributions should use origin access control",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether an Amazon CloudFront distribution with an Amazon S3 origin has origin access control (OAC) configured. The control fails if OAC isn't configured for the CloudFront distribution. When using an S3 bucket as an origin for your CloudFront distribution, you can enable OAC. This permits access to the content in the bucket only through the specified CloudFront distribution, and prohibits access directly from the bucket or another distribution. Although CloudFront supports Origin Access Identity (OAI), OAC offers additional functionality, and distributions using OAI can migrate to OAC. While OAI provides a secure way to access S3 origins, it has limitations, such as lack of support for granular policy configurations and for HTTP/HTTPS requests that use the POST method in AWS Regions that require AWS Signature Version 4 (SigV4). OAI also doesn't support encryption with AWS Key Management Service. OAC is based on an AWS best practice of using IAM service principals to authenticate with S3 origins.",
            "remediation" : "To configure OAC for a CloudFront distribution with S3 origins, see Restricting access to an Amazon S3 origin in the Amazon CloudFront Developer Guide.\nMore Information\nhttps://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        affected_ids = []

        for distribution in self.distributions:
            try:
                for origin in distribution["DistributionConfig"]["Origins"]["Items"]:
                    if origin["S3OriginConfig"]:
                        if not origin["OriginAccessControlId"]:
                            affected_ids.append(distribution["Id"])
            except KeyError:
                pass

        results["affected"] = list(set(affected_ids))

        if results["affected"]:
            results["analysis"] = "The affected distribution ids does not have s3 origin access control configured"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results

    def cloudfront_12(self):
        # CloudFront distributions should be tagged

        results = {
            "id" : "cloudfront_12",
            "ref" : "CloudFront.14",
            "compliance" : "FSPB",
            "level" : "N/A",
            "service" : "cloudfront",
            "name" : "CloudFront distributions should be tagged",
            "affected": [],
            "analysis" : "",
            "description" : "This control checks whether an Amazon CloudFront distribution has tags with the specific keys defined in the parameter requiredTagKeys. The control fails if the distribution doesn’t have any tag keys or if it doesn’t have all the keys specified in the parameter requiredTagKeys. If the parameter requiredTagKeys isn't provided, the control only checks for the existence of a tag key and fails if the distribution isn't tagged with any key. System tags, which are automatically applied and begin with aws:, are ignored. A tag is a label that you assign to an AWS resource, and it consists of a key and an optional value. You can create tags to categorize resources by purpose, owner, environment, or other criteria. Tags can help you identify, organize, search for, and filter resources. Tagging also helps you track accountable resource owners for actions and notifications. When you use tagging, you can implement attribute-based access control (ABAC) as an authorization strategy, which defines permissions based on tags. You can attach tags to IAM entities (users or roles) and to AWS resources. You can create a single ABAC policy or a separate set of policies for your IAM principals. You can design these ABAC policies to allow operations when the principal's tag matches the resource tag. For more information, see What is ABAC for AWS? in the IAM User Guide.",
            "remediation" : "To add tags to a CloudFront distribution, see Tagging Amazon CloudFront distributions in the Amazon CloudFront Developer Guide.\nMore Information\nhttps://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/tagging.html",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        client = self.session.client('cloudfront')

        for distribution in self.distributions:
            try:
                tags = client.list_tags_for_resource(Resource=distribution["ARN"])["Tags"]
                if not tags["Items"]:
                    results["affected"].append(distribution["Id"])
            except KeyError:
                pass
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting distributions - %s" % e.response["Error"]["Code"])

        if results["affected"]:
            results["analysis"] = "The affected distribution ids does not have any tags attached."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No issues found"
            results["pass_fail"] = "PASS"
            results["affected"].append(self.account_id)

        return results
