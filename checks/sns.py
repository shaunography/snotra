import boto3
import json
import logging

from utils.utils import describe_regions

class sns(object):

    def __init__(self, session):
        self.session = session
        self.regions = describe_regions(session)
        self.topics = self.get_topics()
        self.attributes = self.get_topic_attributes()

    def run(self):
        findings = []
        findings += [ self.sns_1() ]
        findings += [ self.sns_2() ]
        return findings

    def get_topics(self):
        logging.info("getting SNS topics")
        topics = {}
        for region in self.regions:
            client = self.session.client('sns', region_name=region)
            try:
                topics[region] = client.list_topics()["Topics"]      
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting topics - %s" % e.response["Error"]["Code"])
        return topics
        
    def get_topic_attributes(self):
        logging.info("getting SNS topic attributes")
        attributes = {}
        for region, topics in self.topics.items():
            attributes[region] = {}
            for topic in topics:
                client = self.session.client('sns', region_name=region)
                try:
                    attributes[region][topic["TopicArn"]] = client.get_topic_attributes(TopicArn=topic["TopicArn"])["Attributes"]
                except boto3.exceptions.botocore.exceptions.ClientError as e:
                    logging.error("Error getting topics - %s" % e.response["Error"]["Code"])
        return attributes


    def sns_1(self):
        # SNS topc allows actions to all aws principals

        results = {
            "id" : "sns_1",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "sns",
            "name" : "SNS Topic Allows Actions To All AWS Principals",
            "affected": [],
            "analysis" : "",
            "description" : "The AWS account under review contains an AWS Simple Notification Service (SNS) which is configured to allow access from all principals AKA Everybody (*).  When an SNS topic policy grants permission to Everyone by using a wildcard, i.e. *, as the Principal value, the topic security can be at risk as any unauthenticated entity can subscribe and receive messages from the topic publishers, update the topic, Publish messages to the topic and even delete topics resulting in potential loss of data availability, privacy and additional account costs.",
            "remediation" : "Ensure that your AWS Simple Notification Service (SNS) topics do not allow Everyone to subscribe. The entities that can subscribe to your SNS topics can be: Everyone (anonymous access), users whose endpoint URL, protocol, email address or ARN from a Subscribe request match a certain value, specific AWS users or resources and the topic owner. From this list of topic subscribers, you should make sure that the Everyone entity is not used with any SNS topics created within your AWS account in order to protect the messages published to your topics against attackers or unauthorized personnel.",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "6.5",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        for region in self.regions: 
            for arn, attributes in self.attributes[region].items():
                statements = json.loads(attributes["Policy"])["Statement"]
                for statement in statements:
                    if statement["Effect"] == "Allow":
                        if statement["Principal"] == {"AWS": "*"} or statement["Principal"] == {"CanonicalUser": "*"}:
                            if "Condition" not in statement:
                                results["affected"].append(arn)

        if results["affected"]:
            results["analysis"] = "The affected SNS Topics Allow all principals to perform actions."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No public SNS Topics found."
            results["pass_fail"] = "PASS"
        
        return results
    
    
    def sns_2(self):
        # Unencrypted SNS Topics

        results = {
            "id" : "sns_2",
            "ref" : "N/A",
            "compliance" : "N/A",
            "level" : "N/A",
            "service" : "sns",
            "name" : "Unencrypted SNS Topics",
            "affected": [],
            "analysis" : "",
            "description" : "The AWS account under review contains an AWS SNS Topic which is not configured to use server side data encryption. When you are using AWS SNS Topics to send and receive messages that contain sensitive data, it is highly recommended to implement encryption to add an additional layer of data confidentiality by making the contents of these messages unavailable to unauthorized users. The encryption and decryption is handled transparently by SQS SSE and does not require any additional action from you or your application",
            "remediation" : "Configure the affected SNS Topics to use server side encryption using the Amazon KMS service.",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "cvss_score" : "3.7",
            "pass_fail" : ""
        }

        logging.info(results["name"])
        
        for region in self.regions: 
            for arn, attributes in self.attributes[region].items():
                try:
                    kms_master_key_id = attributes["KmsMasterKeyId"]
                except KeyError:
                    results["affected"].append(arn)

        if results["affected"]:
            results["analysis"] = "The affected SNS Topics are not encrypted."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No unencrypted SNS Topics found."
            results["pass_fail"] = "PASS"
        
        return results