import boto3
import json

from utils.utils import describe_regions

class sns(object):

    def __init__(self):
        self.regions = describe_regions()

    def run(self):
        findings = []
        findings += [ self.sns_1() ]
        return findings
        
    def sns_1(self):
        # SNS topc allows actions to all aws principals

        results = {
            "id" : "sns_1",
            "ref" : "n/a",
            "compliance" : "n/a",
            "level" : "n/a",
            "service" : "sns",
            "name" : "SNS Topic Allows Actions To All AWS Principals",
            "affected": "",
            "analysis" : "no public SNS Topics found",
            "description" : "The AWS account under review contains an AWS Simple Notification Service (SNS) which is configured to allow access from all principals AKA Everybody (*).  When an SNS topic policy grants permission to Everyone by using a wildcard, i.e. *, as the Principal value, the topic security can be at risk as any unauthenticated entity can subscribe and receive messages from the topic publishers, update the topic, Publish messages to the topic and even delete topics resulting in potential loss of data availability, privacy and additional account costs.",
            "remediation" : "Ensure that your AWS Simple Notification Service (SNS) topics do not allow Everyone to subscribe. The entities that can subscribe to your SNS topics can be: Everyone (anonymous access), users whose endpoint URL, protocol, email address or ARN from a Subscribe request match a certain value, specific AWS users or resources and the topic owner. From this list of topic subscribers, you should make sure that the Everyone entity is not used with any SNS topics created within your AWS account in order to protect the messages published to your topics against attackers or unauthorized personnel.",
            "impact" : "medium",
            "probability" : "low",
            "cvss_vector" : "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "cvss_score" : "6.5",
            "pass_fail" : "PASS"
        }

        print("running check: sns_1")

        failing_topics = []
        
        for region in self.regions:
            client = boto3.client('sns', region_name=region)
            topics = client.list_topics()["Topics"]
            for topic in topics:
                attributes = client.get_topic_attributes(TopicArn=topic["TopicArn"])["Attributes"]
                statements = json.loads(attributes["Policy"])["Statement"]
                for statement in statements:
                    if statement["Effect"] == "Allow":
                        if statement["Principal"] == {"AWS": "*"} or statement["Principal"] == {"CanonicalUser": "*"}:
                            if "Condition" not in statement:
                                failing_topics += [topic["TopicArn"]]

        if failing_topics:
            results["analysis"] = "the following SNS Topics Allow all principals to perform actions: {}".format(" ".join(failing_topics))
            results["affected"] = ", ".join(failing_topics)
            results["pass_fail"] = "FAIL"
        
        return results