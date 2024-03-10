from azure.mgmt.resource import SubscriptionClient
import logging

#from utils.utils import describe_regions
#from utils.utils import get_account_id

class subscription(object):

    def __init__(self, credential):
        self.credential = credential
        self.client = SubscriptionClient(credential)

        #self.account_id = get_account_id(session)

    def run(self):
        findings = []
        findings += [ self.subscription_1() ]
        return findings

    def cis(self):
        findings = []
        findings += [ self.subscription_1() ]
        return findings

    def subscription_1(self):
        # 

        results = {
            "id" : "subscription_1",
            "ref" : "",
            "compliance" : "",
            "level" : 1,
            "service" : "subscription",
            "name" : "Azure Subscriptions",
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
        subscriptions = self.client.subscriptions.list()

        results["analysis"] = []

        for sub in subscriptions:
            results["analysis"].append(sub)
            print(sub.subscription_id, sub.display_name)

        return results
