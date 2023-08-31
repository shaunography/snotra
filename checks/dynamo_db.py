import boto3
import json
import re
import logging

from utils.utils import get_account_id
from utils.utils import describe_regions

class dynamo_db(object):

    def __init__(self, session):
        self.session = session
        self.account_id = get_account_id(session)
        self.regions = describe_regions(session)
        self.tables = self.list_tables()
        self.table_descriptions = self.describe_tables()

    def run(self):
        findings = []
        findings += [ self.dynamo_db_1() ]
        findings += [ self.dynamo_db_2() ]
        findings += [ self.dynamo_db_3() ]
        return findings

    def cis(self):
        findings = []
        return findings

    def list_tables(self):
        # returns list of tables
        logging.info("Getting Tables")
        tables = {}
        for region in self.regions:
            client = self.session.client('dynamodb', region_name=region)
            try:
                tables[region]= client.list_tables()["TableNames"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting tables - %s" % e.response["Error"]["Code"])
        return tables

    def describe_tables(self):
        # returns list of tables
        logging.info("Getting Table Descriptions")
        descriptions = {}
        for region, tables in self.tables.items():
            client = self.session.client('dynamodb', region_name=region)
            descriptions[region] = {}
            try:
                for table_name in tables:
                    descriptions[region][table_name] = client.describe_table(TableName=table_name)["Table"]
            except boto3.exceptions.botocore.exceptions.ClientError as e:
                logging.error("Error getting table description - %s" % e.response["Error"]["Code"])
        return descriptions
    
    def dynamo_db_1(self):
        # Dynamo DB Tables without Deletion Protection Enabled.

        results = {
            "id" : "dynamo_db_1",
            "ref" : "",
            "compliance" : "",
            "level" : "N/A",
            "service" : "dynamodb",
            "name" : "Dynamo DB Tables Without Deletion Protection Enabled",
            "affected": [],
            "analysis" : "Deletion protection can keep your table from being accidentally deleted. This section describes some best practices for using deletion protection.\nFor all active production tables, the best practice is to turn on the deletion protection setting and protect these tables from accidental deletion. This also applies to global replicas.\nWhen serving application development use cases, if the table management workflow includes frequently deleting and recreating development and staging tables then the deletion protection setting can be turned off. This will allow intentional deletion of such tables by authorized IAM principals.",
            "description" : "",
            "remediation" : "You can protect a table from accidental deletion with the deletion protection property. Enabling this property for tables helps ensure that tables do not get accidentally deleted during regular table management operations by your administrators. This will help prevent disruption to your normal business operations.\nMore Information\nhttps://docs.aws.amazon.com/amazondynamodb/latest/developerguide/WorkingWithTables.Basics.html#WorkingWithTables.Basics.DeletionProtection",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "cvss_score" : "4.0",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, tables in self.table_descriptions.items():
            for name, description in tables.items():
                if description["DeletionProtectionEnabled"] == False:
                    results["affected"].append("{} ({})".format(name, region))

        if results["affected"]:
            results["analysis"] = "The Affected Dynamo DB Tables do not have Deletion Protection enabled"
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "All Tables have Deletion Protection Enabled"
            results["pass_fail"] = "PASS"

        return results
    
    def dynamo_db_2(self):
        # unused DynamoDB Tables

        results = {
            "id" : "dynamo_db_2",
            "ref" : "",
            "compliance" : "",
            "level" : "N/A",
            "service" : "dynamodb",
            "name" : "Unused Dynamo DB Tables",
            "affected": [],
            "analysis" : "The affected Dynamo DB Tables have an item count of 0. To minimise costs and maintain good hygiene of the AWS environment it is recomended that all unused resources are deleted.",
            "description" : "",
            "remediation" : "Delete any unysed Dynamo DB tables.",
            "impact" : "info",
            "probability" : "info",
            "cvss_vector" : "N/A",
            "cvss_score" : "N/A",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, tables in self.table_descriptions.items():
            for name, description in tables.items():
                if description["ItemCount"] == 0:
                    results["affected"].append("{} ({})".format(name, region))

        if results["affected"]:
            results["analysis"] = "The Affected Dynamo DB Tables have no items and should be remvoed if not in use."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No unused dynamo DB tables found."
            results["pass_fail"] = "PASS"

        return results

    def dynamo_db_3(self):
        # Dynamo DB Tables without point in time / continous backups enabled 

        results = {
            "id" : "dynamo_db_3",
            "ref" : "",
            "compliance" : "",
            "level" : "N/A",
            "service" : "dynamodb",
            "name" : "Dynamo DB Tables Without Point In Time Recovery Enabled",
            "affected": [],
            "analysis" : "",
            "description" : "Point-in-time recovery helps protect your DynamoDB tables from accidental write or delete operations. With point-in-time recovery, you don't have to worry about creating, maintaining, or scheduling on-demand backups. For example, suppose that a test script writes accidentally to a production DynamoDB table. With point-in-time recovery, you can restore that table to any point in time during the last 35 days. DynamoDB maintains incremental backups of your table.",
            "remediation" : "Consider enabled Point In Time Recovery for important Tables.\nMore Informaiton\nhttps://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery_Howitworks.html",
            "impact" : "low",
            "probability" : "low",
            "cvss_vector" : "AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "cvss_score" : "4.0",
            "pass_fail" : ""
        }

        logging.info(results["name"])

        for region, tables in self.tables.items():
            client = self.session.client('dynamodb', region_name=region)
            for table in tables:
                    backups = client.describe_continuous_backups(TableName=table)["ContinuousBackupsDescription"]
                    if backups["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"] == "DISABLED":
                        results["affected"].append("{} ({})".format(table, region))

        if results["affected"]:
            results["analysis"] = "The Affected Dynamo DB Tables have no items and should be remvoed if not in use."
            results["pass_fail"] = "FAIL"
        else:
            results["analysis"] = "No unused dynamo DB tables found."
            results["pass_fail"] = "PASS"

        return results
