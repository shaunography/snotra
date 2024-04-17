#!/usr/bin/python3

from azure.identity import DefaultAzureCredential
from azure.identity import ClientSecretCredential

import argparse
import json
import os
import sys
import logging
import base64

from datetime import datetime

from checks.resource import resource as Resource
from checks.app_service import app_service
from checks.storage_account import storage_account
from checks.sql import sql
from checks.compute import compute
from checks.keyvault import keyvault
from checks.network import network
from checks.monitor import monitor
from checks.mysql import mysql
from checks.postgresql import postgresql
from checks.cosmosdb import cosmosdb
from checks.containerservice import containerservice
from checks.containerregistry import containerregistry
from checks.eventhub import eventhub
from checks.security import security
from checks.graph_services import graph_services
from checks.graph import graph

def main():

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s : %(levelname)s : %(funcName)s - %(message)s"
    )
    logging.getLogger("azure").setLevel(logging.WARNING)

    parser = argparse.ArgumentParser(description="AWS Auditor")
    parser.add_argument(
        "-r",
        help="results directory",
        dest="results_dir",
        required=True,
        metavar="<results_dir>"
    ),
    parser.add_argument(
        "-t",
        help="azure tenancy id",
        dest="tenant_id",
        required=True,
        metavar="<tenant_id>"
    ),
    parser.add_argument(
        "-s",
        help="azure tenancy id",
        dest="subscription_id",
        metavar="<subscription_id>"
    )
    args = parser.parse_args()

    # Acquire a credential object
    # default credential i.e. az login
    credential = DefaultAzureCredential()
    #azure.core.exceptions.ClientAuthenticationError


    if args.subscription_id:
        resource = Resource(credential, args.subscription_id)
    else:
        resource = Resource(credential, None)

    subscriptions = resource.subscriptions
    resource_groups = resource.resource_groups
    resources = resource.resources


    # init results dictionary
    results = {}

    #results["tenant_id"] = args.tenant_id
    results["account"] = args.tenant_id
    results["datetime"] = str(datetime.today())
    results["findings"] = []
    
    logging.info("performing full scan")
    results["findings"] += resource.run()
    results["findings"] += graph(credential, args.tenant_id).run()
    results["findings"] += graph_services(credential, subscriptions, resource_groups, resources).run()
    results["findings"] += security(credential, subscriptions, resource_groups, resources).run()
    results["findings"] += eventhub(credential, subscriptions, resource_groups, resources).run()
    results["findings"] += containerservice(credential, subscriptions, resource_groups, resources).run()
    results["findings"] += containerregistry(credential, subscriptions, resource_groups, resources).run()
    results["findings"] += mysql(credential, subscriptions, resource_groups, resources).run()
    results["findings"] += postgresql(credential, subscriptions, resource_groups, resources).run()
    results["findings"] += monitor(credential, subscriptions, resource_groups, resources).run()
    results["findings"] += network(credential, subscriptions, resource_groups, resources).run()
    results["findings"] += compute(credential, subscriptions, resource_groups, resources).run()
    results["findings"] += app_service(credential, subscriptions, resource_groups, resources).run()
    results["findings"] += storage_account(credential, subscriptions, resource_groups, resources).run()
    results["findings"] += keyvault(credential, subscriptions, resource_groups, resources).run()
    results["findings"] += sql(credential, subscriptions, resource_groups, resources).run()

    #results["findings"] += cosmosdb(credential, subscriptions, resource_groups, resources).run()

    if not os.path.exists(args.results_dir):
        logging.info("results dir does not exist, creating it for you")
        os.makedirs(args.results_dir)
    
    filename = os.path.join(args.results_dir, "snotra_results_{}.json".format(args.tenant_id))
    logging.info("writing results json {}".format(filename))
    with open(filename, 'w') as f:
        json.dump(results, f, default=str)

if __name__ == '__main__':
    main()

