#!/usr/bin/python3

from azure.identity import DefaultAzureCredential
from azure.identity import ClientSecretCredential

import argparse
import json
import os
import sys
import logging

from datetime import datetime

from checks.resource import resource as Resource
from checks.app_service import app_service
from checks.storage_account import storage_account
from checks.sql import sql
from checks.compute import compute
from checks.keyvault import keyvault
from checks.network import network
#from checks.graph_rbac_management import graph_rbac_management

# old method
#from azure.common.credentials import ServicePrincipalCredentials


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
    ),
    parser.add_argument(
        "--default",
        help="use azure default credential, i.e environment variables, Azure CLI credentials, and managed identity (when running on an Azure VM).",
        dest="default",
        required=False,
        action="store_true",
    )
    args = parser.parse_args()

    if args.default:
        try:
            # Acquire a credential object
            # default credential i.e. az login
            credential = DefaultAzureCredential()
            #azure.core.exceptions.ClientAuthenticationError
        except:
            logging.error("profile not found! try harder...")
            sys.exit(0)
    else:        
        # Information required to authenticate using a Service Principal
        client_id = "7d3fa6bb-7dbf-4ec9-b58b-285ac2232619"
        #client_id = "7d3fa6bb-7dbf-4ec9-b58b-285ac2232619"
        client_secret = "Z6F8Q~ht6VNTx-DDRNCg2J1-WrpbFCTPS~B-AaTS"
        #client_secret = "Z6F8Q~ht6VNTx-DDRNCg2J1-WrpbFCTPS~B-AaTS"
        # Get the application credentials

        logging.info("Authenticating with service principal credentials")
        credential = ClientSecretCredential(args.tenant_id, client_id, client_secret) 
        #old_credential = ServicePrincipalCredentials(client_id, client_secret, tenant=args.tenant_id, resource="https://graph.windows.net")

    resource = Resource(credential)

    subscriptions = resource.subscriptions
    resource_groups = resource.resource_groups
    resources = resource.resources

    if args.subscription_id:
        subscriptions = [ i for i in subscriptions if i.subscription_id == args.subscription_id ]

    # init results dictionary
    results = {}

    results["tenant_id"] = args.tenant_id
    results["datetime"] = str(datetime.today())
    results["findings"] = []
    
    logging.info("performing full scan")
    #results["findings"] += graph_rbac_management(old_credential, args.tenant_id).run()
    #results["findings"] += graph_rbac_management(credential, args.tenant_id).run()
    results["findings"] += resource.run()
    #results["findings"] += network(credential, subscriptions, resource_groups, resources).run()
    results["findings"] += compute(credential, subscriptions, resource_groups, resources).run()
    #results["findings"] += app_service(credential, subscriptions, resource_groups, resources).run()
    #results["findings"] += storage_account(credential, subscriptions, resource_groups, resources).run()
    #results["findings"] += sql(credential, subscriptions, resource_groups, resources).run()
    #results["findings"] += keyvault(credential, subscriptions, resource_groups, resources).run()

    if not os.path.exists(args.results_dir):
        logging.info("results dir does not exist, creating it for you")
        os.makedirs(args.results_dir)
    
    filename = os.path.join(args.results_dir, "snotra_results_{}.json".format(args.tenant_id))
    logging.info("writing results json {}".format(filename))
    with open(filename, 'w') as f:
        json.dump(results, f, default=str)

if __name__ == '__main__':
    main()
