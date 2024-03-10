from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.resource import ResourceManagementClient

import time
import sys
import logging

def list_subscriptions(credential):
    return list(SubscriptionClient(credential).subscriptions.list())
        
def list_resource_groups(credential):
    resource_client = ResourceManagementClient(credential=credential, subscription_id=subscription_id)
    return list(ResourceManagementClient(credential).resource_groups.list())
