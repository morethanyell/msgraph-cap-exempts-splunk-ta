
# encoding = utf-8

import requests
import json
import re

'''
    IMPORTANT
    Edit only the validate_input and collect_events functions.
    Do not edit any other part in this file.
    This file is generated only once when creating the modular input.
'''
'''
# For advanced users, if you want to create single instance mod input, uncomment this method.
def use_single_instance_mode():
    return True
'''

def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    # This example accesses the modular input variable
    # policy_name = definition.parameters.get('policy_name', None)
    # client_id = definition.parameters.get('client_id', None)
    # tenant_id = definition.parameters.get('tenant_id', None)
    pass

def get_bearer_token(helper, client_id, client_secret, tenant_id):
    
    token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
    
    data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'https://graph.microsoft.com/.default'
    }
    
    try:
        
        helper.log_info("Obtaining access token...")
        
        response = requests.post(token_url, data=data)
        response.raise_for_status()
        token_info = response.json()
        
        helper.log_info(f"Access token for client id {client_id} has been granted...")
        
        return token_info['access_token']
    except requests.RequestException as e:
        helper.log_error(f"Error obtaining token: {e}")
        return None

def get_conditional_access_policies(helper, access_token, policyNameRegex):
    
    graph_url = 'https://graph.microsoft.com/v1.0/'
    conditional_policy_url = graph_url + 'identity/conditionalAccess/policies'
    
    headers = {
        'Authorization': 'Bearer ' + access_token,
        'Content-Type': 'application/json'
    }
    
    policies = []
    policies_reduced = []
    
    helper.log_info(f'Retrieving Conditional Access Policies matching regex={policyNameRegex}')
    
    response = requests.get(conditional_policy_url, headers=headers)
    
    if response.status_code == 200:
            
        policies = response.json()
        policies_reduced.extend(policies['value'])
        
        while '@odata.nextLink' in policies:
            next_link = policies['@odata.nextLink']
            response_next_page = requests.get(next_link, headers=headers)
            if response_next_page.status_code == 200:
                policies = response.json()
                policies_reduced.extend(policies['value'])
            else:
                helper.log_error('Error occurred. status_code={str(response_next_page.status_code)} {response_next_page.text}')
                break
        
        filtered_policies_reduced = [item for item in policies_reduced if re.search(policyNameRegex, item.get('displayName', ''), re.IGNORECASE)]
        
        return filtered_policies_reduced
        
        helper.log_info(f'All conditional access policies in cache. count={len(policies_reduced)}')
            
    else:
        helper.log_error(f'Error occurred. status_code={str(response.status_code)} {response.text}')
 
def get_excluded_groups_from_cap(helper, policies):
    
    if policies is None: 
        helper.log_warning(f'Unable to retrieve excluded groups because policies list is empty.')
        return
    
    groups = []
    
    for p in policies:
        for g in p['conditions']['users']['excludeGroups']:
            xg = {}
            xg['policyId'] = p['id']
            xg['policyDisplayName'] = p['displayName']
            xg['policyState'] = p['state']
            xg['policyLastModifiedDateTime'] = p['modifiedDateTime']
            xg['excludedGroups'] = g
            groups.append(xg)
    
    return groups
    
def get_excluded_users_from_cap(helper, policies):
    
    if policies is None: 
        helper.log_warning(f'Unable to retrieve excluded users because policies list is empty.')
        return
    
    users = []
    
    for p in policies:
        for u in p['conditions']['users']['excludeUsers']:
            xu = {}
            xu['policyId'] = p['id']
            xu['policyDisplayName'] = p['displayName']
            xu['policyState'] = p['state']
            xu['policyLastModifiedDateTime'] = p['modifiedDateTime']
            xu['excludedUserMemberOf'] = "null"
            xu['excludedUserState'] = "Excluded from Policy Directly"
            xu['excludedUserId'] = u
            users.append(xu)
    
    return users

def get_group_members(helper, access_token, group_id):
    
    graph_url = 'https://graph.microsoft.com/v1.0/'
    group_members_url = graph_url + f'groups/{group_id}/members?$select=id'

    headers = {
        'Authorization': 'Bearer ' + access_token,
        'Content-Type': 'application/json'
    }

    all_group_members_details = []
    
    helper.log_info(f"Retrieving members of {group_id}")

    response = requests.get(group_members_url, headers=headers)
    
    page_counter = 1
    
    if response.status_code == 200:
        group_members_details = response.json()
        
        all_group_members_details.extend(group_members_details['value'])
        
        while '@odata.nextLink' in group_members_details:
            
            page_counter = page_counter + 1
            
            if page_counter == 2:
                print(f"Group {group_id} has multiple pages.")
            
            next_link = group_members_details['@odata.nextLink']
            response = requests.get(next_link, headers=headers)
            if response.status_code == 200:
                group_members_details = response.json()
                all_group_members_details.extend(group_members_details['value'])
            else:
                helper.log_error(f'Error occurred. Status={str(response.status_code)}', response.text)
                continue
        
        if page_counter > 1:
            helper.log_info(f"Group {group_id} ended collecting all members at page {str(page_counter)}.")
        
        return all_group_members_details

    else:
        helper.log_error(f'Error occurred. Status={str(response.status_code)}', response.text)

def collect_events(helper, ew):
    
    helper.log_info(f'Start of collection.')
    
    opt_global_account = helper.get_arg('client_id')
    client_id = opt_global_account['username']
    client_secret = opt_global_account['password']
    tenant_id = helper.get_arg('tenant_id')
    pattern = helper.get_arg('policy_name')
    
    llvl = helper.get_log_level()
    helper.set_log_level(llvl)
    helper.log_info(f"Loging level is set to: {llvl}")
    
    
    token = get_bearer_token(helper, client_id, client_secret, tenant_id)
    
    meta_source = f"ms_aad_user:tenant_id:{tenant_id}"
    
    pols = get_conditional_access_policies(helper, token, pattern)
    
    helper.log_info(f'Conditional Access Policies (CAP) retrieved. Ingesting all matched CAP as separate sourcetype.')
    
    for p in pols:
        data_event = json.dumps(p, separators=(',', ':'))
        event = helper.new_event(source=meta_source, index=helper.get_output_index(), sourcetype='azure:aad:policy', data=data_event)
        ew.write_event(event)
    
    helper.log_info(f'CAP ingested. Start of retrieving users. Firstly, all users who are directly excluded from CAP.')
    
    users = get_excluded_users_from_cap(helper, pols)
    
    if len(users) == 0:
        helper.log_info(f'Did not find users who are directly excluded from CAP. Moving on to groups.')
    else:
        helper.log_info(f'All users directly excluded from CAP retrieved. Now ingesting users...')
        
        for u in users:
            data_event = json.dumps(u, separators=(',', ':'))
            event = helper.new_event(source=meta_source, index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=data_event)
            ew.write_event(event)
            
        helper.log_info(f'All users directly excluded from CAP ingested. Start of retrieving groups excluded from CAP.')
    
    groups = get_excluded_groups_from_cap(helper, pols)
    
    if len(groups) == 0:
        helper.log_info(f'Did not find groups in the CAP exclusion information. End of collection.')
        return
    
    helper.log_info(f'All groups excluded from CAP retrieved. Now collecting members...')
    
    for g in groups:
        
        gid = g['excludedGroups']
        members = get_group_members(helper, token, gid)
        
        helper.log_info(f'All members of CAP-exclusion group {gid} retrieved. Now ingesting users/members...')
               
        for m in members:
            xu = {}
            xu['policyId'] = g['policyId']
            xu['policyDisplayName'] = g['policyDisplayName']
            xu['policyState'] = g['policyState']
            xu['policyLastModifiedDateTime'] = g['policyLastModifiedDateTime']
            xu['excludedUserMemberOf'] = gid
            xu['excludedUserState'] = "Excluded from Policy via Group"
            xu['excludedUserId'] = m['id']
            
            data_event = json.dumps(xu, separators=(',', ':'))
            event = helper.new_event(source=meta_source, index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=data_event)
            ew.write_event(event)
    
    helper.log_info(f"Ingestion of all users was successful. End of collection.")
    
