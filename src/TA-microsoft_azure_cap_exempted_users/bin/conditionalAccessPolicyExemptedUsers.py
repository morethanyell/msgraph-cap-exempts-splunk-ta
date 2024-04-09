import sys
import json
import requests
import time
import socket
import re
from splunklib.modularinput import *
import splunklib.client as client


class ConditionalAccessPolicyExemptedUsers(Script):

    MASK = "***ENCRYPTED***"
    CREDENTIALS = None

    def get_scheme(self):

        scheme = Scheme("Microsoft Azure AD - Conditional Access Policy Exemptions")
        scheme.use_external_validation = False
        scheme.use_single_instance = False
        scheme.description = "Dump of users who are members of groups exempted from conditional access policies"

        client_id = Argument("client_id")
        client_id.title = "Application/Client ID"
        client_id.data_type = Argument.data_type_string
        client_id.description = "Microsoft Graph App Registered ID"
        client_id.required_on_create = True
        client_id.required_on_edit = False
        scheme.add_argument(client_id)

        client_secret = Argument("client_secret")
        client_secret.title = "Client Secret"
        client_secret.data_type = Argument.data_type_string
        client_secret.description = "Client Secret"
        client_secret.required_on_create = True
        client_secret.required_on_edit = True
        scheme.add_argument(client_secret)

        tenant_id = Argument("tenant_id")
        tenant_id.title = "Tenant/Directory ID"
        tenant_id.data_type = Argument.data_type_string
        tenant_id.description = "Tenant ID"
        tenant_id.required_on_create = True
        tenant_id.required_on_edit = False
        scheme.add_argument(tenant_id)
        
        policy_name = Argument("policy_name")
        policy_name.title = "A valid RegEx patter to match policy names"
        policy_name.data_type = Argument.data_type_string
        policy_name.description = "Policy Name RegEx"
        policy_name.required_on_create = True
        policy_name.required_on_edit = False
        scheme.add_argument(policy_name)

        return scheme
    
    def get_conditional_access_policies(self, ew, client_id, client_secret, tenant_id):
    
        token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'

        token_data = {
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret,
            'scope': 'https://graph.microsoft.com/.default'
        }

        token_response = requests.post(token_url, data=token_data)
        
        if token_response.status_code > 299:
            ew.log("ERROR", f'Failed to retrieve access token. POST https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token status_code={str(token_response.status_code)} {token_response.text}')
            sys.exit(1)
        
        ew.log("INFO", f'Access token retrieved. client_id={client_id}, tenant_id={tenant_id}')
        
        token_response_data = token_response.json()
        access_token = token_response_data['access_token']
        graph_url = 'https://graph.microsoft.com/v1.0/'
        conditional_policy_url = graph_url + 'identity/conditionalAccess/policies'

        headers = {
            'Authorization': 'Bearer ' + access_token,
            'Content-Type': 'application/json'
        }

        filtered_policies = []
        filtered_policies_reduced = []
        
        ew.log("INFO", f'Now retrieving all conditional access policies. GET {conditional_policy_url}')
        
        response = requests.get(conditional_policy_url, headers=headers)

        if response.status_code == 200:
            
            conditional_policies = response.json()
            filtered_policies.extend(conditional_policies['value'])
            
            while '@odata.nextLink' in conditional_policies:
                next_link = conditional_policies['@odata.nextLink']
                response_next_page = requests.get(next_link, headers=headers)
                if response_next_page.status_code == 200:
                    conditional_policies = response.json()
                    filtered_policies.extend(conditional_policies['value'])
                else:
                    ew.log('ERROR', f'Error occurred. status_code={str(response_next_page.status_code)} {response_next_page.text}')
                    break
            
            ew.log("INFO", f'All conditional access policies in cache. count={len(filtered_policies)}')
            
        else:
            ew.log('ERROR', f'Error occurred. status_code={str(response.status_code)} {response.text}')
            sys.exit(1)
        
        for policy in filtered_policies:
            if 'conditions' in policy and 'users' in policy['conditions'] and 'excludeGroups' in policy['conditions']['users']:
                exclude_groups = policy['conditions']['users']['excludeGroups']
                policy_name = policy['displayName']
                if exclude_groups:
                    eg = {"policyName": policy_name, "excludedGroup": exclude_groups}
                    filtered_policies_reduced.append(eg)
        
        return filtered_policies_reduced
        
    def get_group_members(self, ew, client_id, client_secret, tenant_id, groups, _pattern):

        token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'

        token_data = {
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret,
            'scope': 'https://graph.microsoft.com/.default'
        }

        token_response = requests.post(token_url, data=token_data)
        
        if token_response.status_code > 299:
            ew.log("ERROR", f'Failed to retrieve access token. POST https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token status_code={str(token_response.status_code)}', token_response.text)
            sys.exit(1)
            
        ew.log("INFO", f'Access token retrieved. POST https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token')
        
        token_response_data = token_response.json()
        access_token = token_response_data['access_token']
        graph_url = 'https://graph.microsoft.com/v1.0/'
        
        headers = {
            'Authorization': 'Bearer ' + access_token,
            'Content-Type': 'application/json'
        }
        
        mfa_exclusions = []
        all_group_members_details = []
        
        for group in groups:
            
            pn = group['policyName']
            pattern = _pattern
            
            if not re.search(pattern, pn):
                ew.log("INFO", f'Skipped policy_name="{pn}" because it does not match regex="{pattern}"')
                continue
            
            for group_id in group['excludedGroup']:
                
                group_members_url = graph_url + f'groups/{group_id}/members'
                response = requests.get(group_members_url, headers=headers)
                
                ew.log("INFO", f'Now retrieving members of this exempted group. GET {group_members_url}')
                
                if response.status_code == 200:
                    group_members_details = response.json()
                    all_group_members_details.extend(group_members_details['value'])
                    
                    while '@odata.nextLink' in group_members_details:
                        next_link = group_members_details['@odata.nextLink']
                        response_next_page = requests.get(next_link, headers=headers)
                        
                        if response_next_page.status_code == 200:
                            group_members_details = response_next_page.json()
                            all_group_members_details.extend(group_members_details['value'])
                        else:
                            ew.log('ERROR', f'Error occurred. status_code={str(response_next_page.status_code)} {response_next_page.text}')
                            break    
                
                else:
                    ew.log('ERROR', f'Error occurred. status_code={str(response.status_code)} {response.text}')
                    
                ew.log('INFO', f'All users from {group_id} retrieved. members={len(all_group_members_details)}')
                    
                for user in all_group_members_details:
                    
                    if "userPrincipalName" in user:
                        
                        azure_ad_type = user['@odata.type']
                        upn = user['userPrincipalName']
                        uid = user['id']
                        
                        user_dump = {"userPrincipalName": upn, "userAzureADId": uid, "type": azure_ad_type, "memberOfExclusionGroup": group_id, "excludedFrom": pn}
                        mfa_exclusions.append(user_dump)
                            
        
        return mfa_exclusions

    def validate_input(self, definition):
        pass

    def encrypt_keys(self, _client_id, _client_secret, _session_key):

        args = {'token': _session_key}
        service = client.connect(**args)

        credentials = {"clientId": _client_id, "clientSecret": _client_secret}

        try:
            for storage_password in service.storage_passwords:
                if storage_password.username == _client_id:
                    service.storage_passwords.delete(
                        username=storage_password.username)
                    break

            service.storage_passwords.create(json.dumps(credentials), _client_id)

        except Exception as e:
            raise Exception("Error encrypting: %s" % str(e))

    def mask_credentials(self, _input_name, _client_id, _tenant_id, _pattern, _session_key):

        try:
            args = {'token': _session_key}
            service = client.connect(**args)

            kind, _input_name = _input_name.split("://")
            item = service.inputs.__getitem__((_input_name, kind))

            kwargs = {
                "client_id": _client_id,
                "client_secret": self.MASK,
                "tenant_id": _tenant_id,
                "policy_name": _pattern
            }

            item.update(**kwargs).refresh()

        except Exception as e:
            raise Exception("Error updating inputs.conf: %s" % str(e))

    def decrypt_keys(self, _client_id, _session_key):

        args = {'token': _session_key}
        service = client.connect(**args)

        for storage_password in service.storage_passwords:
            if storage_password.username == _client_id:
                return storage_password.content.clear_password

    def stream_events(self, inputs, ew):
        
        start = time.time()
        
        self.input_name, self.input_items = inputs.inputs.popitem()
        session_key = self._input_definition.metadata["session_key"]

        client_id = self.input_items["client_id"]
        client_secret = self.input_items["client_secret"]
        tenant_id = self.input_items["tenant_id"]
        policy_name = self.input_items["policy_name"]

        ew.log("INFO", f'Start of collecting Conditional Access Policies matching regex_pattern={policy_name}')

        try:
            
            if client_secret != self.MASK:
                self.encrypt_keys(client_id, client_secret, session_key)
                self.mask_credentials(self.input_name, client_id, tenant_id, policy_name, session_key)

            decrypted = self.decrypt_keys(client_id, session_key)
            self.CREDENTIALS = json.loads(decrypted)

            client_secret = self.CREDENTIALS["clientSecret"]

            filtered_policies = self.get_conditional_access_policies(ew, client_id, client_secret, tenant_id)
            
            all_members = self.get_group_members(ew, client_id, client_secret, tenant_id, filtered_policies, policy_name)
            
            apiScriptHost = socket.gethostname()

            for user_details in all_members:
                user_details["clientId"] = client_id
                user_details["tenantId"] = tenant_id
                user_details["apiScriptHost"] = apiScriptHost
                user_details_event = Event()
                user_details_event.stanza = self.input_name
                user_details_event.sourceType = "azure:aad:conditionalAccessPolicyExemptedUsers"
                user_details_event.data = json.dumps(user_details)
                ew.write_event(user_details_event)
        
        except Exception as e:
            ew.log("ERROR", f"[MS Azure AD Conditional Access Policy Exempted Groups] Error: {str(e)}")
        
        end = time.time()
        elapsed = round((end - start) * 1000, 2)
        ew.log("INFO", f'Process completed in {str(elapsed)} ms. input_name="{self.input_name}"')


if __name__ == "__main__":
    sys.exit(ConditionalAccessPolicyExemptedUsers().run(sys.argv))
