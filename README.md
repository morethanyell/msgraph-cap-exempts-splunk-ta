# Conditional Access Policy Exempted Users

This Python script is designed to collect information about users who are members of groups exempted from conditional access policies in Microsoft Azure Active Directory (AD). It interacts with the Microsoft Graph API to retrieve data about conditional access policies and their exempted groups, and then fetches the members of these groups.

## Features

- **Data Collection**: Retrieves information about conditional access policies and exempted groups from Microsoft Azure AD using the Microsoft Graph API.
- **Policy Matching**: Filters conditional access policies based on a provided regular expression pattern.
- **User Retrieval**: Fetches members of exempted groups and collects information about them.
- **Output Formatting**: Outputs collected user information in JSON format suitable for consumption by other systems or storage in Splunk.

## Prerequisites

Before using this script, ensure that you have the following:

- **Microsoft Azure AD**: You must have access to an Azure AD instance and appropriate permissions to query conditional access policies and group memberships.
- **Registered Application**: You need to register an application in Azure AD and obtain its client ID and client secret. This application must have appropriate permissions to access the Microsoft Graph API.
- **Python Environment**: This script requires a Python environment with necessary dependencies installed, such as `requests` and `splunklib`.
