#!/usr/bin/python3
# Originally crafted by Andre Holder

# Required Libraries
import json
import os
import requests
import csv
import time
from datetime import datetime

# Variables
global_url= 'https://api.global.alertlogic.com/'
alert_logic_username = ''
alert_logic_password = ''
alert_logic_access_apikey = ''
alert_logic_secret_apikey = ''
alert_logic_cid = ''
deployment_id = ''
alert_logic_deployment_name = 'My Deployment Name'
entitlement = 'Professional'

true=True
false=False

### Validate Authentication to Alert Logic API
#Function to get AIMS Token once we have creds
def get_token_userpass ():
	url = f'{global_url}aims/v1/authenticate'
	global auth_token
	#Use credentials
	aims_user = alert_logic_username
	aims_pass = alert_logic_password

	if "alertlogic.com" in aims_user :
		print ('\nError: Alert Logic User Detected. Cannot authenticate since MFA is mandatory. Use API Keys.\n')
		exit()

	print('\nValidating stored credentials...', end = '')

	#POST request to the URL using credentials. Load the response into auth_info then parse out the token
	token_response = requests.post(url, auth=(aims_user, aims_pass))

	if token_response.status_code != 200:
		print('Error: Could not authenticate. Got the following response: ',end='')
		print(token_response)
		print()
		exit()

	auth_info = json.loads(token_response.text)
	auth_token = auth_info['authentication']['token']

#Same as previous, but uses stored API Keys if they are detected
def get_token_apikey ():
	url = f'{global_url}aims/v1/authenticate'
	global auth_token
	print('Detected stored API Keys. Validating...', end = '')
	#POST request to the URL using keys. Load the response into auth_info then parse out the token
	token_response = requests.post(url, auth=(alert_logic_access_apikey, alert_logic_secret_apikey))

	if token_response.status_code != 200:
		print('Error: Could not authenticate. Got the following response: ',end='')
		print(token_response)
		print()
		exit()

	auth_info = json.loads(token_response.text)
	auth_token = auth_info['authentication']['token']

#Function to validate the AIMS token was successfully generated, and that it has not expired
def validate_token ():
	url = f'{global_url}aims/v1/token_info'
	headers = {'x-aims-auth-token': f'{auth_token}'}
	global validate_info
	validate_response = requests.get(url, headers=headers)
	validate_info = json.loads(validate_response.text)

	#get current unix timestamp,make global for later
	global current_time
	current_time = int(time.time())
	#get token expiration timestamp
	token_expiration = validate_info['token_expiration']
	num_seconds_before_expired=(token_expiration - current_time)

	if num_seconds_before_expired < 0 :
		print(' Errror: Could not generate / validate AIMS Token. Please check credentials and try again\n')
		exit()
	else :
		print(' AIMS token generated and validated.\n')
		time.sleep(1)

if alert_logic_access_apikey != '' and alert_logic_secret_apikey != '':
	get_token_apikey()
	validate_token()
elif alert_logic_username != '' and alert_logic_password != '':
	get_token_userpass()
	validate_token()
else:
	print ('\nError: No credentials stored in the configuration file, to allow authentication against the API.\n')
	exit()
#Authentication complete

headers = {"x-aims-auth-token": f"{auth_token}"} #Set header for all future API calls

#Get base endpoint for customer ID
endpoint_url = f'{global_url}endpoints/v1/{alert_logic_cid}/residency/default/services/assets/endpoint/api'
endpoint_response = requests.get(endpoint_url, headers=headers)

#In case we don't get a 200 response getting the endpoint
if endpoint_response.status_code != 200:
	print('Error: Could not determine API endpoint for the Customer ID stored. Got response code: ' + str(endpoint_response.status_code))
	print()
	exit()

endpoint_info = json.loads(endpoint_response.text)
base_url = endpoint_info['assets']
base_url = 'https://' + base_url

#Get CID that the token exists in (CID the authenticated user was in). Then check if that CID is authorised to view
users_CID = validate_info['user']['account_id']

#Print out authenticated user information
print('Authenticated Users Info:\n')
user_name = validate_info['user']['name']
user_email = validate_info['user']['email']
user_role = validate_info['roles'][0]['name']
user_lastlogin_unix = validate_info['user']['user_credential']['last_login']
user_lastlogin_hr = datetime.utcfromtimestamp(user_lastlogin_unix ).strftime('%d/%m/%Y %H:%M:%S %Z')
print('    Name: ' + user_name)
print('    Email: ' + user_email)
print('    User Role: ' + user_role)
print('    CID: ' + users_CID)
#print('    Last authentication: ' + user_lastlogin_hr) #Don't think this is needed, last time user logged into the UI
print()


#If the CID the user has authenticated from, is not equal to the target CID
if alert_logic_cid != users_CID:
	#This is checking whether there is a managed relationship (ensuring a parent-child relationship) between the 2 CID's.
	managed_CID_check_url = f'{global_url}aims/v1/{users_CID}/accounts/managed/{alert_logic_cid}'
	managed_CID_check_response = requests.get(managed_CID_check_url, headers=headers)
	managed_CID_check_statuscode = managed_CID_check_response.status_code

	#1 - Make sure the CID's have a managed relationship (Status Code 204 is a success response)
	if managed_CID_check_statuscode != 204:
		print(' Error: Authenticated user does not have authorisation to perform actions in CID ' + alert_logic_cid + ' Please try another user.\n')
		exit()

	#2 - If yes to step 1, make sure authenticated user has permissions to create stuff in target CID
	if user_role == 'Read Only' or user_role == 'Support/Care' or user_role == 'Power User' :
		print ('Error: Authenticated user does not have the required permission to create in CID ' + alert_logic_cid)
		print ('\n    - User must be Administrator or Owner\n')
		exit()

#If the CID the user has authenticated from, is equal to the target CID
elif alert_logic_cid == users_CID:
	# Make sure the autenticated user has permission to create in target CID
	if user_role == 'Read Only' or user_role == 'Support/Care' :
		print ('Error: Authenticated user does not have the required permission to create in CID ' + alert_logic_cid)
		print ('\n    - User must be Administrator, Owner or Power user\n')
		exit()

#Get some account information from the CID
print('Target CID Info:\n')
account_info_url = f'{global_url}aims/v1/{alert_logic_cid}/account'
account_info_response = requests.get(account_info_url, headers=headers)
account_info = json.loads(account_info_response.text)
account_name = account_info['name']
account_CID = alert_logic_cid
account_defaultloc = account_info['default_location']
print('    Account Name: ' + account_name)
print('    Accound CID: ' + account_CID)
print('    Default Location: ' + account_defaultloc)
print('    Base URL: ' + base_url)
print()

#Get the policy ID's for the protection levels.
policies_info_url = f'{base_url}/policies/v1/{alert_logic_cid}/policies'
policies_info_response = requests.get(policies_info_url, headers=headers)
policies_info = json.loads(policies_info_response.text)
#The following code pulls in the entitlement set in the configuration file and returns the entitlement ID
entitlement=entitlement.capitalize()
policy_id = [x for x in policies_info if x['name'] == entitlement]
entitlement_id=policy_id[0]['id']

# Read from networks csv list1
def csv_reader():
	global networks
	with open('networks.csv', newline='') as csv_file:
		reader =csv.reader(csv_file)
		networks = list(reader)
		return networks

csv_reader()

# Create the networks in the portal
def create_networks ():
	global network_keys
	global protected_networks
	global list_networks
	network_keys = []
	protected_networks = []
	list_networks = [] 

	if not networks:
		print("    No networks detected in the properties file. Skipping.")
		protected_networks.append("\t\t\t\tNo networks defined")
	else: 
	
		for x in networks: 
			# Pull out network name as the first value in list
			network_name=x[0]
			cidr_list = []
			
			# For every value other than the first, append to new list
			for cidr in x[1:]: 
				cidr_list.append(cidr)
		
			# Format the cidr list ready for the POST payload
			json_cidr_list=str(cidr_list)[1:-1]
			
			#Network creation payload
			network_payload = {
					"network_name": network_name,
					"cidr_ranges": [(json_cidr_list)],
					"span_port_enabled": false
				}
	
			#Convert the payload (including the cidr list) into json
			create_network_payload=json.dumps(network_payload)
			#Inside the scope, replace the [" "] so it's just [ ] 
			create_network_payload=create_network_payload.replace('["','[')
			create_network_payload=create_network_payload.replace('"]',']')
			#Change the objects inside the cidr list to be surrounded by double quotes instead of single
			create_network_payload=create_network_payload.replace("'",'"')
			
			#Create networks and store the network keys into a new list, network_keys (so that we can add to scope later)
			create_network_url = f'{base_url}/assets_manager/v1/{alert_logic_cid}/deployments/{deployment_id}/networks'
			create_network_response = requests.post(create_network_url, create_network_payload, headers=headers)
			
			if create_network_response.status_code !=200: 
				print('    Error: Network with name '+network_name+ ' creation failed. Got the following response: '+ str(create_network_response.status_code))
			else: 
				print('    Network with name '+network_name+ ' created successfully, with CIDR ranges ' + json_cidr_list)
				protected_networks.append("\t\t\t\tNetwork: "+network_name+"\tCIDR's: "+str(cidr_list)[1:-1].replace("'", "")+"\n")
			create_network_info = json.loads(create_network_response.text)
			global network_key
			global claim_key
			network_key=create_network_info['key']
			network_keys.append(network_key)
			claim_key=create_network_info['claim_key']
			list_networks.append("    Network Name: " +network_name+"\t\tUnique Key: "+claim_key+"\n")

			#Find the network UUID for creating subnets later
			global network_id
			#Giving the network time create, was failing going straight into this
			time.sleep(1)
			#Query assets_query for full network info
			network_id_url = f'{base_url}/assets_query/v1/{alert_logic_cid}/deployments/{deployment_id}/assets?asset_types=v:vpc&v.key={network_key}'
			network_uuid_response = requests.get(network_id_url, headers=headers)
			#Pull network_uuid value out
			network_uuid_info = json.loads(network_uuid_response.text)
			network_uuid_info=network_uuid_info['assets'][0]
			network_id=network_uuid_info[0]['network_uuid']

			#Subnet creation for each network
			for each_cidr in cidr_list:
				list_subnets = [] 
				
				#Subnet creation payload
				subnet_name = each_cidr
				subnet_payload = {
						"subnet_name": subnet_name,
						"cidr_block": (each_cidr)
					}

				#Convert the payload into json
				create_subnet_payload=json.dumps(subnet_payload)
				#Inside the scope, replace the [" "] so it's just [ ] 
				create_subnet_payload=create_subnet_payload.replace('["','[')
				create_subnet_payload=create_subnet_payload.replace('"]',']')
				#Change the objects inside the cidr list to be surrounded by double quotes instead of single
				create_subnet_payload=create_subnet_payload.replace("'",'"')
				
				#Create networks and store the network keys into a new list, network_keys (so that we can add to scope later)
				create_subnet_url = f'{base_url}/assets_manager/v1/{alert_logic_cid}/deployments/{deployment_id}/networks/{network_id}/subnets'
				create_subnet_response = requests.post(create_subnet_url, create_subnet_payload, headers=headers)
				
				if create_subnet_response.status_code !=200: 
					print('    Error: Subnet with name '+subnet_name+ ' creation failed. Got the following response: '+ str(create_subnet_response.status_code))
				else: 
					print('    Subnet with name '+subnet_name+ ' created successfully, with CIDR block ' + each_cidr)
					#protected_subnets.append("\t\t\t\tNetwork: "+network_name+"\tCIDR's: "+str(cidr_list)[1:-1].replace("'", "")+"\n")

				list_subnets.append("    Subnet Name: " +subnet_name+ "\n")
	print()

	
	
	#Print created networks and the associated claim key
	list_networks=''.join(list_networks)
	print("The networks just created, and their associated unique registration keys:\n")
	print(str(list_networks))
	#For logging purposes
	protected_networks=''.join(protected_networks)

print("Creating Networks:\n")
create_networks()

def set_scope_protection (): 
	scope_list = []
	
	if not network_keys: 
		print("    No networks were created. Skipping.")
	else: 

		for key in network_keys: 
			scope_list.append("{\"key\":\""+key+"\",\"type\":\"vpc\",\"policy\":{\"id\":\""+entitlement_id+"\"}}")
	
		#Convert python list to string
		scope=str(scope_list)[1:-1]
	
		#Remove single quotes between each json object, dump into json then remove any extra slashes
		scope_json=scope.replace("'","")
		scope_json=json.dumps(scope_json)
		scope_json=scope_json.replace("\\", "")
	
		update_scope_payload={
			"version": 1,
			"scope": {
				"include": [(scope_json)],
				}
			}
		
		update_scope_payload=json.dumps(update_scope_payload)
		update_scope_payload=update_scope_payload.replace("\\", "")
		update_scope_payload=update_scope_payload.replace('""', "")
		update_scope_url = f'{base_url}/deployments/v1/{alert_logic_cid}/deployments/{deployment_id}'
		update_scope_response = requests.put(update_scope_url, update_scope_payload, headers=headers)
	
		if update_scope_response.status_code !=200:
			print('    Error: Protection levels not added to deployment with name "'+alert_logic_deployment_name+'". Got the following response code: '+str(update_scope_response.status_code))
		else:
			print('    Protection levels successfully added to deployment with name "'+alert_logic_deployment_name+'"')
	print()

print("Setting Protection Level on Networks:\n")
set_scope_protection()