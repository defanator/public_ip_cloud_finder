#!/usr/bin/python
from __future__ import print_function
from bs4 import BeautifulSoup as BS
from bs4.element import Tag
import urllib, json, netaddr, argparse, requests, subprocess, re, sys

def get_blocks(cloud=None):
	pass

def get_aws():
	#AWS
	AWSURL = 'https://ip-ranges.amazonaws.com/ip-ranges.json'
	try:
		response = urllib.urlopen(AWSURL)
	except Exception as e:
		print("Error downloading AWS IP blocks: {0}".format(str(e)), file=sys.stderr)
		return list()
	else:
		awsdata = json.loads(response.read())
		return awsdata['prefixes']

def get_gcp():
	#GCP
	GCPROOTDNS = '_cloud-netblocks.googleusercontent.com'
	ret = list()
	try:
		r = subprocess.check_output(['nslookup','-q=TXT',GCPROOTDNS,'8.8.8.8'])
		for d in re.findall(r'include:[^\s]*\s',r):
			r = subprocess.check_output(['nslookup','-q=TXT',d.split('include:')[1].strip(' '),'8.8.8.8'])
			for ip in re.findall(r'ip4:[^\s]*\s',r):
				ret.append(ip.split('ip4:')[1].strip(' '))
	except Exception as e:
		print("Error downloading GCP IP blocks: {0}".format(str(e)), file=sys.stderr)
		return list()
	else:
		return ret

def get_azure():
	#AZURE
	AZUREURL = 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653'
	aux = dict()
	try:
		soup = BS(requests.get(AZUREURL).text,'html.parser')
		ret = list()
		for region in BS(requests.get(soup.find('td').a.attrs['href']).text,'xml').AzurePublicIpAddresses:
			for ip in region:
				if type(ip) == Tag:
					ret.append({'ip' : ip.attrs['Subnet'],'region' : region.attrs['Name']})
	except Exception as e:
		print("Error downloading Azure IP blocks: {0}".format(str(e)), file=sys.stderr)
		return list()
	else:
		return ret

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Check from which cloud is some IP.')
	parser.add_argument('-i','--ip', metavar='N', nargs='+', help='IP addresses or hostnames.')
	parser.add_argument('-a','--all', action='store_true', default=False, help='Get all public cloud blocks.')
	parser.add_argument('-c','--cloud', choices=['aws','gcp','azure'], help='Get all public cloud blocks from this cloud.')
	args = parser.parse_args()
	if args.all:
		#Dump json file
		blocks = {'aws' : get_aws(), 'gcp' : get_gcp(), 'azure' : get_azure()}
		print(json.dumps(blocks))
	elif args.cloud:
		if args.cloud == 'aws':
			print(json.dumps(get_aws()))
		elif args.cloud == 'gcp':
			print(json.dumps(get_gcp()))
		elif args.cloud == 'azure':
			print(json.dumps(get_azure()))
		else:
			print("Nothing to do.")
	elif args.ip:
		aws = get_aws()
		gcp = get_gcp()
		azure = get_azure()
		for ip in args.ip:
			for a in aws:
				if netaddr.IPNetwork(ip) in netaddr.IPNetwork(a['ip_prefix']):
					print("La IP {0} pertenece a Amazon Web Services (region: {1} bloque: {2} servicio: {3}).".format(ip,a['region'],a['ip_prefix'],a['service']))
					quit(0)
			for a in gcp:
				if netaddr.IPNetwork(ip) in netaddr.IPNetwork(a):
					print("La IP {0} pertenece a Google Cloud Platform ({1}).".format(ip,a))
					quit(0)
			for a in azure:
				if netaddr.IPNetwork(ip) in netaddr.IPNetwork(a['ip']):
					print("La IP {0} pertenece a Microsoft Azure (region: {1} bloque: {2}).".format(ip,a['region'],a['ip']))
					quit(0)
			print("La IP {0} no es de un Cloud.".format(ip))
