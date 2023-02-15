import tempfile
import pytest
from kerberoast.__main__ import amain
import os

KERBEROS_SERVER_IP = '10.10.10.2'
KERBEROS_REALM = 'TEST.corp'
LDAP_URL_DEFAULT = 'ldap+ntlm-password://TEST\\victim:Passw0rd!1@10.10.10.2'
KERBEROS_URL_DEFAULT = 'kerberos+password://TEST\\victim:Passw0rd!1@10.10.10.2'
KERBEROS_SPN_DEFAULT = 'srv_mssql@TEST.corp'
ASREPROAST_TARGETS_DEFAULT = ['asreptest']
USERBRUTE_TAGETS = ['victim', 'Administrator', 'Guest', 'krbtgt']

class TestArgs:
    def __init__(self, command, kerberos_url = None, ldap_url = None, ldapcmd=None, out_file = None, ldapfilter = None, spn = None, targets = None, attrs = None, realm = KERBEROS_REALM, user = None, etype = None, address = None):
        self.command = command
        self.kerberos_url = kerberos_url
        self.ldap_url = ldap_url
        self.out_file = out_file
        self.spn = spn
        self.targets = targets
        self.realm = realm
        self.user = user
        self.etype = etype
        self.address = address
        self.type = ldapcmd
        self.attrs = attrs
        self.filter = ldapfilter
        if isinstance(self.targets, str):
            self.targets = [self.targets]
        if isinstance(self.user, str):
            self.user = [self.user]
        if isinstance(self.attrs, str):
            self.attrs = [self.attrs]

@pytest.mark.asyncio
async def test_tgt_file():
    with tempfile.NamedTemporaryFile() as f:
        args = TestArgs(
            'tgt',
            kerberos_url = KERBEROS_URL_DEFAULT,
            out_file = f.name
        )
        await amain(args)
        assert f.read() != b''

@pytest.mark.asyncio
async def test_tgs():
    with tempfile.NamedTemporaryFile() as f:
        args = TestArgs(
            'tgs',
            kerberos_url = KERBEROS_URL_DEFAULT,
            spn = KERBEROS_SPN_DEFAULT,
            out_file = f.name
        )
        await amain(args)
        assert f.read() != b''

@pytest.mark.asyncio
async def test_asreproast_file():
    with tempfile.NamedTemporaryFile('w') as d:
        with tempfile.NamedTemporaryFile() as f:
            args = TestArgs(
                'asreproast',
                out_file = f.name,
                user = ASREPROAST_TARGETS_DEFAULT,
                address= KERBEROS_SERVER_IP,
            )
            await amain(args)
            assert f.read() != b''

@pytest.mark.asyncio
async def test_asreproast(capsys):
    args = TestArgs(
        'asreproast',
        user = ASREPROAST_TARGETS_DEFAULT,
        address= KERBEROS_SERVER_IP,
    )
    await amain(args)
    captured = capsys.readouterr()
    
    assert captured.out.find('asrep') != -1

@pytest.mark.asyncio
async def test_spnroast_file():
    with tempfile.NamedTemporaryFile('w') as d:
        with tempfile.NamedTemporaryFile() as f:
            args = TestArgs(
                'spnroast',
                kerberos_url = KERBEROS_URL_DEFAULT,
                out_file = f.name,
                user = KERBEROS_SPN_DEFAULT,
            )
            await amain(args)
            assert f.read() != b''

@pytest.mark.asyncio
async def test_spnroast(capsys):
    args = TestArgs(
        'spnroast',
        kerberos_url = KERBEROS_URL_DEFAULT,
        user = KERBEROS_SPN_DEFAULT,
    )
    await amain(args)
    captured = capsys.readouterr()
    
    assert captured.out.find('srv_') != -1

@pytest.mark.asyncio
async def test_brute_file():
    with tempfile.NamedTemporaryFile('w') as d:
        with tempfile.NamedTemporaryFile() as f:
            args = TestArgs(
                'brute',
                address= KERBEROS_SERVER_IP,
                out_file = f.name,
                user = USERBRUTE_TAGETS,
            )
            await amain(args)
            assert f.read() != b''

@pytest.mark.asyncio
async def test_ldap_spn_file():
    try:
        fname = 'spntest'
        args = TestArgs(
            'ldap',
            ldap_url = LDAP_URL_DEFAULT,
            ldapcmd= 'spn',
            out_file = fname,
            user = USERBRUTE_TAGETS,
        )
        await amain(args)
        with open(fname+'_spn_users.txt', 'r') as f:
            assert f.read() != ''
    finally:
        os.remove(fname+'_spn_users.txt')

@pytest.mark.asyncio
async def test_ldap_spn(capsys):
    fname = 'spntest'
    args = TestArgs(
        'ldap',
        ldap_url = LDAP_URL_DEFAULT,
        ldapcmd= 'spn',
        user = USERBRUTE_TAGETS,
    )
    await amain(args)
    captured = capsys.readouterr()
    
    assert captured.out.find('srv_') != -1

@pytest.mark.asyncio
async def test_ldap_asrep_file():
    try:
        fname = 'asrep'
        args = TestArgs(
            'ldap',
            ldap_url = LDAP_URL_DEFAULT,
            ldapcmd= 'asrep',
            out_file = fname,
            user = USERBRUTE_TAGETS,
        )
        await amain(args)
        with open(fname+'_asrep_users.txt', 'r') as f:
            assert f.read() != ''
    finally:
        os.remove(fname+'_asrep_users.txt')

@pytest.mark.asyncio
async def test_ldap_asrep(capsys):
    args = TestArgs(
            'ldap',
            ldap_url = LDAP_URL_DEFAULT,
            ldapcmd= 'asrep',
            user = USERBRUTE_TAGETS,
        )
    await amain(args)
    captured = capsys.readouterr()
    
    assert captured.out.find('asreptest') != -1

@pytest.mark.asyncio
async def test_ldap_custom_file():
    try:
        fname = 'custom'
        args = TestArgs(
            'ldap',
            ldap_url = LDAP_URL_DEFAULT,
            ldapcmd= 'custom',
            out_file = fname,
            attrs = 'sAMAccountName',
            ldapfilter = '(sAMAccountName=v*)',
            user = USERBRUTE_TAGETS,
        )
        await amain(args)
        with open(fname+'_ldap_custom.tsv', 'r') as f:
            assert f.read() != ''
    finally:
        os.remove(fname+'_ldap_custom.tsv')

@pytest.mark.asyncio
async def test_ldap_custom(capsys):
    args = TestArgs(
        'ldap',
        ldap_url = LDAP_URL_DEFAULT,
        ldapcmd= 'custom',
        attrs = 'sAMAccountName',
        ldapfilter = '(sAMAccountName=v*)',
        user = USERBRUTE_TAGETS,
    )
    await amain(args)
    captured = capsys.readouterr()
    assert captured.out.find('victim') != -1

#@pytest.mark.asyncio
#async def test_ldap_asrep():
#    with tempfile.NamedTemporaryFile() as f:
#        args = TestArgs(
#            'ldap',
#            ldap_url = LDAP_URL_DEFAULT,
#            ldapcmd= 'full',
#            out_file = f.name,
#            user = USERBRUTE_TAGETS,
#        )
#        await amain(args)
#        assert f.read() != b''



if __name__ == '__main__':
    import asyncio
    asyncio.run(test_asreproast())