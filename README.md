# kerberoast
Kerberos attack toolkit -pure python-
![kerbe_card](https://user-images.githubusercontent.com/19204702/84308376-43e48700-ab13-11ea-94f2-27d2badb8540.jpg)

### Install
```pip3 install kerberoast```   

#### Prereqirements
Python 3.6
See requirements.txt


### For the impatient
IMPORTANT: the accepted target url formats for LDAP and Kerberos are the following  
```<ldap_connection_url>``` : ```<protocol>+<auth-type>://<domain>\<user>:<password>@<ip_or_hostname>/?<param1>=<value1>```  
```<kerberos_connection_url>```: ```<protocol>+<auth-type>://<domain>\<user>:<password>@<ip_or_hostname>/?<param1>=<value1>```  

Steps -with SSPI-:
```kerberoast auto <DC_ip>```  

Steps -SSPI not used-:  
1. Look for vulnerable users via LDAP  
```kerberoast ldap  all <ldap_connection_url> -o ldapenum```
2. Use ASREP roast against users in the ```ldapenum_asrep_users.txt``` file  
```kerberoast asreproast <DC_ip> -t ldapenum_asrep_users.txt```
3. Use SPN roast against users in the ```ldapenum_spn_users.txt``` file  
```kerberoast spnroast <kerberos_connection_url> -t ldapenum_spn_users.txt```
4. Crack SPN roast and ASPREP roast output with hashcat   

## Commands
### ldap
This command group is for enumerating potentially vulnerable users via LDAP.  
#### Command structure  
&nbsp;&nbsp;&nbsp;&nbsp;```kerberoast ldap <type> <ldap_connection_url> <options>```  
  
```Type```: It supports three types of users to be enumerated  
1. ```spn``` Enumerates users with ```servicePrincipalName``` attribute set.  
2. ```asrep``` Enumerates users with ```DONT_REQ_PREAUTH``` flag set in their UAC attribute.
3. ```all``` Startes all the above mentioned enumerations.

```ldap_connection_url```:  Specifies the usercredential and the target server in the msldap url format (see help)  
  
```options```:  
&nbsp;&nbsp;&nbsp;&nbsp;```-o```: Output file base name  

### brute
This command is to perform username enumeration by brute-forcing the kerberos service with possible username candidates  
#### Command structure  
&nbsp;&nbsp;&nbsp;&nbsp;```kerberoast brute <realm> <dc_ip> <targets> <options>```  
  
```realm```: The kerberos realm usually looks like ```COMPANY.corp```  
```dc_ip```: IP or hostname of the domain controller  
```targets```: Path to the file which contains the possible username candidates  
```options```:   
&nbsp;&nbsp;&nbsp;&nbsp;```-o```: Output file base name 

### asreproast
This command is to perform ASREProast attack
#### Command structure  
&nbsp;&nbsp;&nbsp;&nbsp;```kerberoast asreproast <dc_ip> <options>```  
  
```dc_ip```: IP or hostname of the domain controller  
```options```:  
&nbsp;&nbsp;&nbsp;&nbsp;```-r```: Specifies the kerberos realm to be used. It overrides all other realm info.  
&nbsp;&nbsp;&nbsp;&nbsp;```-o```: Output file base name  
&nbsp;&nbsp;&nbsp;&nbsp;```-t```: Path to the file which contains the usernames to perform the attack on   
&nbsp;&nbsp;&nbsp;&nbsp;```-u```: Specifies the user to perform the attack on. Format is either ```<username>``` or ```<username>@<realm>``` but in the first case, the ```-r``` option must be used to specify the realm  
  
## spnroast
This command is to perform SPNroast (AKA kerberoast) attack.  
#### Command structure  
&nbsp;&nbsp;&nbsp;&nbsp;```kerberoast spnroast <kerberos_connection_url> <options>```  
  
```kerberos_connection_url```: Specifies the usercredential and the target server in the kerberos URL format (see help) 

```options```:  
&nbsp;&nbsp;&nbsp;&nbsp;```-r```: Specifies the kerberos realm to be used. It overrides all other realm info.  
&nbsp;&nbsp;&nbsp;&nbsp;```-o```: Output file base name  
&nbsp;&nbsp;&nbsp;&nbsp;```-t```: Path to the file which contains the usernames to perform the attack on   
&nbsp;&nbsp;&nbsp;&nbsp;```-u```: Specifies the user to perform the attack on. Format is either ```<username>``` or ```<username>@<realm>``` but in the first case, the ```-r``` option must be used to specify the realm  
