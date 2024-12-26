# AspiaBot
Dynamic DNS realization for Aspia remote control application (https://aspia.org)

Usage
-------------------

```
AspiaBot [-hvsgjdomti] -a=ip[:port] -u=user -p=password

Required arguments: 
  -a=<..>, --address=<..>	Aspia router IP adress [:optional port numbet]
  -u=<..>, --file=<..>		Aspia user with administrator rights
  -p=<..>, --file=<..>		Password for Aspia user

Optional arguments: 
  -h, --help			this help
  -v, --silent			print version
  -s, --silent			silent mode
  -g, --debug			print full session debug
  -j, --jvm			print Java runtime environment
  -d, --domain			set additional domain name for hosts' records
  -o=<..>, --hosts=<..>		path to system's hosts file
  -m=<..>, --memeo=<..>		add mnemonic names for hosts' records
  -t=<..>, --timeout=<..>	set timeout (in seconds) for TCP/IP session
  -i=<..>, --id=<..>		print TCP/IP address for requred ID

Mandatory arguments to long options are mandatory for short options too.
```
Usage example (basic)
---------------------
Linux
``` sh
sudo AspiaBot -a=1.2.3.4 -u=admin -p=password -o=/etc/hosts
```
Mac OS
``` sh
sudo AspiaBot -a=1.2.3.4 -u=admin -p=password -o=/private/etc/hosts
```
Windows
``` sh
AspiaBot -a=1.2.3.4 -u=admin -p=password -o="c:\windows\system32\drivers\etc\hosts"
```

Usage example (advanced)
------------------------
List all active session on router:
``` sh
AspiaBot -a=1.2.3.4 -u=admin -p=password
```
Get IP-address by ID:
``` sh
AspiaBot -a=1.2.3.4 -u=admin -p=password -i=8 -s
```
Add additional name for some host records:
``` sh
sudo AspiaBot -a=1.2.3.4 -u=admin -p=password -o=/etc/hosts -m"3:sql;9:Fido;18:doe_j"
```

Direct run (for scheduled tasks)
--------------------------------

Linux/MacOS
``` sh
/Library/Java/JavaVirtualMachines/zulu-8.jdk/Contents/Home/bin/java -cp "/Users/Shared/AspiaBot/lib/*" info.malenkov.aspiabot.App -a="1.2.3.4" -u="admin" -p="password" -o="/etc/hosts" -m"3:sql;9:Fido;18:doe_j"
```

Windows
``` sh
C:\PROGRA~1\Zulu\zulu-8\bin\java.exe -cp C:\PROGRA~1\AspiaBot\lib\* info.malenkov.aspiabot.App -a="1.2.3.4" -u="admin" -p="password" -o="/etc/hosts" -m"3:sql;9:Fido;18:doe_j"
```

System requirements
-------------------
- Java 8 or higher 

Contacts
--------
E-Mail: maxim.v.malenkov@gmail.com

Licensing
---------
Project code is available under the GNU General Public License 2.
