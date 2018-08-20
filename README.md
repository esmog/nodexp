# NodeXP - Detection and Exploitation Tool for Node.js Services!

**NodeXP** is an intergrated tool, written in Python 2.7, capable of **detecting possible vulnerabilities** on **Node.js** services as well as **exploiting** them in an automated way, based on **S**(erver)**S**(ide)**J**(avascript)**I**(njection) attack!

## Getting Started - Installation & Usage

Download NodeXP by cloning the Git repository:

	git clone https://github.com/esmog/nodexp

To get a list of all options run (see at the end of README.md file):

	python2.7 nodexp -h


Examples on POST and GET case accordingly:
	
	python2.7 nodexp.py --url="http://nodegoat.herokuapp.com/contributions" --pdata="preTax=[INJECT_HERE]" -c="connect.sid=s:i6fKU7kSLPX1l00WkOxDmEfncptcZP1v.fy9whjYW0fGAvbavzYSBz1C2ZhheDuQ1SU5qpgVzbTA"
	python2.7 nodexp.py --url="http://nodegoat.herokuapp.com/contributions" --pdata="preTax=[INJECT_HERE]" -c="connect.sid=s:i6fKU7kSLPX1l00WkOxDmEfncptcZP1v.fy9whjYW0fGAvbavzYSBz1C2ZhheDuQ1SU5qpgVzbTA" --tech=blind
	
	python2.7 nodexp.py --url="http://192.168.64.30/?name=[INJECT_HERE]" -c="connect.sid=s:i6fKU7kSLPX1l00WkOxDmEfncptcZP1v.fy9whjYW0fGAvbavzYSBz1C2ZhheDuQ1SU5qpgVzbTA"
	python2.7 nodexp.py --url="http://192.168.64.30/?name=[INJECT_HERE]" -c="connect.sid=s:i6fKU7kSLPX1l00WkOxDmEfncptcZP1v.fy9whjYW0fGAvbavzYSBz1C2ZhheDuQ1SU5qpgVzbTA" --tech=blind


## Disclaimer

The tool’s purpose is strictly informational and educational and the tool could also be helpful during the process of a penetration test on Node.js services. Any other malicious or illegal usage of the tool is strongly not recommended and is clearly not a part of the purpose of this research.


## Prerequisites

 - Python 2.7
 - Metasploit Framework
 - Kali Linux (or any other Linux distro with Metasploit Framework installed)

## NodeXP Testbeds
 
 - Download and run the Node.js files for both GET and POST cases from [here](https://github.com/esmog)
 - Visit [Nodegoat](http://nodegoat.herokuapp.com) or install  [Nodegoat](https://github.com/OWASP/NodeGoat) to your local machine!

## Built With

* Python 2.7


## Versioning

NodeXP - Version 1.0.0

## Authors

* **Dimitris Antonaropoulos** - *NodeXP* - [esmog](https://github.com/esmog)


## Acknowledgments

* Thank's to commix tool, in which NodeXP is based upon!


## NodeXP (argumenst help manual)

usage: nodexp.py --url URL [--pdata POST_DATA] [--cookies COOKIES]
                 [--tech {blind,result}] [--rand {char,num,all}]
                 [--digits [16-48]] [--time [100-20000]] [--loop [1-1000]]
                 [--email_length [1-24]] [--num_length [1-10]]
                 [--char_length [1-40]] [--time_factor [1.0-4.0]]
                 [--valid_loop [2-100]] [--payload_path {0,1}]
                 [--rc_path {0,1}] [--lhost LHOST] [--lport LPORT]
                 [--encode {0,1}] [--diff {0,1}] [--info {0,1}] [-h]

Arguments Help Manual For NodeXP - Server Side Javascript Injection Tool

Initial arguments:
  --url URL, -u URL     Enter the desirable URL. If it has GET parameters
                        enter "[INJECT_HERE]" on the parameter you want to
                        inject on the --url. If it uses POST data then you
                        have to use --pdata flag.
                        -u="http://test.com/?parameter=[INJECT_HERE]"
  --pdata POST_DATA, -p POST_DATA
                        Enter the POST data and place "[INJECT_HERE]" on the
                        parameter you want to inject on.
                        -p="parameter=[INJECT_HERE]"
  --cookies COOKIES, -c COOKIES
                        Enter cookies on your request headers.
  --tech {blind,result}, -t {blind,result}
                        Select an injection technique between blind injection
                        and results based injection. Keys: blind, result.
                        Default value = result

Results based injection arguments:
  --rand {char,num,all}, -r {char,num,all}
                        Select the type of random generated string between
                        characters only, numbers only or both. Keys: char,
                        num, all. Default value = char
  --digits [16-48], -d [16-48]
                        Enter the number of digits or chars of the random
                        generated string, between 16 to 48. Default value = 16

Blind injection arguments:
  --time [100-20000], -time [100-20000]
                        Time threshold on blind injection in millieseconds.
                        Default value = 250
  --loop [1-1000], -l [1-1000]
                        Number of requests done to specify the average
                        response time. Be careful, big values may be
                        considered as brute force or dos attacks by website.
                        Default value = 10
  --email_length [1-24], -elen [1-24]
                        Length of the characters given as input to the
                        vulnerable parameter, ex. email='testing@gmail.com'.
                        Default value = 9
  --num_length [1-10], -nlen [1-10]
                        Length of the characters given as input to the
                        vulnerable parameter. ex. tel=2102589834. Default
                        value = 2
  --char_length [1-40], -clen [1-40]
                        Length of the characters given as input to the
                        vulnerable parameter. ex. input='My Surname'. Default
                        value = 10
  --time_factor [1.0-4.0], -time_factor [1.0-4.0]
                        Time factor for minimum time threshold. Default value
                        = 2
  --valid_loop [2-100], -valid_loop [2-100]
                        Number of requests done to specify the validity of the
                        blind injection results. Be careful, big values may be
                        considered as brute force or dos attacks by
                        webservers. Default value = 10

Exploitation arguments:
  --payload_path {0,1}, -pp {0,1}
                        Set payload path to default or type new payload path
                        later. The payload name will be 'nodejs_payload.js'.
                        Default value = 1 (cwd/scripts/) ex. -pp=1
  --rc_path {0,1}, -rp {0,1}
                        Set .rc script path to default or type new .rc script
                        path later. The .rc script name will be
                        'nodejs_shell.rc' Default value = 1 (cwd/scripts/) ex.
                        -rp=1"
  --lhost LHOST, -lh LHOST
                        Local host ip address. ex. -lh="192.168.1.1"
  --lport LPORT, -lp LPORT
                        Ip address port number. ex. -lp="6666"
  --encode {0,1}, -enc {0,1}
                        Base64 encoding on your payload. Default value = 1 ex.
                        -enc=1

Printing arguments:
  --diff {0,1}, -diff {0,1}
                        Print the HTML differences of the responses between
                        valid and malicious requests. Default value = 1
  --info {0,1}, -info {0,1}
                        Print additional info. Default value = 1

Other arguments:
  -h, --help            Show this help message and exit.
