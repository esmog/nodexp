# NodeXP - Detection and Exploitation Tool for Node.js Services!

**NodeXP** is an intergrated tool, written in Python 2.7, capable of **detecting possible vulnerabilities** on **Node.js** services as well as **exploiting** them in an automated way, based on **S**(erver)**S**(ide)**J**(avascript)**I**(njection) attack!

## Getting Started - Installation & Usage

Download NodeXP by cloning the Git repository:

	git clone https://github.com/esmog/nodexp

To get a list of all options run:

	python2.7 nodexp -h


Examples for POST and GET cases accordingly:
	
	python2.7 nodexp.py --url="http://nodegoat.herokuapp.com/contributions" --pdata="preTax=[INJECT_HERE]" -c="connect.sid=s:i6fKU7kSLPX1l00WkOxDmEfncptcZP1v.fy9whjYW0fGAvbavzYSBz1C2ZhheDuQ1SU5qpgVzbTA"
	python2.7 nodexp.py --url="http://nodegoat.herokuapp.com/contributions" --pdata="preTax=[INJECT_HERE]" -c="connect.sid=s:i6fKU7kSLPX1l00WkOxDmEfncptcZP1v.fy9whjYW0fGAvbavzYSBz1C2ZhheDuQ1SU5qpgVzbTA" --tech=blind
	
	python2.7 nodexp.py --url="http://192.168.64.30/?name=[INJECT_HERE]" -c="connect.sid=s:i6fKU7kSLPX1l00WkOxDmEfncptcZP1v.fy9whjYW0fGAvbavzYSBz1C2ZhheDuQ1SU5qpgVzbTA"
	python2.7 nodexp.py --url="http://192.168.64.30/?name=[INJECT_HERE]" -c="connect.sid=s:i6fKU7kSLPX1l00WkOxDmEfncptcZP1v.fy9whjYW0fGAvbavzYSBz1C2ZhheDuQ1SU5qpgVzbTA" --tech=blind

## Setting up and Use Testbeds

In order get familiar with NodeXP you might need to set the Node.js testing services provided (/testbeds) and start using the tool. A local machine running Node.js server will be necessary.

Firstly, you should install 'body-parser' and 'express' packages, in the GET and POST directories. 

Go to 'testbeds/GET' directory on your local machine and paste the command below in terminal:
	
	npm install express --save
		
Go to 'testbeds/POST' directory and paste the commands below in terminal:	

	npm install body-parser --save
	nmp install express --save
	
After the correct installment of the packages you could run each service by running the command 'node' and the desirable js file (ex. node eval.js).	

After you server is up and running, you are ready to run NodeXP and test it upon those services! 

Example for GET case shown below:
	
	python2.7 nodexp.py --url=http://localiprunningnodejsserver:3001/?name=[INJECT_HERE]

Example for POST case shown below: 
	
	python2.7 nodexp.py --url=http://localiprunningnodejsserver:3001/post.js --pdata=username=[INJECT_HERE]
	
## Maintain and Update Payload files

Payloads used by both Blind and Results Based Injection technique are stored in "/files/blind_payloads.txt" and in "/files/payloads.txt".

Payloads are written in every odd line number of text files and, in case of Results Based Injection, their expected responses are written in every even line number of the "payloads.txt" file as a list separeted with commas. Even line numbers of the "blind_payloads.txt" file are empty. 

In order to stop the process of injection, "---end(nextline)---end" is used as a delimeter capable of stop parsing and injecting payloads, for both Blind and Result Based Injection cases. 

Every user can maintain and update the payload txt files with its own payloads, as far as she/he follows the above instructions.

## Disclaimer

The tool’s purpose is strictly academic and was developed in order to conduct my master's thesis. It could also be helpful during the process of a penetration test on Node.js services. Any other malicious or illegal usage of the tool is strongly not recommended and is clearly not a part of the purpose of this research.


## Prerequisites

 - Python 2.7
 - Metasploit Framework
 - msfvenom
 - Kali Linux (or any other Linux distro with Metasploit Framework installed)


## NodeXP Testbeds
 
 - Download and run the Node.js files for both GET and POST cases from [here](https://github.com/esmog/nodexp/tree/master/testbeds)
 - Visit [Nodegoat](http://nodegoat.herokuapp.com) or install  [Nodegoat](https://github.com/OWASP/NodeGoat) to your local machine!


## Built With

* Python 2.7


## Versioning

NodeXP - Version 1.2.2

## Update Notes

- IDS Rules (Snort, Suricata) added, so as to detect attempts for Server Side Javascript Injection using NodeXP
- Bind shell functionality and automatic payload generation added.
- Reverse ssl shell functionality and automatic payload generation added. 
- Supports both static and dynamic payloads on Results Based Detection technique
- Supports mathematical operations and concatenation on Results Based Detection technique.
- External module added (Beta) for the generation of new payloads through the use of RNN (Recurrent Neural Network).

## Authors

* **Dimitris Antonaropoulos** - [esmog](https://github.com/esmog)

