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

The tool’s purpose is strictly academic as it is developed in order to conduct my master's thesis. It could also be helpful during the process of a penetration test on Node.js services. Any other malicious or illegal usage of the tool is strongly not recommended and is clearly not a part of the purpose of this research.


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

* **Dimitris Antonaropoulos** - [esmog](https://github.com/esmog)

