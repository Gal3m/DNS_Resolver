Prerequisites: 
The following modules must be installed: dnspython (for making DNS queries)
Commands to run:
	pip install dnspython
	pip install cryptography

Folder Structure:

resolver.py is the solution python program for part 1 of the assignment.
mydig.sh is a shell script for running resolver.py
dnssec.py is the solution python program for part 2 of the assignment.
dnssec.sh is a shell script for running dnssec.py
mydig_output.txt contains the output of resolver.py
DNSSEC_implementation.pdf: contains the DNSSEC implementation details. 
PartC.pdf contains output graph and it's implications

Instructions on how to run my programs:
please give execute permission to shell scripts
	chown +x *.sh
Part 1:
	python3 resolver.py <Domain_Name> <Record_Type>
	mydig.sh <Domain_Name> <Record_Type>

Part 2:	
	python3 dnssec.py <Domain_Name> <Record_Type>
	dnssec.sh <Domain_Name> <Record_Type>

Based on assignment description we should implement for A record type.

	python3 dnssec.py <Domain_Name> A
	dnssec.sh <Domain_Name> A