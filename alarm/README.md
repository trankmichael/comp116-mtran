Michael Tran
COMP 116: Assignment 2
Ruby Alarm

Implemented Correctly:
	Web Server Log:
		-detects NMAP scans, HTTP errors, and SHELL code
		-parsed the lines correctly getting the correct IP, request, 
		 and attack 
		-reads a .log file and processes using the apachelogregex 
		 ruby gem
	Live Packet Analysis:
		-detects leaked credit cards (VISA, MASTERCARD, DISCOVER, AMEX)
		-detects NMAP, XMAS, and NULL scans based on the TCP flags set 
Not Implemented Correctly:
	Web Server Log:
		-The process of finding the NMAP scan makes false positives 
		 very possible.
			-The lines were analyzed and searched for the regex 
			 /nmap/i. If nmap is found anywhere else - the uri for 
			 example - a false positive would occur
		-There was some trouble finding parsing the specific protocol 
		 used, so the web server log protocol was assumed to be HTTP
	Live Packet Analysis:
		-This module was not thoroughly tested. 
		-Testing was done by generating fake packets with TCP flags 
		 matching the patterns of the three scans. 
		-Credit Cards were tested using wget on web pages containing 
		 them. At times not all the credit cards would appear,
		 specifically cards not of the format of the big four companies

Collaboration:
	Talked to Ming Chow, Tom Strassner, and Aansh Kapadia

Time Spent: 
	 ~15 hours

Questions:
	(1) Are the hueristics "even that good"?
		-The live packet analysis of the flags for the different types
		 of scans is accurate. 
		-The webserver log and credit card detection is not the best.
		 These methods generate a lot of false positives, as a lot 
		 of plaintext comes up in these files and the REGEX's used, 
		 many times, detects incidents that are not incidents.
	(2) What would I add?
		-Given more time, I would add context to the detection of things 
		 such as nmap attacks and credit card detection.  I would try to 
		 make the detection more specific. By having more specific
		 requirements for incidents, false positives would be less 
		 common. 
