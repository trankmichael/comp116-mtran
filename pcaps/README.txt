Michael Tran
Comp 116 - Ming Chow
HW 1

set1.pcap
1. 1503 packets
2. FTP
3. FTP files are not encrypted and they are transferred as plain text,
   ready to be read by any observer.
4. SFTP
5. 67.23.79.113
6. USER: ihackpineapples
   PASS rockyou1
7. 4 files
8. BjN-O1hCAAAZbiq.jpg
   BvgT9p2IQAEEoHu.jpg
   BvzjaN-IQAA3Xg7.jpg
   smash.txt
9. files included

set2.pcap
10. 77882 packets
11. USER: chris@digitalinterlude.com
    PASS: Volrathw69
    USER: 1
    PASS: 
	3 PAIRS FOUND chris@digitalinterlude.com was found twice.
12. ettercap -T -r set2.pcap | grep "PASS" 
    I read the set2.pcap file using the ettercap text console and funneled that
    into grep which searched for the string "PASS" 
13. Pair 1: chris@digitalinterlude.com:Volrathw69
	-protocol: POP3
	-server IP: 75.126.75.131
	-domain: 		
	-port number: 110
    Pair 2: 1 0 
	-protocol: TCP
	-server IP: 75.127.96.187
	-domain: defcon-wireless-village.com
	-port number: 80 
	
14. 1
15. In WireShark I filtered the POP protocol and followed the TCP 
    stream matching the first password pair.  In the stream it showed
    that Chris had successfully logged on and logged off after sending
    a few emails.
16. I would recommend firstly not using open connection where network 
    traffic could be collected by any one watching in the form of pcap
    files. Secondly, I would recommend using the SSL/TLS protocols to
    access these accounts. I believe there are other forms of encrypted
    authentication methods supported by POP as well.  Plain text 
    unencrypted passwords and usernames is insecure. 

