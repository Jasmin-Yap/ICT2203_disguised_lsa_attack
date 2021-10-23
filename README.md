# ICT2203_disguised_lsa_attack
Once an OSPF neighborship has been established, it will reflood its LSA every 30 minutes (unless configured otherwise). This provides a window of oportunity for attackers to insert links to phantom routers by poisoning a router's LSDB.

![alt text](https://github.com/Jasmin-Yap/ICT2203_disguised_lsa_attack/blob/main/topology.png)

This is done by sending a packet to trigger the fightback response from our victim (router 1). After, triggering the fightback, we will spoof the victim's fightback and send the spoofed packet to the victim's neighbor (router 2) before it can receive the victim's fightback. This will poison the neighbor's LSDB with the phantom link(s).

This attack uses python and scapy to copy the original packet and create fake packets to send to the victim and neighbor.

The mitigation to this attack is to use OSPF MD5 Authentication, however this is only effective if the attacker does not know the secret key used to encrypt the data.

This code is executed via CLI via the command:
<filename>.py -v <ip of the victim router> -n <ip of the neighbor router> -i <interface that is used to sniff and send packets>
