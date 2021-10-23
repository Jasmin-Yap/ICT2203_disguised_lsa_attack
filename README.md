# ICT2203_disguised_lsa_attack
Once an OSPF neighborshp has been established, it will reflood its LSA every 30 minutes (unless configured otherwise). This provides a window of oportunity for attackers to insert links to phantom routers by poisoning a router's LSDB.

This is done by sending a packet to trigger the fightback response from our victim (router 1). After, triggering the fightback, we will spoof the victim's fightback and send the spoofed packet to the victim's neighbor (router 2) before it can receive the victim's fightback. This will poison the neighbor's LSDB with the phantom link(s).
