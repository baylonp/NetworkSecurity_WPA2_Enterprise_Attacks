## What?

In this project, me and my colleagues had fun playing with a WPA2 Enterprise network architecture that we setup in order to apply a real life chain of attack. First **deauth attack**, then **evil twin attac**k and once inside the network, a **DNS spoofing attack**.

We took as reference the paper [METTER PAPER] which performed several different attacks on a wider network architecure, closer to an enterprise one.




## Table of Content

- [Introduction]()
- [Paper Results]()
- [Overview of the Architecture]()
- [Let's setup]()
- [Performed Attacks]()
  - [Deauthentication]()
    - [Possible Mitigations]()
  - [Evil Twin  Attack]()
    - [Possible Mitigations]()
  - [DNS Spoofing]()
    - [Possible Mitigations]()





## Introduction
This project aims to examine the paper **”Empirical Evaluation of Attacks
Against IEEE 802.11 Enterprise Networks: The AWID3 Dataset”**, which
analyzes the vulnerabilities of the IEEE 802.11 protocol, with a specific focus on
attacks conducted in environments protected by security mechanisms such as Pro-
tected Management Frames (PMF) introduced with the IEEE 802.11w.




## Paper Results

The analysis conducted in the paper yielded a series of significant findings regarding
the security of IEEE 802.11 enterprise networks.


One of the most relevant aspects emerging from the study concerns the **effectiveness of PMF** in mitigating deauthentication and disassociation attacks. In theory,
these security mechanisms should prevent attackers from sending unauthenticated
management frames to force clients to disconnect from the network. 

However, the tests revealed that, while PMF enhances protection against some attacks, its implementation varies significantly across different devices, and in some cases, it is not
sufficient to fully prevent client disconnections. One of the most relevant aspects
emerging from the study concerns the effectiveness of PMF in mitigating deauthentication and disassociation attacks. In theory, these security mechanisms should
prevent attackers from sending unauthenticated management frames to force clients
to disconnect from the network. However, the tests revealed that, while PMF enhances protection against some attacks, its implementation varies significantly across
different devices, and in some cases, it is not sufficient to fully prevent client disconnections.


**Another interesting aspect** revealed by the analysis was the variation in security implementations across different hardware and software vendors. The
tests showed that while some Windows and Linux devices formally support PMF
and WPA3, **they exhibit significant differences in how they handle attacks**. For
example, some devices ignored unprotected deauthentication frames, while others
processed them, resulting in a connection loss—even when the protocol should theoretically prevent this. This demonstrates that the protection offered by PMF does
not solely depend on the protocol itself but also on how manufacturers implement the specifications in their devices.



## Overview of The Architecture 

The list of what was needed in our environment to make it work comprises:

- Router supporting WPA2 Enterprise
- RADIUS server (**Freeradius**) on an Ubuntu Server
- Clients for testing- PCs and Phones

We run Freeradius on a VM in a Proxmox server. The server had an assigned NIC that connected it directly to the router. We also
tried deploying an AD Domain Controller on a Windows Server for storing users credentials, the connection between Freeradius and the DC worked flawlessly but the
user authentication could not work and we decided to drop this approach relying only on the Freeradius server and users specified in its configuration file. The architecture
can be seen in the figure below. 
![image](https://github.com/user-attachments/assets/c6e91a47-6382-4f62-bf95-a6988d8adae1)


## Let's setup

The Freeradius server was setup in a way that the clients connecting to the router
needed credentials and the server provided a certificate instead. This is the basis
for the **PEAP-MSCHAPv2 authentication scheme**.

After having installed the freeradius server with: '**$ sudo apt-get install freeradius**' we needed to enable the specific freeradius module for PEAP-MSCHAPv2 authentication mechanism.

The configuration file is at: **/etc/freeradius/3.0/sites-enabled/default** and we make sure the module has the lines  **AUth-Type MS-CHAP { mschap}**  uncommented. We do this both for the Authenticate{} and the Authorize{} section.



At this point some users are needed to be in the **/etc/freeradius/3.0/users**. We added a user named **Bob** with its password being **hello** with the string **"bob" Cleartext-Password := "hello"**.

Notice that we didn’t apply any hashing techniques to the password so that the cracking process would be easier. In reality, hash+salt should be the preferred way
to store the passwords.



The second to last step is to generate the RADIUS server certificate, since the server authenticate itself to the client using them. We generate the public and private certs using the default conf. The process involves compiling with the **make** command inside the **/etc/freeradius/3.0/certs** folder.

To conclude, we set PEAP-MSCHAPv2 as the RADIUS server authentication scheme at **/etc/freeradius/3.0/mods-enabled/eap** inside the peap section.

## Performed Attacks

The attacks that we implemented have been chosen in such a way that they resemble a real chain of attack in a real scenario. First happens **reconnaissance** during which we studied the networks and decided which was the best target. The attacked network’s SSID is **TP-Link 4784**. We started with the **Deauthentication attacks**, so that the we force the connected clients to join our fake network. Then we performed an **Evil Twin Attack**, creating a fake AP in such a way that the client would be tricked into reconnecting to the network. The combination of these two types of attack ensures that the client, after being deauthenticated, can see our rogue AP as the one with the highest signal and thus wanting to connect to it. Finally, to simulate what an attacker can do after having breached into the network, we performed a **DNS spoofing attack** manipulating the ARP tables of the router and of the client, in order to demonstrate how an attacker that gain access to the network can redirect the traffic of clients. In our case, we redirected the traffic to a simple webserver that we spwaned that comprised a HTML webpage saying ”This is a fake web page, part of our DNS spoofing attack”.

## Deauthentication

For this attack, since we wanted to deeply understand the reality of what was happening under the hood, we decided to **ditch the Kali Linux Tool aireplay-ng** and choose to implement our own Python Code using the Scapy Library.

The functions that make the attack works are:
  • scan for ap(ssid, interface)
  • scan for clients(ap mac, interface)
  • disconnect user(target mac, ap mac, interface)

```python
def scan_for_ap(ssid, interface):
    print(f"Scanning for AP with SSID: {ssid}...")
    found = []  # List to save the found MAC address

    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon) and pkt.info.decode() == ssid:
            print(f"Found AP: {ssid}, MAC: {pkt.addr2}")
            found.append(pkt.addr2)
            return True

    def stop_filter(pkt):
        return len(found) > 0

    sniff(iface=interface, prn=packet_handler, timeout=10,
          store=False, stop_filter=stop_filter)

    return found[0] if found else None
```


