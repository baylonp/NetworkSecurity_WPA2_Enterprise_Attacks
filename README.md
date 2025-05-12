## What?

In this project, me and my colleagues had fun playing with a WPA2 Enterprise network architecture that we setup in order to apply a real life chain of attack. First **deauth attack**, then **evil twin attac**k and once inside the network, a **DNS spoofing attack**.

We took as reference the paper [METTER PAPER] which performed several different attacks on a wider network architecure, closer to an enterprise one.




## Table of Content

- [Introduction]()
- [Paper Results]()
- [Overview of the Architecture]()
- [Let's setup]()
- []()
- 







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
can be seen in figure. 
![image](https://github.com/user-attachments/assets/ad59f992-c61f-42d8-b3bd-65384bd3fce6)


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



