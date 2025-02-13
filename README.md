## What?

In this project, me and my colleagues had fun playing with a WPA2 Enterprise network architecture that we setup in order to apply a real life chain of attack. First **deauth attack**, then **evil twin attac**k and once inside the network, a **DNS spoofing attack**.

We took as reference the paper [METTER PAPER] which performed several different attacks on a wider network architecure, closer to an enterprise one.




## Table of Content

- [Introduction]()
- [Paper Results]()
- [What Is A Deep Learning Model And Where To Start Building One]()
- [Validation Split = 0.2]()







## Introduction
This project aims to examine the paper **”Empirical Evaluation of Attacks
Against IEEE 802.11 Enterprise Networks: The AWID3 Dataset”**, which
analyzes the vulnerabilities of the IEEE 802.11 protocol, with a specific focus on
attacks conducted in environments protected by security mechanisms such as Pro-
tected Management Frames (PMF) introduced with the IEEE 802.11w.




## Paper Results

The analysis conducted in the paper yielded a series of significant findings regarding
the security of IEEE 802.11 enterprise networks.


One of the most relevant aspects emerging from the study concerns the **effective-
ness of PMF** in mitigating deauthentication and disassociation attacks. In theory,
these security mechanisms should prevent attackers from sending unauthenticated
management frames to force clients to disconnect from the network. 

However, the tests revealed that, while PMF enhances protection against some attacks, its imple-
mentation varies significantly across different devices, and in some cases, it is not
sufficient to fully prevent client disconnections. One of the most relevant aspects
emerging from the study concerns the effectiveness of PMF in mitigating deauthentication and disassociation attacks. In theory, these security mechanisms should
prevent attackers from sending unauthenticated management frames to force clients
to disconnect from the network. However, the tests revealed that, while PMF en-
hances protection against some attacks, its implementation varies significantly across
different devices, and in some cases, it is not sufficient to fully prevent client discon-
nections.
