The Contiki Operating System
============================

[![Build Status](https://secure.travis-ci.org/contiki-os/contiki.png)](http://travis-ci.org/contiki-os/contiki)

Contiki is an open source operating system that runs on tiny low-power
microcontrollers and makes it possible to develop applications that
make efficient use of the hardware while providing standardized
low-power wireless communication for a range of hardware platforms.

Contiki is used in numerous commercial and non-commercial systems,
such as city sound monitoring, street lights, networked electrical
power meters, industrial monitoring, radiation monitoring,
construction site monitoring, alarm systems, remote house monitoring,
and so on.

For more information, see the Contiki website:

[http://contiki-os.org](http://contiki-os.org)

AKM extensions for Contiki
==========================

This repository contains a modified version of Contiki that implements the
Adaptive Key Management (AKM) protocol. AKM is a security protocol built upon
the principle that nodes have a bounded amount of memory to perform security
related function. Consequently, they should try to make the best use of their
resources in order to connect to as many nodes as possible and form the largest
secure overlay network possible (i.e. have the best node coverage).

AKM monitors RPL messages in order to build a set of neighbors that are crucial
for connecting the node to network. This categorisation enables nodes to
remove security association with their peers when they are of lesser value than
other, more interesting, neighbors.

A new MAC layer is introduced for AKM protocol and works as a pass through for
non-AKM related message.  This MAC layer implements low level message filtering,
fragmentation and reassembly required for AKM messages.

Mutual authentication is performed using lightweight ECC certificates (shipped
as a git submodule).

This research was funded by NIST as part of the Secure Smart Grid project.
