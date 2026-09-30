# SABRE

SABRE is a prototype implementation of a programmable relay network for Bitcoin block propagation, developed as part of a Bachelor's thesis project.

The project uses a P4-programmable switch and a python controller to implement and manage the relay network.

## Technologies

* P4
* P4Runtime
* BMv2
* Mininet
* Python
* Scapy
* TCP / UDP
* Bitcoin Core 

## Components

* `codiceP4.p4` — P4 data-plane implementation
* `controller.py` — Python control-plane implementation
* `topo.py` — Mininet testing network topology
* `sabre.p4info.txt` — P4Runtime interface description
* `codiceP4.json` — compiled P4 switch configuration
* Test scripts — used to test the controller and SABRE protocol

## Status

Prototype developed for academic purposes as part of a Bachelor's thesis.

The repository is currently being reviewed and further development and documentation will follow.
