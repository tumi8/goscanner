# TUM goscanner

[![Build Status](https://travis-ci.org/tumi8/goscanner.svg?branch=master)](https://travis-ci.org/tumi8/goscanner)


goscanner is a tool for large-scale TLS, x509 Certificate, HTTP header, 
and SSH scans developed at the TUM Chair of Network Architectures and Services (see [Authors](./AUTHORS.md)).

Update (2022-05-24): goscanner is now able to [actively fingerprint TLS servers](https://active-tls-fingerprinting.github.io)

## Building

Steps for building goscanner:

1. Set up your go environment
2. Run `make`

## Configuring Scans

goscanner supports multipe types of scans. Among them are [ tls, http, ssh, scvs].
Some scans can be chained (e.g., tls and http to scan https). 
In these cases they will reuse the same TCP connection.
See `example.conf` how to configure the default https scan.

## Input

goscanner needs a list of resolved IPv4 or Ipv6 address [:Port] [,domain name [,client hello]] tuples as input.
The domain and  client hello is optional. 
If a domain is present, it will be used as SNI.
If present, the TLS scan will use the provided client hello for scanning.

Example input.csv:

    172.217.22.78,google.com,client_hello_1
    172.217.22.78,google.com,client_hello_2
    172.217.22.78,,client_hello_2
    140.82.121.4,github.com
    [::1]:8443
    ::1

The IP, domain tuples can be generated, for example, with [massdns](https://github.com/blechschmidt/massdns)

    bin/massdns -r local_resolvers.txt input_domains.txt -q -o J \
    | jq '[.name,.data.answers[-1].data]  | @csv' -r \
    | csvtool col 1,2 - | awk -F, '$2!=""' > input.csv

goscanner provides a utility function to enhance the input with the client hellos 
(we recommend randomizing the input to reduce bursts on target servers):

    ./goscanner create-ch-input --ch-dir ./client-hellos --input input.csv | shuf > input-chs.csv

The client hello is the name of a json file (e.g., `client_hello_1.json`). 
All client hellos can be loaded from a directory with the config option

    client-hello-dir = ./client-hellos

## Generating CHs

The Client Hellos (CHs) used for the TLS scan can be configured.
They are loaded from `.json` files and several CHs are already built in the scanner (including CHs built after [JARM](https://github.com/salesforce/jarm)).
They can be generated with

    ./goscanner create-ch --out client-hellos -c custom
    ./goscanner create-ch --out client-hellos -c jarm

goscanner is also able to generate random CHs. However, there is no guarantee these are functional CHs.
goscanner will download possible parameters for the CHs from IANA into the `tmp` directory.

    ./goscanner create-ch --out ./client-hellos -c random --num-random 1000 --tmp ./tmp


## Active TLS Stack Fingerprinting

goscanner is able to fingerprint TLS servers as described by [Active TLS Stack Fingerprinting](https://active-tls-fingerprinting.github.io).
Additionally, this site provides optimized client hellos for fingerprinting.

The goscanner is able to post-process a scan with multiple CHs per target to generate the fingerprints.

    ./goscanner generate-fingerprints --scanner-dir ./tls-scanner-output [-ch-dir ./client-hellos]

## Reading logs

To get better human-readable logs from the json output you can use

    go get -u github.com/mightyguava/jl/cmd/jl
    
Just pipe your logs to `jl --format logfmt`. e.g.

    tail scanner.log | jl --format logfmt
