# mosipcertmanager
Helm chart for installing mosipcertmanager

## Introduction
It's a cronjob that checks partner certificate expiry dates and renews the certificates if expired.

## Install
* Review the `values.yaml` file and ensure that the database parameter values are set according to your environment
* RUN Install script
```
./install.sh
```

# TL;DR
```console
$ helm repo add mosip https://mosip.github.io
$ helm install my-release mosip/mosipcertmanager
```