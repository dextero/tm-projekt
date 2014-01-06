#!/bin/bash

ifconfig lo inet6 del '::1'
ifconfig lo inet6 add '::1/124'
ifconfig lo mtu 1500 up
