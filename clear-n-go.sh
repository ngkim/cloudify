#!/bin/bash

HOST=$1

ssh-keygen -f "/home/ngkim/.ssh/known_hosts" -R $HOST
ssh root@$HOST

