#!/bin/bash

DEST=211.224.204.132

rsync -avz dsl/src/ root@$DEST:workspace/myCloudify/dsl/src
rsync -avz restful/src/ root@$DEST:workspace/myCloudify/restful/src
rsync -avz CLI/src/ root@$DEST:workspace/myCloudify/CLI/src
