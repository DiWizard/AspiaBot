#!/bin/bash
protoc --java_out=../app/src/main/java aspia.key.exchange.proto
protoc --java_out=../app/src/main/java aspia.router.admin.proto 