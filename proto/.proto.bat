@echo off

REM Use libprotoc 3.21.4

rem protoc --java_out=proto aspia.proto 
rem protoc --java_out=..\app\src\main\java aspia.key.exchange.proto 
rem protoc --java_out=..\app\src\main\java aspia.router.admin.proto 

I:\protoc-21.4\bin\protoc.exe --java_out=..\app\src\main\java aspia.key.exchange.proto
I:\protoc-21.4\bin\protoc.exe --java_out=..\app\src\main\java aspia.common.proto 
I:\protoc-21.4\bin\protoc.exe --java_out=..\app\src\main\java aspia.router.common.proto 
I:\protoc-21.4\bin\protoc.exe --java_out=..\app\src\main\java aspia.router.admin.proto

rem I:\protoc-21.4\bin\protoc.exe --java_out=proto aspia.key.exchange.proto
rem I:\protoc-21.4\bin\protoc.exe --java_out=proto aspia.common.proto 
rem I:\protoc-21.4\bin\protoc.exe --java_out=proto aspia.router.common.proto 
rem I:\protoc-21.4\bin\protoc.exe --java_out=proto aspia.router.admin.proto
