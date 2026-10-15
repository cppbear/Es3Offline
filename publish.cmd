@echo off
rem Single-file self-contained exe -> Es3Offline\publish\Es3Offline.exe
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -o publish
