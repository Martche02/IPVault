@echo off

set "BRANCH_NAME="

for /f "delims=" %%I in ('git rev-parse --abbrev-ref HEAD 2^>nul') do set "BRANCH_NAME=%%I"

if "%BRANCH_NAME%"=="" (
  set "BRANCH_NAME=master"
)

setx "IPVAULT_EXTERNAL_PDB_DIR=\\PATH\TO\RELEASES\BuildProject\Solution\%BRANCH_NAME%\"