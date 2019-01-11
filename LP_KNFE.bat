REM Logparser  Batch File for FRS NIRT and LIRTs Analyzing Surge Triage output.

REM Security Log *************************************************
REM Simple Queries ***********************************************

REM Find Event id
REM LogParser.exe -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5038'"

REM Eventid 1102
REM Eventlog was cleared
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') as Username, EXTRACT_TOKEN(Strings, 2, '|') AS Workstation FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '1102'"

REM Eventid 4624
REM successful logon
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType,EXTRACT_TOKEN(strings, 9, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY')"

REM Find specific user
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType,EXTRACT_TOKEN(strings, 9, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND Username = 'Administrator'"

REM Find RDP logons
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType,EXTRACT_TOKEN(strings, 9, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND LogonType = '10'"

REM Find console logons
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType,EXTRACT_TOKEN(strings, 9, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND LogonType = '2' AND ProcessName NOT LIKE '\%Retina\%'"

REM Find specific IP
REM Change IP to item of interest / IOC
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType,EXTRACT_TOKEN(strings, 9, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND SourceIP = '10.1.47.151'"

REM look at NTLM based logons 
REM possible pass-the-hash 
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType, EXTRACT_TOKEN(strings, 10, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND AuthPackage LIKE '%NtLmSsp%' AND Username NOT LIKE '%$'"

REM
REM Event id 4625
REM unsuccessful logon
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 10, '|') as LogonType,EXTRACT_TOKEN(strings, 11, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 13, '|') AS Workstation, EXTRACT_TOKEN(Strings, 19, '|') AS SourceIP FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4625 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY')"

REM Find specific User
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 10, '|') as LogonType,EXTRACT_TOKEN(strings, 11, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 13, '|') AS Workstation, EXTRACT_TOKEN(Strings, 19, '|') AS SourceIP FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4625 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND Username = 'Administrator'"


REM Find specific IP
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 10, '|') as LogonType,EXTRACT_TOKEN(strings, 11, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 13, '|') AS Workstation, EXTRACT_TOKEN(Strings, 19, '|') AS SourceIP FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4625 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND SourceIP = '10.1.47.151'"

REM check ntlm based attempts
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 10, '|') as LogonType, EXTRACT_TOKEN(strings, 11, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 13, '|') AS Workstation, EXTRACT_TOKEN(Strings, 19, '|') AS SourceIP FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4625 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND AuthPackage LIKE '%NtLmSsp%' AND Username NOT LIKE '%$'"

REM event id 4634
REM user logoff

REM LogParser.exe -stats:OFF -i:EVT "Select TimeGenerated ASREM Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4634 AND Domain NOT IN ('NT AUTHORITY')"

REM Event id 4648
REM explicit creds was used
REM <<too noisy>> LogParser.exe -stats:OFF -i:EVT "SELECT timegenerated as date, extract_token(strings, 1, '|') as accountname, extract_token(strings, 2, '|') as domain, extract_token(strings, 5, '|') as usedaccount, extract_token(strings, 6, '|') as useddomain, extract_token(strings, 8, '|') as targetserver, extract_token(strings, 9, '|') as extradata, extract_token(strings, 11, '|') as procname, extract_token(strings, 12, '|') as sourceip FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4648"

REM Search by accountname
 LogParser.exe -stats:OFF -i:EVT "SELECT timegenerated as date, extract_token(strings, 1, '|') as accountname, extract_token(strings, 2, '|') as domain, extract_token(strings, 5, '|') as usedaccount, extract_token(strings, 6, '|') as useddomain, extract_token(strings, 8, '|') as targetserver, extract_token(strings, 9, '|') as extradata, extract_token(strings, 11, '|') as procname, extract_token(strings, 12, '|') as sourceip FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4648 AND accountname = 'Administrator'"

REM Search by usedaccount
 LogParser.exe -stats:OFF -i:EVT "SELECT timegenerated as date, extract_token(strings, 1, '|') as accountname, extract_token(strings, 2, '|') as domain, extract_token(strings, 5, '|') as usedaccount, extract_token(strings, 6, '|') as useddomain, extract_token(strings, 8, '|') as targetserver, extract_token(strings, 9, '|') as extradata, extract_token(strings, 11, '|') as procname, extract_token(strings, 12, '|') as sourceip FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4648 AND usedaccount = 'Administrator'"

REM event id 4657
REM A registry value was modified
REM LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '4657'"

REM event id 4663
REM An attempt was made to access an object
LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '4663'"

REM Event id 4672
REM Admin logon

LogParser.exe -stats:OFF -i:EVT "Select TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4672 AND Domain NOT IN ('NT AUTHORITY')

REM Find specific user
REM  LogParser.exe -stats:OFF -i:EVT "Select TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4672 AND Domain NOT IN ('NT AUTHORITY') AND Username = 'Administrator'"

REM event id 4688
REM new process was created
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain, EXTRACT_TOKEN(Strings, 5, '|') AS Process FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4688"
 
REM Search by user
REM LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain, EXTRACT_TOKEN(Strings, 5, '|') AS Process FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4688 AND Username = 'Administrator'"

REM Search by process name
REM LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain, EXTRACT_TOKEN(Strings, 5, '|') AS Process FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4688 AND Process LIKE '%rundll32.exe%'"

REM event id 4704
REM A user right was assigned
LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '4704'"

REM event id 4705
REM A user right was removed
LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '4705'"

REM event id 4706
REM A new trust was created to a domain
REM Not useful on workstations.
REM LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '4706'"

REM event id 4720
REM A user account was created 
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(Strings, 0, '|') AS createduser, extract_token(strings, 1, '|') AS createddomain, extract_token(strings, 4, '|') as whocreated, extract_token(strings, 5, '|') AS whodomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '4720'"

REM Event id 4722
REM user account was enabled
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4722"

REM event id 4723
REM attempt to change password for the account - user changed his own password
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4723"

REM event id 4724
REM attempt to reset user 
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4724"
REM event id 4725 
REM user account was disabled
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4725"

REM ****************************************************************************
REM ** JP CERT and SANS Know Normal Find Evil **********************************
REM ****************************************************************************

LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 5140"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4702"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4701"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4700"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4699"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4698"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4697"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4672"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4648"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4648"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4624"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4688"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4689"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 5140"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 5156"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4672"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4656"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4663"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 5410"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 5154"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4656"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4660"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4658"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4634"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 5142"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 5154"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 5154"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 5144"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 5447"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4946"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4769"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 5145"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4768"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4769"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4762"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4673"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 8222"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4656"
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4720"
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
REM event id 4726
REM A user account was deleted 
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(Strings, 0, '|') AS deleteduser, extract_token(strings, 1, '|') AS deleteddomain, extract_token(strings, 4, '|') as whodeleted, extract_token(strings, 5, '|') AS whodomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '4726'"

REM event id 4727
REM A security-enabled global group was created 
 LogParser.exe -stats:OFF -i:EVT "SELECT *  FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '4727'"

REM event id 4728
REM A member was added to a security-enabled global group
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(Strings, 0, '|') as addeduser, extract_token(strings, 2, '|') as togroup, extract_token(strings, 3, '|') as groupdomain, extract_token(strings, 6, '|') as whoadded, extract_token(strings, 7, '|') as whodomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '4728'"

REM event id 4729
REM A member was removed from a security-enabled global group
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(Strings, 0, '|') as removeduser, extract_token(strings, 2, '|') as fromgroup, extract_token(strings, 3, '|') as groupdomain, extract_token(strings, 6, '|') as whoremoved, extract_token(strings, 7, '|') as whodomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '4729'"

REM event id 4730
REM A security-enabled global group was deleted
 LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '4730'"


REM event id 4731
REM A security-enabled local group was created 
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as createdgroup, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4731"

REM event id 4732
REM  A member was added to a security-enabled local group
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(Strings, 0, '|') as addeduser, extract_token(strings, 2, '|') as togroup, extract_token(strings, 3, '|') as groupdomain, extract_token(strings, 6, '|') as whoadded, extract_token(strings, 7, '|') as whodomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '4732'"

REM event id 4733
REM A member was removed from a security-enabled local group
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(Strings, 0, '|') as removeduser, extract_token(strings, 2, '|') as fromgroup, extract_token(strings, 3, '|') as groupdomain, extract_token(strings, 6, '|') as whoremoved, extract_token(strings, 7, '|') as whodomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '4733'"

REM event id 4734
REM  A security-enabled local group was deleted
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 2, '|') AS whichgroup, EXTRACT_TOKEN(Strings, 3, '|') AS domaingroup, EXTRACT_TOKEN(Strings, 6, '|') AS who, EXTRACT_TOKEN(Strings, 7, '|') AS workstation FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4734"




REM event id 4738
REM user account was changed 
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 1, '|') as user, extract_token(strings, 2, '|') as domain, extract_token(strings, 5, '|') as whichaccount, extract_token(strings, 6, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4738"

REM event id 4740
REM A user account was locked out
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as workstation, extract_token(strings, 4, '|') as wholocked, extract_token(strings, 5, '|') as whodomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '4740'"

REM event id 4742
REM computer account was changed 
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 5, '|') as user, extract_token(strings, 6, '|') as domain, extract_token(strings, 1, '|') as whichaccount, extract_token(strings, 2, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4742"

REM event id 4754
REM A security-enabled universal group was created
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as createdgroup, extract_token(strings, 1, '|') as domain, extract_token(strings, 4, '|') as whichaccount, extract_token(strings, 5, '|') as whichdomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4754"

REM event id 4756
REM  	A member was added to a security-enabled universal group
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(Strings, 0, '|') as addeduser, extract_token(strings, 2, '|') as togroup, extract_token(strings, 3, '|') as groupdomain, extract_token(strings, 6, '|') as whoadded, extract_token(strings, 7, '|') as whodomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '4756'"

REM event id 4757
REM A member was removed from a security-enabled universal group
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(Strings, 0, '|') as removeduser, extract_token(strings, 2, '|') as fromgroup, extract_token(strings, 3, '|') as groupdomain, extract_token(strings, 6, '|') as whoremoved, extract_token(strings, 7, '|') as whodomain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '4757'"

REM event id 4758
REM  A security-enabled universal group was deleted
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 2, '|') AS whichgroup, EXTRACT_TOKEN(Strings, 3, '|') AS domaingroup, EXTRACT_TOKEN(Strings, 6, '|') AS who, EXTRACT_TOKEN(Strings, 7, '|') AS workstation FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4758"


REM event id 4767
REM A user account was unlocked
 LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '4767'"


REM event id 4768
REM Kerberos TGT was requested
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 7, '|') as cipher, extract_token(strings, 9, '|') as sourceip FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4768"


REM event id 4769
REM Kerberos Service ticket was requested
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0, '|') as user, extract_token(strings, 1, '|') as domain, extract_token(strings, 2, '|') as service, extract_token(strings, 5, '|') as cipher, extract_token(strings, 6, '|') as sourceip FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4769"




REM event id 4771
REM kerberos pre-atuhentication failed
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 0 , '|') as user, extract_token(strings, 6 , '|') as sourceip FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4771 AND user NOT LIKE '%$'"




REM event id 4776
REM domain/computer attemped to validate user credentials
 LogParser.exe -stats:OFF -i:EVT "Select TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4776 AND Domain NOT IN ('NT AUTHORITY') AND Username NOT LIKE '%$'"
REM Search by username
 LogParser.exe -stats:OFF -i:EVT "Select TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4776 AND Domain NOT IN ('NT AUTHORITY') AND Username NOT LIKE '%$' AND Username = 'Administrator'"



REM event id 4778 
REM RDP session reconnected
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date,EXTRACT_TOKEN(Strings, 0, '|') AS Username, EXTRACT_TOKEN(Strings, 1, '|') AS Domain, EXTRACT_TOKEN(Strings, 4, '|') AS Workstation, EXTRACT_TOKEN(Strings, 5, '|') AS SourceIP  FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4778"

REM event id 4779
REM RDP session disconnected
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date,EXTRACT_TOKEN(Strings, 0, '|') AS Username, EXTRACT_TOKEN(Strings, 1, '|') AS Domain, EXTRACT_TOKEN(Strings, 4, '|') AS Workstation, EXTRACT_TOKEN(Strings, 5, '|') AS SourceIP  FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4779"

REM event id 4781
REM User account was renamed
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 0, '|') AS newname, EXTRACT_TOKEN(Strings, 1, '|') AS oldname, EXTRACT_TOKEN(Strings, 2, '|') AS accdomain, EXTRACT_TOKEN(Strings, 5, '|') AS Username, EXTRACT_TOKEN(Strings, 6, '|') AS Domain FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4781"

REM event id 4825
REM RDP Access denied
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 0, '|') AS Username, EXTRACT_TOKEN(Strings, 1, '|') AS Domain, EXTRACT_TOKEN(Strings, 3, '|') AS SourceIP FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4825"


REM event id 4946
REM new exception was added to firewall
 LogParser.exe -stats:OFF -i:EVT "Select TimeGenerated AS Date, extract_token(strings, 2, '|') as rulename FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4946"

REM event id 4948
REM rule was deleted from firewall 
 LogParser.exe -stats:OFF -i:EVT "Select TimeGenerated AS Date, extract_token(strings, 2, '|') as rulename FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4948"


REM event id 5038
REM Code integrity determined that the image hash of a file is not valid
 LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5038'"

REM event id 5136
REM A directory service object was modified
 LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, extract_token(strings, 3, '|') AS Username, extract_token(strings, 4, '|') AS Domain, extract_token(strings, 8, '|') AS objectdn, extract_token(strings, 10, '|') AS objectclass, extract_token(strings, 11, '|') AS objectattrib, extract_token(strings, 13, '|') AS attribvalue FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5136'"


REM event id 5137
REM A directory service object was created
 LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5137'"

REM event id 5138
REM A directory service object was undeleted
 LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5138'"

REM event id 5139
REM A directory service object was moved
 LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5139'"

REM event id 5141
REM A directory service object was deleted
 LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5141'"

REM event id 5140
REM A network share object was accessed
 LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5140'"

REM event id 5142
REM A network share object was added
 LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5142'"

REM event id 5143
REM A network share object was modified
 LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5143'"

REM event id 5144
REM A network share object was deleted
 LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5144'"

REM event id 5145
REM A network share object was checked to see whether client can be granted desired access
 LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5145'"


REM event id 5154
REM The Windows Filtering Platform has permitted an application or service to listen on a port for incoming connections
 LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5154'"

REM event id 5155
REM The Windows Filtering Platform has blocked an application or service from listening on a port for incoming connections
 LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5155'"

REM event id 5156
REM The Windows Filtering Platform has allowed a connection
 LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5156'"

REM event id 5157
REM The Windows Filtering Platform has blocked a connection
 LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5157'"

REM event id 5158
REM The Windows Filtering Platform has permitted a bind to a local port
 LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5158'"

REM event id 5159
REM The Windows Filtering Platform has blocked a bind to a local port
 LogParser.exe -stats:OFF -i:EVT "SELECT * FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = '5159'"

REMREMREMREMREMREMREMREMREMREMREMREMREM
REM System Log
REMREMREMREMREMREMREMREMREMREMREMREMREM
REM EventID 7045 
REM New Service was installed in system
 LogParser.exe -stats:OFF -i:EVT "Select TimeGenerated AS Date, extract_token(strings, 0, '|') AS ServiceName, extract_token(strings, 1, '|') AS ServicePath, extract_token(strings, 4, '|') AS ServiceUser FROM System.evtx WHERE EventID = 7045"


REM EventID 7036
REM Service actions
 LogParser.exe -stats:OFF -i:EVT "Select TimeGenerated AS Date, extract_token(strings, 0, '|') as servicename FROM System.evtx WHERE EventID = 7036"


REMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREM
REM Task Scheduler Log
REMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREM
REM EventID 100 
REM Task was run
 LogParser.exe -stats:OFF -i:EVT "Select TimeGenerated AS Date, extract_token(strings,0, '|') as taskname, extract_token(strings, 1, '|') as username FROM '.\files\c\windows\system32\winevt\logs\Microsoft-Windows-TaskScheduler%4Operational.evtx' WHERE EventID = 100"

REM eventid 200
REM action was executed
 LogParser.exe -stats:OFF -i:EVT "Select TimeGenerated AS Date, extract_token(strings,0, '|') as taskname, extract_token(strings, 1, '|') as taskaction FROM '.\files\c\windows\system32\winevt\logs\Microsoft-Windows-TaskScheduler%4Operational.evtx' WHERE EventID = 200"


REM eventid 140
REM user updated a task

 LogParser.exe -stats:OFF -i:EVT "Select TimeGenerated as Date, extract_token(strings, 0, '|') as taskname, extract_token(strings, 1, '|') as user FROM '.\files\c\windows\system32\winevt\logs\Microsoft-Windows-TaskScheduler%4Operational.evtx' WHERE EventID = 140"


REM event id 141 
REM user deleted a task
 LogParser.exe -stats:OFF -i:EVT "Select TimeGenerated as Date, extract_token(strings, 0, '|') as taskname, extract_token(strings, 1, '|') as user FROM '.\files\c\windows\system32\winevt\logs\Microsoft-Windows-TaskScheduler%4Operational.evtx' WHERE EventID = 141"

REMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREM
REM Windows Firewall Log
REMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREM
REM EventID 2004
REM New exception rule was added
 LogParser.exe -stats:OFF -i:EVT "Select TimeGenerated AS Date, extract_token(strings, 1, '|') as rulename, extract_token(strings, 3, '|') as apppath, extract_token(strings, 22, '|') as changedapp FROM '.\files\c\windows\system32\winevt\logs\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx' WHERE EventID = 2004"


REM event id 2005
REM rule was changed 
 LogParser.exe -stats:OFF -i:EVT "Select TimeGenerated AS Date, extract_token(Strings, 1, '|') as rulename, extract_token(Strings, 3, '|') AS apppath, extract_token(Strings, 4, '|') AS servicename, extract_token(strings, 7, '|') AS localport, extract_token(strings, 22, '|') as modifyingapp  FROM '.\files\c\windows\system32\winevt\logs\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx' WHERE EventID = 2005"

REM event id 2006
REM rule was deleted
 LogParser.exe -stats:OFF -i:EVT "Select TimeGenerated AS Date, extract_token(Strings, 1, '|') as rulename, extract_token(strings, 3, '|') as changedapp FROM '.\files\c\windows\system32\winevt\logs\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx' WHERE EventID = 2006"

REM EventID 2011
REM Firewall blocked inbound connections to the application, but did not notify the user
 LogParser.exe -stats:OFF -i:EVT "Select Timegenerated as date, extract_token(strings, 1, '|') as file, extract_token(strings, 4, '|') as port FROM '.\files\c\windows\system32\winevt\logs\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx' WHERE EventID = 2011"

REMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREM
REM RDP LocalSession Log 
REM Local logins 
REMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREM
REM Event id 21
REM Successful logon
 LogParser.exe -stats:OFF -i:EVT "Select timegenerated as Date, extract_token(strings, 0, '|') as user, extract_token(strings, 2, '|') as sourceip FROM '.\files\c\windows\system32\winevt\logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx' WHERE EventID = 21"

REM find specific user
 LogParser.exe -stats:OFF -i:EVT "Select timegenerated as Date, extract_token(strings, 0, '|') as user, extract_token(strings, 2, '|') as sourceip FROM '.\files\c\windows\system32\winevt\logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx' WHERE EventID = 21 AND user LIKE '%Administrator%'"



REMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREM
REM RDP RemoteSession Log
REMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREM
REM Event ID 1149
REM Successful logon
 LogParser.exe -stats:OFF -i:EVT "Select timegenerated as Date, extract_token(strings, 0, '|') as user, extract_token(strings, 2, '|') as sourceip FROM '.\files\c\windows\system32\winevt\logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx' WHERE EventID = 1149"
 
 
REMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREM
REM Suspicious Commands/Procs associated with possible Recon
REMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREMREM
LogParser.exe -stats:OFF -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 1, '|') AS Username, EXTRACT_TOKEN(Strings, 2, '|') AS Domain, EXTRACT_TOKEN(Strings, 5, '|') AS Process FROM '.\files\c\windows\system32\winevt\logs\Security.evtx' WHERE EventID = 4688 AND (Process LIKE '%\\at.exe'  OR Process LIKE '%\\ceipdata.exe'  OR Process LIKE '%\\ceiprole.exe'  OR  Process LIKE '%\\chcp.exe' OR Process LIKE '%\\cmd.exe'  OR Process LIKE '%\\compmgmtlauncher.exe'  OR Process LIKE '%\\csvde.exe'  OR Process LIKE '%\\dsget.exe' OR Process LIKE '%\\dsquery.exe'  OR Process LIKE '%\\esentutl.exe'  OR Process LIKE '%\\\\find.exe'  OR Process LIKE '%\\fsutil.exe'  OR Process LIKE '%\\hostname.exe'  OR Process LIKE '%\\ipconfig.exe'  OR Process LIKE '%\\ldifde.exe'  OR Process LIKE '%\\nbtstat.exe'  OR Process LIKE '%\\net.exe'  OR Process LIKE '%\\net1.exe'  OR Process LIKE '%\\netdom.exe' OR Process LIKE '%\\netsh.exe' OR Process LIKE '%\\netstat.exe' OR Process LIKE '%\\nltest.exe' OR Process LIKE '%\\nslookup.exe' OR Process LIKE '%\\ping.exe' OR Process LIKE '%\\psexec.exe' OR Process LIKE '%\\qprocess.exe' OR Process LIKE '%\\query.exe' OR Process LIKE '%\\quser.exe' OR Process LIKE '%\\qwinsta.exe' OR Process LIKE '%\\reg.exe'  OR Process LIKE '%\\sc.exe' OR Process LIKE '%\\schtasks.exe' OR Process LIKE '%\\servermanagercmd.exe' OR Process LIKE '%\\set.exe' OR Process LIKE '%\\systeminfo.exe' OR Process LIKE '%\\tasklist.exe' OR Process LIKE '%\\time.exe' OR Process LIKE '%\\tracert.exe'  OR Process LIKE '%\\tree.exe' OR Process LIKE '%\\type.exe' OR Process LIKE '%\\vds.exe' OR Process LIKE '%\\vdsldr.exe' OR Process LIKE '%\\ver.exe' OR Process LIKE '%\\wevtutil.exe' OR Process LIKE '%\\whoami.exe' OR Process LIKE '%\\WinrsHost.exe' OR Process LIKE '%\\inver.exe' OR Process LIKE '%\\wmic.exe' OR Process LIKE '%\\wusa.exe') AND NOT Process LIKE '%\\dsregcmd.exe'"
