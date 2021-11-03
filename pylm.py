from evtx import PyEvtxParser
from lxml import etree
import magic
import progressbar
import re
import pandas as pd
import argparse

data_fields_timeline = {"RecordID":[],"DateTime":[],"EventID":[],"SubjectLogonId":[],"TargetLogonId":[],"DetectionRules":[],"Description":[],"MITRE":[]}
data_fields_4624 = {"RecordID":[],"DateTime":[],"SubjectLogonId":[],"SubjectDomainName":[],"SubjectUserSid":[],"SubjectUserName":[],"TargetLogonId":[],"TargetDomainName":[],"TargetUserSid":[],"TargetUserName":[],"WorkstationName":[],"IpAddress":[],"IpPort":[],"LogonType":[],"ProcessId":[],"ProcessName":[],"DetectionRules":[],"MITRE":[],"Description":[]}
data_fields_4688 = {"RecordID":[],"DateTime":[],"SubjectLogonId":[],"SubjectDomainName":[],"SubjectUserSid":[],"SubjectUserName":[],"ProcessId":[],"ParentProcessName":[],"NewProcessId":[],"NewProcessName":[],"CommandLine":[],"DetectionRules":[],"MITRE":[],"Description":[]}
data_fields_4648 = {"RecordID":[],"DateTime":[],"SubjectLogonId":[],"SubjectDomainName":[],"SubjectUserSid":[],"SubjectUserName":[],"TargetDomainName":[],"TargetServerName":[],"TargetUserName":[],"TargetInfo":[],"IpAddress":[],"IpPort":[],"ProcessId":[],"ProcessName":[],"DetectionRules":[],"MITRE":[],"Description":[]}
data_fields_5140 = {"RecordID":[],"DateTime":[],"SubjectLogonId":[],"SubjectDomainName":[],"SubjectUserSid":[],"SubjectUserName":[],"IpAddress":[],"IpPort":[],"ObjectType":[],"ShareName":[],"ShareLocalPath":[],"DetectionRules":[],"MITRE":[],"Description":[]}
data_fields_5145 = {"RecordID":[],"DateTime":[],"SubjectLogonId":[],"SubjectDomainName":[],"SubjectUserSid":[],"SubjectUserName":[],"IpAddress":[],"IpPort":[],"ObjectType":[],"ShareName":[],"ShareLocalPath":[],"RelativeTargetName":[],"AccessList":[],"DetectionRules":[],"MITRE":[],"Description":[]}


def main():
    parser = argparse.ArgumentParser(
        description="Analyze lateral movement event from Windows security event log file (.EVTX)")
    parser.add_argument("evtx", type=str, help="Path to the Windows security event log file (.EVTX)")
    args = parser.parse_args()
    if re.search(r'Event Log', magic.from_file(args.evtx)):
        events_str = parse_events(args.evtx)
        print("Counting event..")
        n_events = count_events(args.evtx)
        print("Number of event :", n_events)
        filtered_data_timeline,filtered_data_4624,filtered_data_4688, filtered_data_4648,filtered_data_5140,filtered_data_5145 = filter_events(events_str,n_events)
        print("Writing ouput..")
        write_excel(filtered_data_timeline,filtered_data_4624,filtered_data_4688,filtered_data_4648,filtered_data_5140,filtered_data_5145) 
        
    else:
        print('Input file is not Windows Event log (.EVTX) format, Please check')
    
def write_excel(filtered_data_timeline,filtered_data_4624,filtered_data_4688,filtered_data_4648,filtered_data_5140,filtered_data_5145):
    dataframe_timeline = pd.DataFrame(filtered_data_timeline)
    dataframe_4624 = pd.DataFrame(filtered_data_4624)
    dataframe_4688 = pd.DataFrame(filtered_data_4688)
    dataframe_4648 = pd.DataFrame(filtered_data_4648)
    dataframe_5140 = pd.DataFrame(filtered_data_5140)
    dataframe_5145 = pd.DataFrame(filtered_data_5145)

    dataframe_timeline = dataframe_timeline.style.applymap(timeline_color, subset=['EventID'])
    dataframe_4624 = dataframe_4624.style.applymap(color, subset=['DetectionRules'])
    dataframe_4688 = dataframe_4688.style.applymap(color, subset=['DetectionRules'])
    dataframe_4648 = dataframe_4648.style.applymap(color, subset=['DetectionRules'])
    dataframe_5140 = dataframe_5140.style.applymap(color, subset=['DetectionRules'])
    dataframe_5145 = dataframe_5145.style.applymap(color, subset=['DetectionRules'])

    fileName = 'LMresult.xlsx'
    writer = pd.ExcelWriter(fileName, engine='xlsxwriter')
    dataframe_timeline.to_excel(writer,sheet_name="timeline", index = False)
    dataframe_4624.to_excel(writer,sheet_name="4624", index = False)
    dataframe_4688.to_excel(writer,sheet_name="4688", index = False)
    dataframe_4648.to_excel(writer,sheet_name="4648", index = False)
    dataframe_5140.to_excel(writer,sheet_name="5140", index = False)
    dataframe_5145.to_excel(writer,sheet_name="5145", index = False)

    writer.save()
    print("Done, Analysis result filename :",fileName)

    
def timeline_color(EventID):
    if EventID == "4624":
        color = 'white'
        background = 'blue'
    elif EventID == "4688":
        color = 'white'
        background = 'grey'
    elif EventID == "4648":
        color = 'white'
        background = 'red'
    elif EventID == "5140":
        color = 'black'
        background = 'yellow'
    elif EventID == "5145":
        color = 'black'
        background = 'green'
    else:
        color = 'black'
        background = 'none'
    return f'color: {color}; background-color: {background}'



def color(DetectionRules):
    if DetectionRules != "-":   
        color = 'white'
        background = 'red'
    else:
        color = 'black'
        background = 'none'
    border = 'solid'
    return f'color: {color}; background-color: {background}'

def count_events(evtx_file):
    parser = PyEvtxParser(evtx_file)
    count = 0
    for record in parser.records():
        count+=1
    return count

def parse_events(evtx_file):
    parser = PyEvtxParser(evtx_file)
    for record in parser.records():
        yield record


def save_result(data_fields_name,RecordID,DateTime,EventID,SubjectLogonId,TargetLogonId,DetectionRules,MITRE,Description):
    data_fields_timeline["RecordID"].append(RecordID)
    data_fields_timeline["DateTime"].append(DateTime)
    data_fields_timeline["EventID"].append(EventID)
    data_fields_timeline["SubjectLogonId"].append(SubjectLogonId)
    data_fields_timeline["TargetLogonId"].append(TargetLogonId)
    data_fields_timeline["DetectionRules"].append(DetectionRules)
    data_fields_timeline["Description"].append(Description)
    data_fields_timeline["MITRE"].append(MITRE)
    save_event_result(data_fields_name,DetectionRules,MITRE,Description)

def save_event_result(data_fields_name,DetectionRules,MITRE,Description):
    data_fields_name["DetectionRules"].append(DetectionRules)
    data_fields_name["Description"].append(Description)
    data_fields_name["MITRE"].append(MITRE)

    

def check_none(data):
    if data is not None:
        return data
    else:
        return "-"

def check_targetHost(target):
    if target:
        return target
    else:
        return "some host"

def map_accessList_code(accessLists):
    accessLists = re.findall(r'(?<=%%)\S+', accessLists)
    AccessListCode = {"4416":"ReadData (or ListDirectory)","4417":"WriteData (or AddFile)","4418":"AppendData (or AddSubdirectory or CreatePipeInstance)","4419":"ReadEA","4420":"WriteEA","4421":"Execute/Traverse","4422":"DeleteChild","4423":"ReadAttributes","4424":"WriteAttributes","1537":"DELETE","1538":"READ_CONTROL","1539":"WRITE_DAC","1540":"WRITE_OWNER","1541":"SYNCHRONIZE","1542":"ACCESS_SYS_SEC"}
    mappingResult = ""
    for accessList in accessLists:
        if mappingResult == "":
            mappingResult = mappingResult + AccessListCode[accessList]
        else:
            mappingResult = mappingResult + ", " + AccessListCode[accessList]
    return mappingResult

def filter_events(events_str,n_events):
    event_index=0
    with progressbar.ProgressBar(max_value=n_events) as bar:
        for event_str in events_str:
            event_index+=1
            bar.update(event_index)
            
            event_data = event_str['data']
            parser = etree.XMLParser(recover=True)
            event_data_xml= etree.fromstring(event_data.encode(), parser=parser)

            namespaces = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            system_tag = event_data_xml.find("./ns:System",namespaces)
            eventID = system_tag.find("./ns:EventID",namespaces).text
            if eventID == "4624":
                eventdata_tag = event_data_xml.find("./ns:EventData",namespaces)
                for child in eventdata_tag:
                    if child.attrib["Name"] in data_fields_4624:
                        data_fields_4624[child.attrib["Name"]].append(child.text)
                data_fields_4624["DateTime"].append(event_str["timestamp"])
                data_fields_4624["RecordID"].append(event_str["event_record_id"])
                ipAddress = check_none(eventdata_tag.find('./ns:Data[@Name="IpAddress"]',namespaces).text)
                targetUserName = check_none(eventdata_tag.find('./ns:Data[@Name="TargetUserName"]',namespaces).text)
                if ipAddress != "-" and ipAddress != "::1" and ipAddress != "127.0.0.1" and targetUserName != "ANONYMOUS LOGON" and not re.search(r'\w+\$$', targetUserName) :
                    logonType = check_none(eventdata_tag.find('./ns:Data[@Name="LogonType"]',namespaces).text)
                    targetDomainName = check_none(eventdata_tag.find('./ns:Data[@Name="TargetDomainName"]',namespaces).text)
                    targetLogonId = check_none(eventdata_tag.find('./ns:Data[@Name="TargetLogonId"]',namespaces).text)
                    subjectLogonId = check_none(eventdata_tag.find('./ns:Data[@Name="SubjectLogonId"]',namespaces).text)
                    if logonType == "3":
                        save_result(data_fields_4624,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,targetLogonId,"Lateral Movement with SMB/Windows Admin Shares from "  + ipAddress,"Lateral Movement - Remote Services: SMB/Windows Admin Shares (https://attack.MITRE.org/techniques/T1021/002/)",ipAddress + " use SMB/Windows Admin Shares to lateral movement to this host with account " + targetDomainName + "\\" + targetUserName)                        
                    elif logonType =="10":
                        save_result(data_fields_4624,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,targetLogonId,"Lateral Movement with Remote Desktop Protocol from " + ipAddress,"Lateral Movement - Remote Services: Remote Desktop Protocol (https://attack.MITRE.org/techniques/T1021/001/)",ipAddress  + " use Remote Desktop Protocol to lateral movement to this host with account " + targetDomainName + "\\" + targetUserName)
                    else:
                        save_event_result(data_fields_4624,"-","-","-")            
                else:
                    save_event_result(data_fields_4624,"-","-","-")
            elif eventID == "4688":                
                eventdata_tag = event_data_xml.find("./ns:EventData",namespaces)

                for child in eventdata_tag:
                    if child.attrib["Name"] in data_fields_4688:
                        data_fields_4688[child.attrib["Name"]].append(child.text)
                
                data_fields_4688["DateTime"].append(event_str["timestamp"])
                data_fields_4688["RecordID"].append(event_str["event_record_id"])
                
                newProcessName = check_none(eventdata_tag.find('./ns:Data[@Name="NewProcessName"]',namespaces).text)
                commandLine = check_none(eventdata_tag.find('./ns:Data[@Name="CommandLine"]',namespaces).text)
                subjectLogonId = check_none(eventdata_tag.find('./ns:Data[@Name="SubjectLogonId"]',namespaces).text)
                subjectDomainName = check_none(eventdata_tag.find('./ns:Data[@Name="SubjectDomainName"]',namespaces).text)
                subjectUserName = check_none(eventdata_tag.find('./ns:Data[@Name="SubjectUserName"]',namespaces).text)
                
                parentProcessNameData = eventdata_tag.find('./ns:Data[@Name="ParentProcessName"]',namespaces)
                if parentProcessNameData is None:
                    data_fields_4688["ParentProcessName"].append("-")

                if (re.search(r'psexec.exe$', newProcessName, re.IGNORECASE) and re.search(r'\\\\', commandLine)):
                    targetHost = check_targetHost(re.findall(r'(?<=\\\\)\S+', commandLine))[0]
                    save_result(data_fields_4688,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with PSEXEC to "+ targetHost,"Lateral Movement - Remote Services: SMB/Windows Admin Shares (https://attack.mitre.org/techniques/T1021/002/)",subjectDomainName + "\\" + subjectUserName + " use PSEXEC to lateral movement to " + targetHost + " and run command : " + commandLine)

                elif re.search(r'powershell.exe$', newProcessName, re.IGNORECASE) and re.search(r'-ComputerName', commandLine, re.IGNORECASE):
                    targetHost = check_targetHost(re.findall(r'(?<=-ComputerName )\S+', commandLine))[0]
                    save_result(data_fields_4688,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with Powershell to "+ targetHost,"Execution - Command and Scripting Interpreter:PowerShell (https://attack.mitre.org/techniques/T1059/001/)",subjectDomainName + "\\" + subjectUserName + " use Powershell to lateral movement to " + targetHost + " and run command : " + commandLine)

                elif re.search(r'wmic.exe$', newProcessName, re.IGNORECASE) and re.search(r'\/node', commandLine, re.IGNORECASE):
                    targetHost = check_targetHost(re.findall(r'(?<=\/node:)\S+', commandLine))[0]
                    save_result(data_fields_4688,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with WMI/WMIC to "+ targetHost,"Execution - Windows Management Instrumentation (https://attack.mitre.org/techniques/T1047/)",subjectDomainName + "\\" + subjectUserName + " use WMI/WMIC to lateral movement to " + targetHost + " and run command : " + commandLine)

                elif re.search(r'Invoke-WmiMethod', commandLine, re.IGNORECASE) and re.search(r'-Computer', commandLine, re.IGNORECASE):
                    targetHost = check_targetHost(re.findall(r'(?<=-Computer )\S+', commandLine))[0]
                    save_result(data_fields_4688,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with WMI/WMIC to "+ targetHost,"Execution - Windows Management Instrumentation (https://attack.mitre.org/techniques/T1047/)",subjectDomainName + "\\" + subjectUserName + " use WMI/WMIC to lateral movement to " + targetHost + " and run command : " + commandLine)

                elif re.search(r'sc.exe$', newProcessName, re.IGNORECASE) and re.search(r'\\\\', commandLine):
                    targetHost = check_targetHost(re.findall(r'(?<=\\\\)\S+', commandLine))[0]
                    save_result(data_fields_4688,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with Service to "+ targetHost,"Execution - System Services: Service Execution (https://attack.mitre.org/techniques/T1569/002/)",subjectDomainName + "\\" + subjectUserName + " use Service to lateral movement to " + targetHost + " and run command : " + commandLine)

                elif re.search(r'at.exe$', newProcessName, re.IGNORECASE) and re.search(r'\\\\', commandLine):
                    targetHost = check_targetHost(re.findall(r'(?<=\\\\)\S+', commandLine))[0]
                    save_result(data_fields_4688,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with Task Scheduler to "+ targetHost,"Execution - Scheduled Task/Job:Scheduled Task (https://attack.mitre.org/techniques/T1053/005/)",subjectDomainName + "\\" + subjectUserName + " use Task Scheduler to lateral movement to " + targetHost + " and run command : " + commandLine)

                elif re.search(r'schtasks.exe$', newProcessName, re.IGNORECASE) and re.search(r'\/S', commandLine):
                    targetHost = check_targetHost(re.findall(r'(?<=\/S )\S+', commandLine))[0]
                    save_result(data_fields_4688,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with Task Scheduler to "+ targetHost,"Execution - Scheduled Task/Job:Scheduled Task (https://attack.mitre.org/techniques/T1053/005/)",subjectDomainName + "\\" + subjectUserName + " use Task Scheduler to lateral movement to " + targetHost + " and run command : " + commandLine)

                elif re.search(r'net.exe$', newProcessName, re.IGNORECASE) and re.search(r'\\\\', commandLine):
                    targetHost = check_targetHost(re.findall(r'(?<=\\\\)\S+', commandLine))[0]
                    save_result(data_fields_4688,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with NET USE to "+ targetHost,"Lateral Movement - Remote Services: SMB/Windows Admin Shares (https://attack.mitre.org/techniques/T1021/002/)",subjectDomainName + "\\" + subjectUserName + " use NET USE to lateral movement to " + targetHost + " and run command : " + commandLine)

                elif re.search(r'winrs.exe$', newProcessName, re.IGNORECASE) and re.search(r'-r',commandLine, re.IGNORECASE):
                    targetHost = check_targetHost(re.findall(r'(?<=-r:)\S+', commandLine))[0]
                    save_result(data_fields_4688,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with WinRS to "+ targetHost,"Lateral Movement - Remote Services: Windows Remote Management (https://attack.mitre.org/techniques/T1021/006/)",subjectDomainName + "\\" + subjectUserName + " use WinRS to lateral movement to " + targetHost + " and run command : " + commandLine)
                
                elif parentProcessNameData is not None:
                    parentProcessName = check_none(parentProcessNameData.text)
                    if re.search(r'services.exe$', parentProcessName, re.IGNORECASE) and (re.search(r'cmd.exe$', newProcessName, re.IGNORECASE) or re.search(r'powershell.exe$', newProcessName, re.IGNORECASE)):
                        save_result(data_fields_4688,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with Service from some host (Potential)","Execution - System Services: Service Execution (https://attack.mitre.org/techniques/T1569/002/)","some host use Service to lateral movement to this host and run command : " + commandLine)

                    elif re.search(r'wmiprvse.exe$', parentProcessName, re.IGNORECASE):
                        save_result(data_fields_4688,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with WMI/WMIC from some host (Potential)","Execution - Windows Management Instrumentation (https://attack.mitre.org/techniques/T1047/)","some host use  WMI/WMIC to lateral movement to this host and run command : " + commandLine)

                    elif re.search(r'winrshost.exe$', parentProcessName, re.IGNORECASE):
                        save_result(data_fields_4688,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with WinRS from some host (Potential)","Lateral Movement - Remote Services: Windows Remote Management (https://attack.mitre.org/techniques/T1021/006/)","some host use  WinRS to lateral movement to this host and run command : " + commandLine)

                    elif re.search(r'wsmprovhost.exe$', parentProcessName, re.IGNORECASE):
                        save_result(data_fields_4688,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with Powershell from some host (Potential)","Execution - Command and Scripting Interpreter:PowerShell (https://attack.mitre.org/techniques/T1059/001/)","some host use  Powershell to lateral movement to this host and run command : " + commandLine)

                    elif re.search(r'PSEXESVC.exe', parentProcessName, re.IGNORECASE):
                        save_result(data_fields_4688,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with PSEXEC from some host (Potential)","Lateral Movement - Remote Services: SMB/Windows Admin Shares (https://attack.MITRE.org/techniques/T1021/002/)","some host use  PSEXEC to lateral movement to this host and run command : " + commandLine)

                    else:
                        save_event_result(data_fields_4688,"-","-","-")
            
                else:
                    save_event_result(data_fields_4688,"-","-","-")
                
                

            elif eventID == "4648":
                eventdata_tag = event_data_xml.find("./ns:EventData",namespaces)
                for child in eventdata_tag:
                    if child.attrib["Name"] in data_fields_4648:
                        data_fields_4648[child.attrib["Name"]].append(child.text)

                data_fields_4648["DateTime"].append(event_str["timestamp"])
                data_fields_4648["RecordID"].append(event_str["event_record_id"])
                targetServerName = check_none(eventdata_tag.find('./ns:Data[@Name="TargetServerName"]',namespaces).text)
                processName = check_none(eventdata_tag.find('./ns:Data[@Name="ProcessName"]',namespaces).text)
                subjectUserName = check_none(eventdata_tag.find('./ns:Data[@Name="SubjectUserName"]',namespaces).text)
                targetUserName = check_none(eventdata_tag.find('./ns:Data[@Name="TargetUserName"]',namespaces).text)

                if not re.search(r'\w+\$$', targetServerName) and targetServerName != "localhost" and processName != "-" and not re.search(r'\w+\$$', subjectUserName) and not re.search(r'\w+\$$', targetUserName):
                    targetInfo = check_none(eventdata_tag.find('./ns:Data[@Name="TargetInfo"]',namespaces).text)
                    subjectLogonId = check_none(eventdata_tag.find('./ns:Data[@Name="SubjectLogonId"]',namespaces).text)
                    subjectDomainName = check_none(eventdata_tag.find('./ns:Data[@Name="SubjectDomainName"]',namespaces).text)
                    targetDomainName = check_none(eventdata_tag.find('./ns:Data[@Name="TargetDomainName"]',namespaces).text)
                    ipAddress = check_none(eventdata_tag.find('./ns:Data[@Name="IpAddress"]',namespaces).text)
                    
                    if re.search('wmic.exe$',processName, re.IGNORECASE) or re.search('^RestrictedKrbHost',targetInfo, re.IGNORECASE):
                        save_result(data_fields_4648,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with WMI/WMIC to "+ targetServerName + " (" + ipAddress + ") ","Execution - Windows Management Instrumentation (https://attack.mitre.org/techniques/T1047/)",subjectDomainName + "\\" + subjectUserName + " use WMI/WMIC to lateral movement to host " + targetServerName + " (" + ipAddress + ") " + " with account " + targetDomainName + "\\" + targetUserName)

                    elif re.search('schtasks.exe$',processName, re.IGNORECASE) or re.search('^host',targetInfo, re.IGNORECASE):
                        save_result(data_fields_4648,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with Task Scheduler to "+ targetServerName + " (" + ipAddress + ") ","Execution - Scheduled Task/Job:Scheduled Task (https://attack.mitre.org/techniques/T1053/005/)",subjectDomainName + "\\" + subjectUserName + " use Task Scheduler to lateral movement to host " + targetServerName + " (" + ipAddress + ") " + " with account " + targetDomainName + "\\" + targetUserName)
                    
                    elif re.search('powershell.exe$',processName, re.IGNORECASE) or re.search('^HTTP',targetInfo, re.IGNORECASE):
                        save_result(data_fields_4648,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with Powershell to "+ targetServerName + " (" + ipAddress + ") ","Execution - Command and Scripting Interpreter:PowerShell (https://attack.mitre.org/techniques/T1059/001/)",subjectDomainName + "\\" + subjectUserName + " use Powershell to lateral movement to host " + targetServerName + " (" + ipAddress + ") " + " with account " + targetDomainName + "\\" + targetUserName)
                    
                    elif re.search('lsass.exe$',processName, re.IGNORECASE) or re.search('^TERMSRV',targetInfo, re.IGNORECASE):
                        save_result(data_fields_4648,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with Remote Desktop Protocol to "+ targetServerName + " (" + ipAddress + ") ","Lateral Movement - Remote Services: Remote Desktop Protocol (https://attack.mitre.org/techniques/T1021/001/)",subjectDomainName + "\\" + subjectUserName + " use Remote Desktop Protocol to lateral movement to host " + targetServerName + " (" + ipAddress + ") " + " with account " + targetDomainName + "\\" + targetUserName)

                    elif re.search('^cifs',targetInfo, re.IGNORECASE):
                        save_result(data_fields_4648,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with PSEXEC/NET USE to "+ targetServerName + " (" + ipAddress + ") ","Lateral Movement - Remote Services: SMB/Windows Admin Shares (https://attack.mitre.org/techniques/T1021/002/)",subjectDomainName + "\\" + subjectUserName + " use PSEXEC/NET USE to lateral movement to host " + targetServerName + " (" + ipAddress + ") " + " with account " + targetDomainName + "\\" + targetUserName)

                    elif re.search('winrs.exe$',processName, re.IGNORECASE):
                        save_result(data_fields_4648,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with WinRS to "+ targetServerName + " (" + ipAddress + ") ","Lateral Movement - Remote Services: Windows Remote Management (https://attack.mitre.org/techniques/T1021/006/)",subjectDomainName + "\\" + subjectUserName + " use WinRS to lateral movement to host " + targetServerName + " (" + ipAddress + ") " + " with account " + targetDomainName + "\\" + targetUserName)

                    elif re.search('sc.exe$',processName, re.IGNORECASE):
                        save_result(data_fields_4648,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with Service to "+ targetServerName + " (" + ipAddress + ") ","Execution - System Services: Service Execution (https://attack.mitre.org/techniques/T1569/002/)",subjectDomainName + "\\" + subjectUserName + " use Service to lateral movement to host " + targetServerName + " (" + ipAddress + ") " + " with account " + targetDomainName + "\\" + targetUserName)
                    
                    else:
                        save_result(data_fields_4648,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement to "+ targetServerName + " (" + ipAddress + ") ","Lateral Movement (https://attack.mitre.org/tactics/TA0008/)",subjectDomainName + "\\" + subjectUserName + " use " + processName + " lateral movement to host " + targetServerName + " (" + ipAddress + ") " + " with account " + targetDomainName + "\\" + targetUserName)

                else:
                    save_event_result(data_fields_4648,"-","-","-")

            elif eventID == "5140":
                eventdata_tag = event_data_xml.find("./ns:EventData",namespaces)
                for child in eventdata_tag:
                    if child.attrib["Name"] in data_fields_5140:
                        data_fields_5140[child.attrib["Name"]].append(child.text)
                
                data_fields_5140["DateTime"].append(event_str["timestamp"])
                data_fields_5140["RecordID"].append(event_str["event_record_id"])

                ipAddress = check_none(eventdata_tag.find('./ns:Data[@Name="IpAddress"]',namespaces).text)
                subjectUserName = check_none(eventdata_tag.find('./ns:Data[@Name="SubjectUserName"]',namespaces).text)
                
                if ipAddress != "::1" and ipAddress != "127.0.0.1" and not re.search(r'\w+\$$', subjectUserName):
                    subjectLogonId = check_none(eventdata_tag.find('./ns:Data[@Name="SubjectLogonId"]',namespaces).text)
                    shareName = check_none(eventdata_tag.find('./ns:Data[@Name="ShareName"]',namespaces).text)
                    subjectDomainName = check_none(eventdata_tag.find('./ns:Data[@Name="SubjectDomainName"]',namespaces).text)
                    shareLocalPath = check_none(eventdata_tag.find('./ns:Data[@Name="ShareLocalPath"]',namespaces).text)
                    save_result(data_fields_5140,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with SMB/Windows Admin Shares to "+ipAddress,"Lateral Movement - Remote Services: SMB/Windows Admin Shares (https://attack.MITRE.org/techniques/T1021/002/)",ipAddress + " use SMB/Windows Admin Shares to access " + shareName + " (" + shareLocalPath + ") " + " path on this host with account " + subjectDomainName + "\\" + subjectUserName)
                    
                else:
                    save_event_result(data_fields_5140,"-","-","-")

            elif eventID == "5145":
                eventdata_tag = event_data_xml.find("./ns:EventData",namespaces)
                for child in eventdata_tag:
                    if child.attrib["Name"] in data_fields_5145:
                        
                        if child.attrib["Name"] == "AccessList":
                            data_fields_5145[child.attrib["Name"]].append(map_accessList_code(child.text))
                        else:
                            data_fields_5145[child.attrib["Name"]].append(child.text)

                
                data_fields_5145["DateTime"].append(event_str["timestamp"])
                data_fields_5145["RecordID"].append(event_str["event_record_id"])
                
                subjectUserName = check_none(eventdata_tag.find('./ns:Data[@Name="SubjectUserName"]',namespaces).text)
                ipAddress = check_none(eventdata_tag.find('./ns:Data[@Name="IpAddress"]',namespaces).text)
                accessList = map_accessList_code(check_none(eventdata_tag.find('./ns:Data[@Name="AccessList"]',namespaces).text))


                if ipAddress != "::1" and ipAddress != "127.0.0.1" and not re.search(r'\w+\$$', subjectUserName):
                    subjectLogonId = check_none(eventdata_tag.find('./ns:Data[@Name="SubjectLogonId"]',namespaces).text)
                    subjectDomainName = check_none(eventdata_tag.find('./ns:Data[@Name="SubjectDomainName"]',namespaces).text)
                    shareName = check_none(eventdata_tag.find('./ns:Data[@Name="ShareName"]',namespaces).text)
                    relativeTargetName = check_none(eventdata_tag.find('./ns:Data[@Name="RelativeTargetName"]',namespaces).text)
                    shareLocalPath = check_none(eventdata_tag.find('./ns:Data[@Name="ShareLocalPath"]',namespaces).text)             

                    if shareName == "\\*\BITS":
                        save_result(data_fields_5145,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with Background Intelligent Transfer Service (BITS) from "+ipAddress,"Defense Evasion, Persistence - BITS Jobs (https://attack.MITRE.org/techniques/T1197/)",ipAddress + " use BITS to access " + shareName + "(" + shareLocalPath + relativeTargetName + ")" + " on this host with account " + subjectDomainName + "\\" + subjectUserName)
                        
                    elif shareName == "\\*\WMI_SHARE":
                        save_result(data_fields_5145,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with wmiexec.vbs from "+ipAddress,"Execution - Windows Management Instrumentation (https://attack.MITRE.org/techniques/T1047/)",ipAddress + " use wmiexec.vbs to access " + shareName + "(" + shareLocalPath + relativeTargetName + ")" + " on this host with account " + subjectDomainName + "\\" + subjectUserName)
                        
                    elif re.search(r'PSEXECSVC', shareName, re.IGNORECASE):
                        save_result(data_fields_5145,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement with PSEXEC from "+ipAddress,"Lateral Movement - Remote Services: SMB/Windows Admin Shares (https://attack.MITRE.org/techniques/T1021/002/)",ipAddress + " use PSEXEC to access " + shareName + "(" + shareLocalPath + relativeTargetName + ")" + " on this host with account " + subjectDomainName + "\\" + subjectUserName)
                        
                    elif re.search(r'WriteData', accessList, re.IGNORECASE):
                        save_result(data_fields_5145,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement from "+ipAddress,"Lateral Movement (https://attack.mitre.org/tactics/TA0008/)",ipAddress + " write data or create file to " + shareName + " (" + shareLocalPath + relativeTargetName + ") " + "on this host with account " + subjectDomainName + "\\" + subjectUserName)

                    elif re.search(r'ReadData', accessList, re.IGNORECASE):
                        if re.search(r'\.', relativeTargetName, re.IGNORECASE):
                            save_result(data_fields_5145,event_str["event_record_id"],event_str["timestamp"],eventID,subjectLogonId,"-","Lateral Movement from "+ipAddress,"Lateral Movement (https://attack.mitre.org/tactics/TA0008/)",ipAddress + " read data in " + shareName + " (" + shareLocalPath + relativeTargetName + ") " + "on this host with account " + subjectDomainName + "\\" + subjectUserName)
                        else: 
                            save_event_result(data_fields_5145,"-","-","-")
                    else:
                        save_event_result(data_fields_5145,"-","-","-")    
                else:
                    save_event_result(data_fields_5145,"-","-","-")

        return data_fields_timeline, data_fields_4624, data_fields_4688, data_fields_4648, data_fields_5140, data_fields_5145
        
if __name__ == "__main__":
    main()