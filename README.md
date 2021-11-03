# PyLM
Detect lateral movement from windows security event logs (.evtx) file 

Main Features
- Detect lateral movement from event id : 4624, 4648, 4688, 5140, 5145
- Mapping lateral movement techniques to MITRE ATT&CK Framework
- Create lateral movement timeline
- Result as Excel file

# Requirement
- python3
- python libraries that includes : evtx, lxml, python-magic, progressbar, pandas 

Install libraries with command
> pip install -r requirements.txt

# Usage
> python3 pylm.py [evtx]

evtx : Path to the Windows security event log file (.EVTX)

# Output
Result as excel file (LMresult.xlsx)
![image](https://user-images.githubusercontent.com/56068288/129543228-29839f9b-b216-44a5-b737-bfdb3191f8ba.png)
