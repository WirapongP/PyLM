# PyLM
Python tool for detect lateral movement from windows security event logs (Security.evtx) file 

Main Features
- Detect lateral movement from event id : 4624, 4648, 4688, 5140, 5145
- Mapping lateral movement techniques to MITRE ATT&CK Framework
- Create lateral movement timeline
- Result as Excel file

# Requirement
- python3.7+
- python libraries that includes : evtx, lxml, python-magic-bin, progressbar2, pandas, argparse, Jinja2, xlsxwriter 

# Install
1. Download with
> git clone https://github.com/WirapongP/PyLM
2. Install required libraries with
> pip install -r requirements.txt

# Usage
> python3 pylm.py [evtx]

evtx : Path to the Windows security event log file (Security.evtx)

# Output
Result as excel file (LMresult.xlsx)
![image](https://user-images.githubusercontent.com/56068288/129543228-29839f9b-b216-44a5-b737-bfdb3191f8ba.png)
