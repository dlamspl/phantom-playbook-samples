A collection of Phantom playbooks for reference, ideas and testing. Everytime you import a playbook from a non-Splunk-Phantom official repo make sure you review the content and test before using them in production. 

Repo structure:
```
README.md - This README file
playbooks/PlaybookNameFolder/
			-------- PlaybookNameFolder.png  - Screenshot
			-------- PlaybookNameFolder.json - Autogenerated JSON file 
			-------- PlaybookNameFolder.py   - PY source
			-------- PlaybookNameFolder.tgz  - Playbook file for import
```

If you want to install a playbook on your Phantom dev instance download the .tgz file and import. 

Available Playbooks
-----------


01. Splunk_Demo_On_Notable
---
Required Assets: Splunk

```
Showcase the different actions we can perform via the Splunk app on Enterprise Security generated notables. 

- Updates the notable status, owner, comment, criticality
- Triggers risk modifier for sourceAddress
- Triggers risk modifier for sourceUserName


Data source: ES notable from saved search on Splunk
Required artifact fields: event_id, sourceAddress, sourceUserName
```

[Image goes here ] Splunk Demo On Notable.png

02. PBS-GenericPlaybook
---
Required Assets: Any

```
This playbook shows how we can collect indicators in a more generic way. As long as the container artifacts use CEF Compatible fields to store indicators , this playbook will collect IPs, Domains, URLs and Hashes. 

It will then run related actions on any asset which supports such actions. 
```
