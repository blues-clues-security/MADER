![](mader_logo.png)
# MADER
MITRE Adversary Detection Engineering Repository (MADER) is a collection of presentations that cover the detection engineering documentation and methodology as taught by SpecterOps.

Credit for this idea goes to SpecterOps who provided a lot of these insights and more in their [Adversary Threats: Detection](https://specterops.io/training/adversary-tactics-detection/) course.

## Detection Engineering Methodology
1. Select a Target Technique (this includes the variation of the technique)
2. Research Underlying Technology
3. Identify Proof of Concept Malware Sample(s)
4. Identify Data Sources
5. Build the Detection

### Select a Target Technique
Self explanatory, select a technique that has not already been captured, or set out to improve an existing presentation.

*!TODO: Include MITRE ATTCK Mapping of techniques captured in this repo*

Techniques should be selected using a TTP driven method rather than data, intelligence, entity or threat driven
Focus on TTPs in general rather than attacks against a specific system
Example:
- Looking for *Credential Access*, specifically *Credential Dumping* via *Powershell*
- Looking for *Persistence*, specifically *modification of an existing service* via *reg.exe*

Detections should be built at the most generic level possible, but many times a single technique will require multiple detections for completion

Inputs:
- MITRE ATT&CK Framework
- Your organization’s data sources
- Threat Intelligence

Output:
- A specific technique that you will be targeting
- Possibly, a specific implementation of that technique (Procedure)
- Document the different variations of this technique

### Research Underlying Technology
Research the technology associated with the technique to help understand the use cases, related data sources, and detection opportunities

Output:
- How the technique works (low level)?
- Why attackers would use this technique?
- What alternatives to this technique do attackers have?
- What is the list of potential data sources?

### Proof of Concept Malware Sample
- Build or Find a benign malware sample to allow for data source evaluation and detection validation

Input:
- Target technique/procedure
- Understanding of attack technique

Output:
- Ability to execute the technique for validation purposes
- Command Line parameters
- Script
- Binary

### Identify Data Sources
Evaluate what data sources are necessary to allow for detection of the technique  
This step is part of a cycle with the next step (Build Atomic Detection)

Input:
- Selected Technique/Procedure
- Understanding of involved technology
- Understanding of attacker’s motivation
- Proof of concept malware sample

Output:
- List of selected data sources
- Necessary data sources are enabled and being centralized

### Build the Detection
How would you naturally describe what you want to query?  
What is the data index you would use (based on the data sensor)?  
What is the event identifier (EventID)?  
What are the event details that will allow you to narrow in on your detection, based on your research?  

## Final Product
Each presentation will cover the following:
- Goal
  - Short, plaintext description of the behavior the Alerting and Detection Strategy (ADS) is designed to detect
- Categorization
  - Mapping of the ADS to the relevant entry in MITRE ATT&CK
- Strategy Abstract
  - High-level walkthrough of how the ADS functions
- Technical Context
  - Detailed information and background needed for a responder to understand all components of the alert
- Blind Spots and Assumptions
  - Recognized issues, assumptions, and areas where an ADS may not fire
- False Positives
  - Known instances of an ADS misfiring due to a misconfiguration, idiosyncrasy in the environment, or other non-malicious scenario
- Validation
  - Steps required to generate a representative True Positive event which triggers this alert
- Priority
  - Alerting levels that an ADS may be tagged with
- Response
  - General triage steps in the event that this alert fired to determine if alert is a true positive
- Additional Resources
  - Any other internal, external, or technical references that may be useful for understanding the ADS

