# incident-MFASweep

Investigating Microsoft Authentication Account Compromise Alerts

![image](https://github.com/dita-cyber/incident-MFASweep/blob/52d0668547dab591eeb1719c69d54066916d381e/MFA2.png)

Microsoft authentication account compromise alerts are triggered when suspicious activity, such as unusual login attempts or changes in authentication settings, is detected. Example of alert descriptions:

•	Alert for "user email address" (A general alert indicating unusual activity associated with the specified email address, requiring further investigation.)<br/>
•	Account compromised following a password-spray attack for "user email address" (Triggered by multiple login attempts using common passwords, suggesting an attempt to exploit weak passwords across accounts.)<br/>
•	Anonymous IP address for "user email address" (Indicates login attempts from a masked or anonymized IP address, potentially signaling malicious intent to hide the access origin.)<br/>
•	Successful Authentication from an Unusual Geolocation from IP address (Triggered by a successful login from a location atypical for the user, raising concerns about unauthorized access.)<br/>
•	Unfamiliar sign-in properties for "user email address" (Highlights discrepancies in the user’s typical login behavior, such as changes in device or network, indicating possible compromise.)<br/>
•	Login from an unusual location (Signals a login attempt from a location not commonly associated with the user, suggesting potential compromise or travel.)<br/>
•	Password Spray involving one user (Indicates a targeted password spray attack on a specific user account, with multiple password attempts to gain access.)<br/>
•	Malicious IP address involving one user (Detects activities from an IP address known for malicious behavior, suggesting the user account might be under attack.)<br/>
•	Potentially Compromised Credentials for "user email address" (Suggests that the credentials for the specified email may have been exposed or used without authorization.)<br/>
•	Anomalous Token (Triggered by the detection of an unusual or unexpected authentication token, which may indicate token theft or misuse.)<br/>
•	Atypical travel involving one user (Raised when login activity suggests implausible travel within the time frame, indicating credential misuse.)<br/>
•	Impossible travel activity (Highlights logins from geographically distant locations that are impossible to reach in the given time, suggesting unauthorized access attempts.)<br/>

An MFA Sweep is an attack technique where malicious actors attempt to access multiple services using stolen credentials to identify gaps in MFA enforcement.
Step-by-Step Investigation Process

To begin, I utilize Kusto Query Language (KQL) to sift through logs and identify anomalies. I focus on user data by examining patterns related to location, IP addresses, user agents, display names, and Conditional Access status within the specified time frame. This helps pinpoint unusual activities that might suggest a compromised account. 

SigninLogs<br/>
| where TimeGenerated > ago(30d)<br/>
| where * contains "email_account"<br/>
| project TimeGenerated, UserPrincipalName, UserDisplayName, Location, LocationDetails, IPAddress, Status, ConditionalAccessStatus, AuthenticationRequirement, AuthenticationDetails, ResultType, ResultDescription, UserAgent, MfaDetail, AppDisplayName, DeviceDetail<br/>
| sort by TimeGenerated<br/>

Using the KQL query, I analyze user login data to identify deviations from normal behavior, such as logins from unfamiliar locations or devices, over the past 30 days, extending to 90 days if necessary due to data retention limits in Sentinel logs, which provides a comprehensive view of the user's login patterns. Key aspects to examine include consistency in location patterns, multi-factor authentication usage, the nature of authentication events (successful or failed), account status (blocked due to Conditional Access policies, invalid passwords, session revocation by admins, or high-risk indicators), user agent consistency and any suspicious changes, and device details like registration status, potential new device registration, or authentication from unknown devices or locations. These analyses are compiled into a report to assess whether the behavior is malicious, suspicious, or expected based on new user patterns.

Next, I check the IP addresses associated with the suspicious logins against Open Source Intelligence (OSINT) databases like VirusTotal, AbuseIPDB. This step is crucial for assessing the reputation of these IPs, determining whether they are linked to known malicious activities, and comparing them with the user's historical login patterns. 

![image](https://github.com/dita-cyber/incident-MFASweep/blob/52d0668547dab591eeb1719c69d54066916d381e/VTIP2.png)

![image](https://github.com/dita-cyber/incident-MFASweep/blob/52d0668547dab591eeb1719c69d54066916d381e/AIPDBIP2.png)

To gain a comprehensive understanding of the situation, I examine other data sources like the AuditLogs table and recent security alerts. This helps identify additional indicators of compromise (IOCs), such as unauthorized changes in user settings or other triggered alerts that might be related to the same compromise incident.

AuditLogs<br/>
| where Category == "UserManagement" and OperationName == "Update User"<br/>
| project TimeGenerated, TargetResources, ModifiedProperties<br/>

If information analyzed until this point is not enough, I follow by queries all tables that have the user account and gain a better understanding of data logs available for that account using the general KQL:

search "user_email"<br/>
| summarize count() by $table<br/>


