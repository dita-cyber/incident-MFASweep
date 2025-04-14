# incident - Microsoft Authentication and MFASweep

Investigating Microsoft Authentication Account Compromise Alerts

![image](https://github.com/dita-cyber/incident-MFASweep/blob/52d0668547dab591eeb1719c69d54066916d381e/MFA2.png)

Microsoft authentication account compromise alerts are triggered when suspicious activity, such as unusual login attempts or changes in authentication settings, is detected. Example of alert descriptions:

**•	Alert for "user email address"** <br/>(A general alert indicating unusual activity associated with the specified email address, requiring further investigation.)<br/>
<br/>
**•	Account compromised following a password-spray attack for "user email address"**<br/> (Triggered by multiple login attempts using common passwords, suggesting an attempt to exploit weak passwords across accounts.)<br/>
<br/>
**•	Anonymous IP address for "user email address"**<br/> (Indicates login attempts from a masked or anonymized IP address, potentially signaling malicious intent to hide the access origin.)<br/>
<br/>
**•	Successful Authentication from an Unusual Geolocation from IP address**<br/> (Triggered by a successful login from a location atypical for the user, raising concerns about unauthorized access.)<br/>
<br/>
**•	Unfamiliar sign-in properties for "user email address"** <br/>(Highlights discrepancies in the user’s typical login behavior, such as changes in device or network, indicating possible compromise.)<br/>
<br/>
**•	Login from an unusual location**<br/> (Signals a login attempt from a location not commonly associated with the user, suggesting potential compromise or travel.)<br/>
<br/>
**•	Password Spray involving one user**<br/> (Indicates a targeted password spray attack on a specific user account, with multiple password attempts to gain access.)<br/>
<br/>
**•	Malicious IP address involving one user** <br/>(Detects activities from an IP address known for malicious behavior, suggesting the user account might be under attack.)<br/>
<br/>
**•	Potentially Compromised Credentials for "user email address"**<br/> (Suggests that the credentials for the specified email may have been exposed or used without authorization.)<br/>
<br/>
**•	Anomalous Token** <br/>(Triggered by the detection of an unusual or unexpected authentication token, which may indicate token theft or misuse.)<br/>
<br/>
**•	Atypical travel involving one user** <br/>(Raised when login activity suggests implausible travel within the time frame, indicating credential misuse.)<br/>
<br/>
**•	Impossible travel activity** <br/>(Highlights logins from geographically distant locations that are impossible to reach in the given time, suggesting unauthorized access attempts.)<br/>
<br/>

**Step-by-Step Investigation Process**

To begin, I use Kusto Query Language (KQL) to sift through logs and identify anomalies. I focus on user data by examining patterns related to location, IP addresses, user agents, display names, and Conditional Access status within the specified time frame. This helps pinpoint unusual activities that might suggest a compromised account. 

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

**MFA Sweep Attacks**<br/>

An MFA Sweep is an attack technique where malicious actors attempt to access multiple services using stolen credentials to identify gaps in MFA enforcement.<br/>

MFA Sweep attacks exist because attackers are constantly looking for ways to bypass security measures and gain unauthorized access to accounts. MFA is robust, but inconsistencies in its implementation across different services can be exploited.<br/>

**How MFA Sweep Attacks Work**<br/>
<br/>
MFA Sweep attacks typically involve using tools like MFASweep, which attempt to log in to various Microsoft services using correct user credentials. The tool checks if MFA is enabled by trying to authenticate across multiple services, such as Microsoft Graph API, Azure Service Management API, Microsoft 365 Exchange Web Services, and more[1]. If any authentication methods succeed without requiring MFA, the attacker identifies a potential vulnerability.<br/>

That is why it is important to analyze the authentication logs to ensure events are expected. Even in situations where suspicious authentication events were blocked due to conditional access, attackers can use correct credential to bypass MFA. 

**Common MFA Bypass Techniques**<br/>
<br/>
**Phishing Attacks:** Attackers trick users into entering their MFA codes or login credentials on fake websites[4].
**Man-in-the-Middle (MitM) Attacks:** Attackers intercept and forward MFA-protected logins, capturing credentials and session cookies in real-time[5].
**Token Theft:** Attackers steal authentication tokens, allowing them to bypass MFA and gain access to accounts[3].
**SIM Swapping:** Attackers use social engineering to transfer a user's mobile phone number to a new SIM card owned by the attacker[5].
**MFA Fatigue:** Attackers flood users with MFA push notifications, hoping the user will eventually approve one to stop the notifications[5].


