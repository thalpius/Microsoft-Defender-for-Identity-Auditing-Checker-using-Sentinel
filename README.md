> [!IMPORTANT]
> "This repo is now in 'Blue Screen' mode—archived and frozen in time!"

# Microsoft Defender for Identity Auditing Checker using Sentinel

I created a script that checks the Microsoft Defender for Identity Auditing configuration and writes the result in the event viewer. Using the event, you can use any SIEM/SOAR solution to monitor the state of the configuration. Check the following blog post if you want to know more about how to monitor the Microsoft Defender for Identity Auditing configuration using Microsoft Sentinel.

For more information please check:<br>
https://thalpius.com/2022/12/14/microsoft-defender-for-identity-auditing-checker-using-sentinel/

# Screenshots

Here you can see the event written to the application log in the event viewer:
<p align="center"><img width="92%" height="92%" src="/Screenshots/MicrosoftDefenderForIdentityAuditingCheckerUsingSentinel01.png"></p>

Here you can see an alert in Microsoft Sentinel once an auditing configuration is not configured properly:
<p align="center"><img src="/Screenshots/MicrosoftDefenderForIdentityAuditingCheckerUsingSentinel02.png"></p>
