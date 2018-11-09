![](media/1a4bfb7e6ada9924c5df1b9d5138a09d.png)

![](media/26399b8a702b70d0a377ac1dd967bc84.png)

Build Active Directory infrastructure in 10 minutes
===================================================

Document Version **1.0.0**

Overview
========

Introduction
------------

>   Active Directory is one of the of the most important items in an
>   infrastructure and it can be very long to build a complete Active Directory
>   environment for testing a simple thing.

>   Because in most organization, you need to make a lot of test with
>   applications or other stuffs in a lab environment, this suit of scripts
>   intends to reduce time of building Active Directory infrastructure.

>   This suit of scripts had also developed for active directory noob that do
>   not have all the knowledge for building active directory infrastructure.

Recommendations
---------------

>   If you need information about Active Directory, here are some links that can
>   be helpful:

>   *Everything you need to get started with Active Directory:*

>   <https://blogs.technet.microsoft.com/ashleymcglone/2012/01/03/everything-you-need-to-get-started-with-active-directory/>

>   *Microsoft Virtual Academy: Using PowerShell for Active Directory by Ashley
>   McGlone:*

>   <https://blogs.technet.microsoft.com/ashleymcglone/2014/10/29/microsoft-virtual-academy-using-powershell-for-active-directory/>

>   *All Microsoft Test Lab Guides (or TLGs):*

>   <http://social.technet.microsoft.com/wiki/contents/articles/1262.test-lab-guides.aspx>

>   *Download Windows Server 2012 R2 Test Lab Guide:*

>   <https://www.microsoft.com/en-us/download/details.aspx?id=39638>

>   *All Windows Server 2012 r2 Test Lab Guides:*

>   <http://social.technet.microsoft.com/wiki/contents/articles/7807.windows-server-2012-test-lab-guides.aspx>

What this scripts do?
---------------------

>   Just launch each script and answer to the questions.

>   Example:

![](media/c0b19a0b26f321c9ce6231f3e6de7558.png)

>   It’s not necessary to edit scripts because in most case you have the choice
>   to specify whatever you want (IP address etc.) or you can leave the default
>   choice.

>   Each following parts is run by a single script.

>   The advantage is that you don’t have to install everything if you don’t
>   want.

-   Export Organizational Units, Groups, Users and Groups Memberships from old
    Active Directory domain in some CSV files

-   Install all updates for the OS

-   Rename the computer and prepare the server to be promoted as a Domain
    Controller

-   Install Active Directory Services and DNS server

-   Configure the DNS server

-   Install and configure DHCP server

-   Install certification authority

-   Import all exported objects from the CVS files in the new Active Directory
    domain.

![](media/8c5387fb0d09ddd00a0304246754c0d5.png)

System Requirements 
--------------------

>   This suit of scripts has been developed and tested to work with:

-   Windows Server 2012 R2 (fully patched)

-   Windows Server 2016 Technical Preview 4

-   Windows Server 2016 Technical Preview 5

>   The system requirements are as follows:

-   PowerShell 4.0

Licensing
---------

>   All scripts are provided under the Microsoft Public License:

>   <https://atlserver.codeplex.com/license>

Scripts details
===============

Log files
---------

>   Each script generates a log file (Transcript function)

>   Logs files is always located in the same script folder under a subfolder
>   with the format date as follow: \\\\Scripts_Folder\\Year-Month-Day\\
>   Script_Name_Years-Month-Day_Hour-Minute.log

>   For a reason I can explained now, all scripts and answers are always writing
>   in the log files with Windows Server 2016…. But it’s not the case in Windows
>   Server 2012 R2. Perhaps it’s because Powershell under Windows Server 2016 is
>   in debug mode… I don’t know.

>   Because no password must appear in a log file (or the CISO fired you),
>   please note that when a password is asking in the script, generating log
>   files is stopped. Log files generation coming back after the password is
>   set.

Step 0 - Export objects to CSV
------------------------------

### What this script do?

>   First script export this object type in a CSV file from another domain:

-   Organizational Units

-   Groups

-   Users

-   Groups Memberships

>   For each object type, the script asks the path of the CSV file where store
>   the CSV file.

>   You can choose your own path if you want.

>   By default, the folder stored the CSV files in a subfolder named CSV.

### Steps:

-   01 – Start log files

-   02 - Function Declaration

-   03 - Import Module Active Directory

-   04 - Variable Declaration

-   05 - Set the path to CSV file for OUs

-   06 - Import OUs to CSV (The Domain Controllers OU are exclude)

-   07 - Set the path to CSV file for Groups

-   08 - Import Groups to CSV (All Groups in container Users and Built-in are
    excluded)

-   09 - Set the path to CSV file for Users

-   10 - Import Users to CSV (All Users in container Users and Built-in are
    excluded)

-   11 - Set the path to CSV file for Groups Memberships

-   12 - Import Groups Memberships to CSV

-   13 - Warning to check the content of CSV files

-   14 - Stop Transcript

### Recommendations:

>   This script must be launched from another domain

>   I recommend to always accept the default path of the CSV.

>   Do not store multiple CSV file with the same object type name because it
>   could cause problem for with the script for importing objects to active
>   directory.

### What this script not do?

>   This script does not export VMI filters and GPO … perhaps it will be another
>   part of the script.

>   At this time, it’s little complicated for me specially for GPO because you
>   need to import and link GPO to OU.

Step 1 – Install all updates for the OS 
----------------------------------------

### What this script do?

>   This script installs all updates on the OS.

>   Be aware: it could be very very long specially for a Windows 2012 R2 OS…

>   I have a fiber connection and it took more than one hour for download and
>   install all updates.

>   This script use the Windows Updates module wrote by Michal Gajda
>   (<http://commandlinegeeks.com/>)

>   I don’t know why but Microsoft don’t build a powershell module for Windows
>   Update… It’s a bit frustrating but fortunately there is the Michal Gajda
>   module.

>   After installing all updates, the script asks to set or not the windows
>   update to “download and install automatically”.

### Steps:

-   01 – Start log files

-   02 - Function Declaration

-   03 - Import Module Windows Update

-   04 - Start the download and install of all hotfixes from Microsoft Download
    site

-   05 – Ask to set Windows Update to automatic download and install Updates

-   06 - Ask for the computer to be rebooted

-   07 - Stop log files

### Recommendations:

>   Install all recommended updates for security reasons and for avoid bugs and
>   problems.

>   Launch the script several times because certain updates appear after other
>   updates are installed.

### What this script not do?

>   This script doesn’t verify if you have an internet connection.

>   Perhaps it will be a new feature.

Step 2 – Set IP configuration and computer name
-----------------------------------------------

### What this script do?

>   This script asks to change the computer name and all the IP configuration:

-   IP address

-   Subnet mask

-   Gateway

-   DNS Server

>   After all changes are made with information you supply.

### Steps:

-   01 – Start log files

-   02 - Function Declaration

-   03 - Ask for the computer name and confirm

-   04 - Ask for IP address and confirm

-   05 - Ask for subnet mask and confirm

-   06 - Ask for default gateway and confirm

-   07 - Display warning and ask for DNS Server

-   08 - Display warning and ask if IPv4 must be preferred to IPv6 and confirm

-   09 - Display summary information and ask to confirm all parameters

-   10 - Change the IP settings

-   11 - Rename the computer

-   12 – Display new information for verify all settings are set correctly

-   13 - Ask for reboot

-   14 - Stop log files

### Recommendations:

>   Disable all network card interface except the one that you want your domain
>   controller listen.

>   Before launching the script, verify the IP configuration consistency (IP
>   Address, subnet mask, gateway). If there is a misconfiguration in your IP
>   configuration, the script will get an error.

>   I’ll recommended to verify your IP configuration directly in the TCP/IP
>   properties. If the IP configuration is wrong, you will have this error for
>   example: *The combination of IP address and subnet mask is invalid etc.
>   etc.*

>   If you have this type an error, be sure the script will badly finish.

### What this script not do?

>   Verify the IP configuration consistency.

>   Configure the network adapter with IPv6 configuration.

Step 3 – Install Active Directory Services & DNS
------------------------------------------------

### What this script do?

>   This script asks for the FQDN domain name that you want, the password for
>   Directory Services Restore and it install Active Directory Services and DNS
>   Server.

### Steps:

-   01 - Active and start Transcript

-   02 - Function Declaration

-   03 - Warning Message

-   04 - Confirm to continue after the Warning

-   05 - Ask for the FQDN Domain Name and confirm

-   06 - Ask the password for Directory Services Restore and confirm

-   07 - Install Active Directory and DNS Server.

-   08 - Ask for reboot computer

-   09 - Stop transcript

### Recommendations:

>   It’s better to respect the naming convention for the FQDN
>   (<https://support.microsoft.com/en-us/kb/909264>)

>   Please backup the password for Directory Services Restore in a keepass or
>   other password software manager.

### What this script not do?

>   Verify if the FQDN is in a correct format.

Step 4 – Configure Active Directory Services & DNS
--------------------------------------------------

### What this script do?

>   This script will terminate to configure Active Directory Service and DNS:

-   Ask for the DNS forwarders you want

-   Create the reverse lookup zone

-   Add PTR record to the reverse lookup zone

-   Configure DNS forwarders with the DNS forwarders you supply

-   Add and configure a global names zone

-   Enable the Active Directory recycle bin

-   Enable the Privileged Access Management Feature (only for Windows Server
    2016)

-   Add the domain name in the DNS Suffix for this connection

-   Set DNS server to listen only on IPv4 addresses

### Steps:

-   01 - Active and start Transcript

-   02 - Function Declaration

-   03 - Check if the computer is a Domain Controller

-   04 - Import Module Active Directory

-   05 - Display Summary on what the script will do

-   06 - Ask for the DNS forwarders and confirm

-   07 - Set variables for DNS Server reverse lookup zone

-   08 - Create the reverse lookup zone

-   09 - Add a PTR record for this computer to the reverse lookup zone

-   10 - Configure DNS forwarders

-   11 - Install and configure the global names zone

-   12 - Enable the recycled bin

-   13 – Enable Privileged Access Management Feature if the computer is Windows
    Server 2016

-   14 - Add the domain name to the DNS suffix in the network interface card

-   15 - Configure the DNS server to only listen on IPVv4

-   16 - Restart the DNS server service

-   17 - Stop transcript

### Recommendations:

>   Nothing!

### What this script not do?

>   Configure the DNS server to listen on IPv6 addresses.

Step 5 – Install DHCP
---------------------

### What this script do?

>   This script asks for:

-   Scope IP

-   Subnet Mask

-   DHCP lease

-   Option DNS server

-   Option gateway

-   DHCP name

-   DHCP description

>   It will install and configure the DHCP with the information you supply.

### Steps:

-   01 - Active and start Transcript

-   02 - Function Declaration

-   03 - Confirm to continue after the Warning

-   04 - Active Transcript

-   05 - Import Module Active Directory

-   06 - Set some Variable for Domain

-   07 - Ask for the scope IP for the DHCP server and confirm

-   08 - Ask for the Subnet Mask for Scope and confirm

-   09 - Ask for the DHCP lease and confirm

-   10 - Ask for the option DNS server and confirm

-   11 - Ask for the option gateway and confirm

-   12 - Ask for the DHCP name and confirm

-   13 - Ask for the DHCP description and confirm

-   14 - Ask to confirm all parameters

-   15 - Install DHCP server and management tools

-   16 - Create the scope

-   17 - Set router scope gateway option

-   18 - Set name servers scope option

-   19 - Set DNS server scope option

-   20 - Set DNS domain name scope option

-   21 - Authorize the DHCP Server in Active Directory

-   22 - Add DHCP server security groups in Active Directory

-   23 - Delete warning in server manager for terminate DHCP configuration

-   24 - Restart the service DHCP server

-   25 - Stop Transcript

### Recommendations:

>   Nothing

### What this script not do?

>   Nothing

Step 6 – Install Certificate Authority
--------------------------------------

### What this script do?

>   This script asks for:

-   Certification authority type

-   Crypto provider name

-   Key length

-   Hash algorithm

-   Validity period for certification authority certificate

>   It will install and configure the certificate authority with the information
>   you supply.

### Steps:

-   01 - Active and start Transcript

-   02 - Function Declaration

-   03 - Import Module Active Directory

-   04 - Set some Variable for Domain

-   05 - Ask for certification authority type

-   06 - Ask for crypto provider name and confirm

-   07 - Ask for key length and confirm

-   08 - Ask for hash algorithm and confirm

-   09 - Ask for the validity period for certification authority certificate and
    confirm

-   10 - Ask to confirm all parameters

-   11 - Install certificate authority module and management tools

-   12 - Create the certificate authority

-   13 - Restart the service active directory certificate services

-   14 - Stop Transcript

### Recommendations:

>   As you know, Public Key Infrastructure is a very important item for secure
>   an active directory domain, I recommend to create templates certificates for
>   computers, users and Servers with auto enrolment has follow this post:

>   <https://4sysops.com/archives/how-to-deploy-certificates-with-group-policy-part-2-configuration/#creating-the-certificates>

>   And don’t forget Bruce Schneier is the root of all certificates

### What this script not do?

>   Create templates certificate and distribute certificates to computers,
>   servers or users.

>   Perhaps it will be a new feature.

Step 7 – Export Objects to Active Directory with CSV
----------------------------------------------------

### What this script do?

>   This script creates all objects from the CSV that you create in step 0

-   Create Organizational Units

-   Create groups

-   Create users

-   Create groups memberships

### Steps:

-   01 - Active and start Transcript

-   02 - Function Declaration

-   03 - Warning Message and confirm

-   04 - Import Module Active Directory

-   05 - Ask for the old FQDN and confirm

-   06 - Ask for the CSV file contains Organizational Units and confirm

-   07 - Ask to confirm that all Organizational Units are in order

-   08 - Create the Organizational Units

-   09 - Ask for the CSV file contains Groups and confirm

-   10 - Create the Groups

-   11 - Ask for the CSV file contains Users and confirm

-   12 - Stop Transcript

-   13 - Ask for password for users and confirm

-   14 - Start Transcript

-   15 - Ask for the old mail domain name and confirm

-   16 - Create the Users

-   17 - Set the password for the Users

-   18 - Enable the User Accounts

-   19 - Set for Users to change password at next logon

-   20 - Ask for the CSV file contains Groups Memberships and confirm

-   21 - Create Groups Memberships

-   22 - Stop Transcript

### Recommendations:

>   Make order in the CSV file for Organizational Units otherwise you will have
>   some errors.

### What this script not do?

>   Create WMI filters and GPO.

>   Perhaps it will be a new feature.

And after, what should I do?
============================

Secure your Active Directory Domain!!!

Why?

Because by default, Microsoft configures Active Directory with relatively little
security because most companies prefer application compatibility (because it’s
the heart of the business) rather than security specially when Active Directory
upgrades.

Microsoft push security for more than ten years…. But a lot of companies (and IT
Administrators) prefer to install by default to have less problems and because
it's less complicated.

That's the two reasons why Active Directory is not secure enough.

Because of that, it’s important to have more security than the default state….
And it’s not very difficult…

GPO
---

When you install Active Directory domain, it comes with 2 default GPO:

-   Default domain policy

-   Default domain controllers policy

As you known GPO as the best tools for securing Active Directory domain
environment.

I highly recommend to configure this two policy or others with Security Baseline
from Microsoft Security Guidance.

-   *Security baseline for Windows 8.1, Windows Server 2012 R2 and Internet
    Explorer 11:*
    <http://blogs.technet.com/b/secguide/archive/2014/08/13/security-baselines-for-windows-8-1-windows-server-2012-r2-and-internet-explorer-11-final.aspx>

-   *Security baseline for Windows 10 (v1511, "Threshold 2"):*
    <http://blogs.technet.com/b/secguide/archive/2016/01/22/security-baseline-for-windows-10-v1511-quot-threshold-2-quot-final.aspx>

Security Baselines from Microsoft are more secure and compatibility is well with
a modern infrastructure (without old software and with patched applications
etc.).

You need to make test before using this GPO and more specially make a backup of
your domain controller if you intend to put in production this GPO.

Be aware to always have remote connection to your domain controllers because if
you modify the Default Domain Controllers Policy you could accidentally delete
rights to domain admins to connect to domain controllers.

If you do this, you have just 2 solutions:

-   Use the Administrator account for Directory Services Restore

-   Make a restore of your domain controller

You could also use SCM (Security Compliance Manager) to have the best security
practices: <https://www.microsoft.com/en-us/download/details.aspx?id=16776>

EMET (Enhanced Mitigation Experience Toolkit)
---------------------------------------------

Even if you have secure your Active Directory Domain, there are still threats
which you can't do anything:

-   Zero Day Vulnerabilities:
    <https://en.wikipedia.org/wiki/Zero-day_%28computing%29>

The best solution to mitigate this vulnerability is to use EMET (Enhanced
Mitigation Experience Toolkit) from Microsoft.

This software helps a lot to mitigate vulnerabilities and it’s free.

I highly recommend to install that software on all your servers, computers and
even domain controllers and configure it.

The best recommendations for configure this software are in all GPO you can find
in the GPO from Security Baseline ([See above](#gpo)).

You have more information about EMET on this wonderful blog from Sean Metcalf:

<https://adsecurity.org/?p=2579>

LAPS (Local Administrator Password Solution)
--------------------------------------------

Other problem is the password management of the Local Administrator Account.

It’s not easy to change and in the most case you need to have in-house solution
to manage this password or editor solution to change it regularly.

-   Microsoft solved this problem with LAPS:
    <https://www.microsoft.com/en-us/download/details.aspx?id=46899>

LAPS change the Administrator Password Local Account for you with no effort.

The password is store on the computer object in a hidden attribute.

You can delegate to a group the ability the see the password if you need it.

Even if you delete the computer from Active Directory, you can retrieve it in
the Active Directory Recycle Bin (Lost and Found container).

You can find all steps for configure LAPS in the LAPS Operations Guide document
from Microsoft or on this blog from Chris Brown:

-   Deploying the Local Administrator Password Solution Part 1:

<https://flamingkeys.com/2015/05/deploying-the-local-administrator-password-solution-part-1/>

-   Deploying the Local Administrator Password Solution Part 2:

<https://flamingkeys.com/2015/05/deploying-the-local-administrator-password-solution-part-2/>

-   Deploying the Local Administrator Password Solution Part 3:

<https://flamingkeys.com/2015/05/deploying-the-local-administrator-password-solution-part-3/>

Protect LSASS process from attacks
----------------------------------

LSASS (Local Security Authority Server Service) is the process that authenticate
users and machine.

For example, this process sends your password to the Active Directory for
authenticated yourself (or a computer) on the domain.

Because of that, this process is often attack by malwares or other tools for
retrieved the password.

This type of attack is called “Pass The Hash”

The most known software for that is mimikatz :
<https://github.com/gentilkiwi/mimikatz/releases/latest>

… and it’s really impressive that this software can do.

You can protect the LSASS process with the GPO but before that you must audit
your Active Directory domain to find any applications, plug-ins or drivers used
by the lsass.exe process.

For that, you can use the *PtH.admx* and *PtH.adml* provided in the GPO from
Security Baseline ([see above](#gpo)) and enable the Lsass.exe audit mode.

![](media/612791c8e3c174637298ddc700760b53.png)

Please read the TechNet to understand how it works:
<https://technet.microsoft.com/en-us/library/dn408187.aspx>

You can also read this document:

-   “Reducing the Effectiveness of Pass-the-Hash” from our wonderful NSA:
    <https://www.nsa.gov/ia/_files/app/Reducing_the_Effectiveness_of_Pass-the-Hash.pdf>

-   “Mitigating Pass-the-Hash (PtH) Attacks and Other Credential Theft” from
    Microsoft:

<https://www.microsoft.com/en-us/download/details.aspx?id=36036>
