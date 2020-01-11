include_controls 'microsoft-windows-server-2016-stig-baseline' do
  control 'V-73235' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not mandatory in CMS ARS 3.1'
  end
  control 'V-73249' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not applied to this system categorization in CMS ARS 3.1'
  end
  control 'V-73251' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not applied to this system categorization in CMS ARS 3.1'
  end
  control 'V-73253' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not applied to this system categorization in CMS ARS 3.1'
  end
  control 'V-73259' do
    desc "check", "Open \"Windows PowerShell\".

    Domain Controllers:
    
    Enter \"Search-ADAccount -AccountInactive -UsersOnly -TimeSpan 60.00:00:00\"
    
    This will return accounts that have not been logged on to for 60 days, along
    with various attributes such as the Enabled status and LastLogonDate.
    
    Member servers and standalone systems:
    
    Copy or enter the lines below to the PowerShell window and enter. (Entering
    twice may be required. Do not include the quotes at the beginning and end of
    the query.)
    
    \"([ADSI]('WinNT://{0}' -f $env:COMPUTERNAME)).Children | Where {
    $_.SchemaClassName -eq 'user' } | ForEach {
     $user = ([ADSI]$_.Path)
     $lastLogin = $user.Properties.LastLogin.Value
     $enabled = ($user.Properties.UserFlags.Value -band 0x2) -ne 0x2
     if ($lastLogin -eq $null) {
     $lastLogin = 'Never'
     }
     Write-Host $user.Name $lastLogin $enabled
    }\"
    
    This will return a list of local accounts with the account name, last logon,
    and if the account is enabled (True/False).
    For example: User1 10/31/2015 5:49:56 AM True
    
    Review the list of accounts returned by the above queries to determine the
    finding validity for each account reported.
    
    Exclude the following accounts:
    
    - Built-in administrator account (Renamed, SID ending in 500)
    - Built-in guest account (Renamed, Disabled, SID ending in 501)
    - Application accounts
    
    If any enabled accounts have not been logged on to within the past 60 days,
    this is a finding.
    
    Inactive accounts that have been reviewed and deemed to be required must be
    documented with the ISSO."
    desc "fix", "Regularly review accounts to determine if they are still active.
    Remove or disable accounts that have not been used in the last 60 days."
  end
  control 'V-73265' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not included in CMS ARS 3.1'
  end
  control 'V-73275' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not mandatory in CMS ARS 3.1'
  end
  control 'V-73281' do
    desc "check", "Verify CMS approved HBSS software is installed, configured, and
    properly operating. Ask the operator to document the HBSS software installation
    and configuration.
    
    If the operator is not able to provide a documented configuration for an
    installed HBSS or if the HBSS software is not properly configured, maintained,
    or used, this is a finding."
    desc "fix", "Install a CMS approved HBSS software and ensure it is operating
    continuously."
  end
  control 'V-73283' do
    title "Windows Server 2016 must automatically remove or disable temporary
    user accounts after 60 days."
    desc "If temporary user accounts remain active when no longer needed or for
    an excessive period, these accounts may be used to gain unauthorized access. To
    mitigate this risk, automated termination of all temporary accounts must be set
    upon account creation.
    
    Temporary accounts are established as part of normal account activation
    procedures when there is a need for short-term accounts without the demand for
    immediacy in account activation.
    
    If temporary accounts are used, the operating system must be configured to
    automatically terminate these types of accounts after a CMS-defined time period
    of 60 days.
    
    To address access requirements, many operating systems may be integrated
    with enterprise-level authentication/access mechanisms that meet or exceed
    access control policy requirements."
    desc "check", "Review temporary user accounts for expiration dates.

    Determine if temporary user accounts are used and identify any that exist. If
    none exist, this is NA.
    
    Domain Controllers:
    
    Open \"PowerShell\".
    
    Enter \"Search-ADAccount -AccountExpiring | FT Name, AccountExpirationDate\".
    
    If \"AccountExpirationDate\" has not been defined within 60 days for any
    temporary user account, this is a finding.
    
    Member servers and standalone systems:
    
    Open \"Command Prompt\".
    
    Run \"Net user [username]\", where [username] is the name of the temporary user
    account.
    
    If \"Account expires\" has not been defined within 60 days for any temporary
    user account, this is a finding."
    desc "fix", "Configure temporary user accounts to automatically expire within 60 days.

    Domain accounts can be configured with an account expiration date, under
    \"Account\" properties.
    
    Local accounts can be configured to expire with the command \"Net user
    [username] /expires:[mm/dd/yyyy]\", where username is the name of the temporary
    user account.
    
    Delete any temporary user accounts that are no longer necessary."
  end
  control 'V-73285' do
    title "Windows Server 2016 must automatically remove or disable emergency
    accounts after the crisis is resolved or within 24 hours."
    desc "check", "Determine if emergency administrator accounts are used and
    identify any that exist. If none exist, this is NA.
    
    If emergency administrator accounts cannot be configured with an expiration
    date due to an ongoing crisis, the accounts must be disabled or removed when
    the crisis is resolved.
    
    If emergency administrator accounts have not been configured with an expiration
    date or have not been disabled or removed following the resolution of a crisis,
    this is a finding.
    
    Domain Controllers:
    
    Open \"PowerShell\".
    
    Enter \"Search-ADAccount ‚ÄìAccountExpiring | FT Name, AccountExpirationDate\".
    
    If \"AccountExpirationDate\" has been defined and is not within 24 hours for an
    emergency administrator account, this is a finding.
    
    Member servers and standalone systems:
    
    Open \"Command Prompt\".
    
    Run \"Net user [username]\", where [username] is the name of the emergency
    account.
    
    If \"Account expires\" has been defined and is not within 72 hours for an
    emergency administrator account, this is a finding."
    desc "fix", "Remove emergency administrator accounts after a crisis has been
    resolved or configure the accounts to automatically expire within 24 hours.
    
    Domain accounts can be configured with an account expiration date, under
    \"Account\" properties.
    
    Local accounts can be configured to expire with the command \"Net user
    [username] /expires:[mm/dd/yyyy]\", where username is the name of the temporary
    user account."
  end
  control 'V-73307' do
    title "The time service must synchronize with an appropriate CMS time source."
    desc "check", "Review the Windows time service configuration.

    Open an elevated \"Command Prompt\" (run as administrator).
    
    Enter \"W32tm /query /configuration\".
    
    Domain-joined systems (excluding the domain controller with the PDC emulator
    role):
    
    If the value for \"Type\" under \"NTP Client\" is not \"NT5DS\", this is a
    finding.
    
    Other systems:
    
    If systems are configured with a \"Type\" of \"NTP\", including standalone
    systems and the domain controller with the PDC Emulator role, and do not have a
    CMS time server defined for \"NTPServer\", this is a finding.
    
    To determine the domain controller with the PDC Emulator role:
    
    Open \"PowerShell\".
    
    Enter \"Get-ADDomain | FT PDCEmulator\"."
    desc "fix", "Configure the system to synchronize time with an appropriate CMS
    time source.
    
    Domain-joined systems use NT5DS to synchronize time from other systems in the
    domain by default.
    
    If the system needs to be configured to an NTP server, configure the system to
    point to an authorized time server by setting the policy value for Computer
    Configuration >> Administrative Templates >> System >> Windows Time Service >>
    Time Providers >> \"Configure Windows NTP Client\" to \"Enabled\", and
    configure the \"NtpServer\" field to point to an appropriate CMS time server.
    
    The US Naval Observatory operates stratum 1 time servers, identified at
    http://tycho.usno.navy.mil/ntp.html. Time synchronization will occur through a
    hierarchy of time servers down to the local level. Clients and lower-level
    servers will synchronize with an authorized time server in the hierarchy."
  end
  control 'V-73309' do
    title "Windows 2016 account lockout duration must be configured to 60 minutes or greater."
    desc "check", "Verify the effective setting in Local Group Policy Editor.

    Run \"gpedit.msc\".
    
    Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
    >> Security Settings >> Account Policies >> Account Lockout Policy.
    
    If the \"Account lockout duration\" is less than \"60\" minutes (excluding \"0\"), this is a finding.
    
    For server core installations, run the following command:
    
    Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt
    
    If \"LockoutDuration\" is less than \"60\" minutes (excluding \"0\") in the file, this
    is a finding.
    
    Configuring this to \"0\", requiring an administrator to unlock the account, is more restrictive and is not a finding."
    desc "fix", "Configure the policy value for Computer Configuration >> Windows
    Settings >> Security Settings >> Account Policies >> Account Lockout Policy >>
    \"Account lockout duration\" to \"60\" minutes or greater.
    
    A value of \"0\" is also acceptable, requiring an administrator to unlock the
    account."
  end
  control 'V-73313' do
    title "Windows Server 2016 must have the period of time before the bad logon
    counter is reset configured to 120 minutes or greater."
    desc "check", "Verify the effective setting in Local Group Policy Editor.

    Run \"gpedit.msc\".
    
    Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
    >> Security Settings >> Account Policies >> Account Lockout Policy.
    
    If the \"Reset account lockout counter after\" value is less than \"120\"
    minutes, this is a finding.
    
    For server core installations, run the following command:
    
    Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt
    
    If \"ResetLockoutCount\" is less than \"120\" in the file, this is a finding."
    desc "fix", "Configure the policy value for Computer Configuration >> Windows
    Settings >> Security Settings >> Account Policies >> Account Lockout Policy >>
    \"Reset account lockout counter after\" to at least \"120\" minutes."
  end
  control 'V-73315' do
    title "Windows Server 2016 password history must be configured to 6
    passwords remembered."
    desc "A system is more vulnerable to unauthorized access when system users
    recycle the same password several times without being required to change to a
    unique password on a regularly scheduled basis. This enables users to
    effectively negate the purpose of mandating periodic password changes. The
    default value is \"6\" for Windows domain systems. CMS has decided this is the
    appropriate value for all Windows systems."
    desc "check", "Verify the effective setting in Local Group Policy Editor.

    Run \"gpedit.msc\".
    
    Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
    >> Security Settings >> Account Policies >> Password Policy.
    
    If the value for \"Enforce password history\" is less than \"6\" passwords
    remembered, this is a finding.
    
    For server core installations, run the following command:
    
    Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt
    
    If \"PasswordHistorySize\" is less than \"6\" in the file, this is a finding."
    desc "fix", "Configure the policy value for Computer Configuration >> Windows
    Settings >> Security Settings >> Account Policies >> Password Policy >>
    \"Enforce password history\" to \"6\" passwords remembered."
  end
  control 'V-73321' do
    title "Windows Server 2016 minimum password length must be configured to 15
    characters."
    desc "check", "Verify the effective setting in Local Group Policy Editor.

    Run \"gpedit.msc\".
    
    Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
    >> Security Settings >> Account Policies >> Password Policy.
    
    If the value for the \"Minimum password length,\" is less than \"15\"
    characters, this is a finding.
    
    For server core installations, run the following command:
    
    Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt
    
    If \"MinimumPasswordLength\" is less than \"15\" in the file, this is a
    finding."
    desc "fix", "Configure the policy value for Computer Configuration >> Windows
    Settings >> Security Settings >> Account Policies >> Password Policy >>
    \"Minimum password length\" to \"15\" characters."
  end
  control 'V-73387' do
    title "The directory service must be configured to terminate LDAP-based
    network connections to the directory server after 30 minutes of inactivity."
    desc "check", "This applies to domain controllers. It is NA for other systems.

    Open an elevated \"Command Prompt\" (run as administrator).
    
    Enter \"ntdsutil\".
    
    At the \"ntdsutil:\" prompt, enter \"LDAP policies\".
    
    At the \"ldap policy:\" prompt, enter \"connections\".
    
    At the \"server connections:\" prompt, enter \"connect to server [host-name]\"
    (where [host-name] is the computer name of the domain controller).
    
    At the \"server connections:\" prompt, enter \"q\".
    
    At the \"ldap policy:\" prompt, enter \"show values\".
    
    If the value for MaxConnIdleTime is greater than \"1800\" (30 minutes) or is not
    specified, this is a finding.
    
    Enter \"q\" at the \"ldap policy:\" and \"ntdsutil:\" prompts to exit.
    
    Alternately, Dsquery can be used to display MaxConnIdleTime:
    
    Open \"Command Prompt (Admin)\".
    Enter the following command (on a single line).
    
    dsquery * \"cn=Default Query Policy,cn=Query-Policies,cn=Directory Service,
    cn=Windows NT,cn=Services,cn=Configuration,dc=[forest-name]\" -attr
    LDAPAdminLimits
    
    The quotes are required and dc=[forest-name] is the fully qualified LDAP name
    of the domain being reviewed (e.g., dc=disaost,dc=mil).
    
    If the results do not specify a \"MaxConnIdleTime\" or it has a value greater
    than \"1800\" (30 minutes), this is a finding."
    desc "fix", "Configure the directory service to terminate LDAP-based network
    connections to the directory server after 30 minutes of inactivity.
    
    Open an elevated \"Command prompt\" (run as administrator).
    
    Enter \"ntdsutil\".
    
    At the \"ntdsutil:\" prompt, enter \"LDAP policies\".
    
    At the \"ldap policy:\" prompt, enter \"connections\".
    
    At the \"server connections:\" prompt, enter \"connect to server [host-name]\"
    (where [host-name] is the computer name of the domain controller).
    
    At the \"server connections:\" prompt, enter \"q\".
    
    At the \"ldap policy:\" prompt, enter \"Set MaxConnIdleTime to 1800\".
    
    Enter \"Commit Changes\" to save.
    
    Enter \"Show values\" to verify changes.
    
    Enter \"q\" at the \"ldap policy:\" and \"ntdsutil:\" prompts to exit."
  end
  control 'V-73401' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not included in CMS ARS 3.1'
  end
  control 'V-73403' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not included in CMS ARS 3.1'
  end
  control 'V-73487' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not applied to this system categorization in CMS ARS 3.1'
  end
  control 'V-73495' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not applied to this system categorization in CMS ARS 3.1'
  end
  control 'V-73541' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not included in CMS ARS 3.1'
  end
  control 'V-73567' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not included in CMS ARS 3.1'
  end
  control 'V-73571' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not included in CMS ARS 3.1'
  end
  control 'V-73583' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not included in CMS ARS 3.1'
  end
  control 'V-73585' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not included in CMS ARS 3.1'
  end
  control 'V-73595' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not mandatory in CMS ARS 3.1'
  end
  control 'V-73601' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not mandatory in CMS ARS 3.1'
  end
  control 'V-73603' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not included in CMS ARS 3.1'
  end
  control 'V-73615' do
    title "PKI certificates associated with user accounts must be issued by the
    CMS PKI or an approved External Certificate Authority (ECA)."
  end
  control 'V-73639' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not included in CMS ARS 3.1'
  end
  control 'V-73647' do
    desc "check", "If the following registry value does not exist or is not
    configured as specified, this is a finding.
    
    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path:
    \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\
    
    Value Name: LegalNoticeText
    
    Value Type: REG_SZ
    Value: See message text below
    
    * This warning banner provides privacy and security notices consistent with applicable federal laws, directives, and other federal guidance for accessing this Government system, which includes (1) this computer network, (2) all computers connected to this network, and (3) all devices and storage media attached to this network or to a computer on this network.  * This system is provided for Government authorized use only.  * Unauthorized or improper use of this system is prohibited and may result in disciplinary action and/or civil and criminal penalties.  * Personal use of social media and networking sites on this system is limited as to not interfere with official work duties and is subject to monitoring.  * By using this system, you understand and consent to the following:     - The Government may monitor, record, and audit your system usage, including usage of personal devices and email systems for official duties or to conduct HHS business. Therefore, you have no reasonable expectation of privacy regarding any communication or data transiting or stored on this system. At any time, and for any lawful Government purpose, the government may monitor, intercept, and search and seize any communication or data transiting or stored on this system.     - Any communication or data transiting or stored on this system may be disclosed or used for any lawful Government purposeb."
    desc "fix", "Configure the policy value for Computer Configuration >> Windows
    Settings >> Security Settings >> Local Policies >> Security Options >>
    \"Interactive Logon: Message text for users attempting to log on\" to the
    following:
    
    * This warning banner provides privacy and security notices consistent with applicable federal laws, directives, and other federal guidance for accessing this Government system, which includes (1) this computer network, (2) all computers connected to this network, and (3) all devices and storage media attached to this network or to a computer on this network.  * This system is provided for Government authorized use only.  * Unauthorized or improper use of this system is prohibited and may result in disciplinary action and/or civil and criminal penalties.  * Personal use of social media and networking sites on this system is limited as to not interfere with official work duties and is subject to monitoring.  * By using this system, you understand and consent to the following:     - The Government may monitor, record, and audit your system usage, including usage of personal devices and email systems for official duties or to conduct HHS business. Therefore, you have no reasonable expectation of privacy regarding any communication or data transiting or stored on this system. At any time, and for any lawful Government purpose, the government may monitor, intercept, and search and seize any communication or data transiting or stored on this system.     - Any communication or data transiting or stored on this system may be disclosed or used for any lawful Government purposeb."
  end
  control 'V-73649' do
    desc "check", "If the following registry value does not exist or is not
    configured as specified, this is a finding.
    
    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path:
    \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\
    
    Value Name: LegalNoticeCaption
    
    Value Type: REG_SZ
    Value: See message title options below
    
    \"CMS Notice and Consent Banner\", \"US Department of Health and Human Services Warning
    Statement\", or an organization-defined equivalent.
    
    If an organization-defined title is used, it can in no case contravene or
    modify the language of the banner text required in WN16-SO-000150.
    
    Automated tools may only search for the titles defined above. If an
    organization-defined title is used, a manual review will be required."
    desc "fix", "Configure the policy value for Computer Configuration >> Windows
    Settings >> Security Settings >> Local Policies >> Security Options >>
    \"Interactive Logon: Message title for users attempting to log on\" to \"CMS
    Notice and Consent Banner\", \"US Department of Health and Human Services Warning Statement\", or
    an organization-defined equivalent.
    
    If an organization-defined title is used, it can in no case contravene or
    modify the language of the message text required in WN16-SO-000150."
  end
  control 'V-73707' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not included in CMS ARS 3.1'
  end
  control 'V-73709' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not applied to this system categorization in CMS ARS 3.1'
  end
  control 'V-73711' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not applied to this system categorization in CMS ARS 3.1'
  end
  control 'V-73713' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not included in CMS ARS 3.1'
  end
  control 'V-73715' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not applied to this system categorization in CMS ARS 3.1'
  end
  control 'V-73717' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not applied to this system categorization in CMS ARS 3.1'
  end
  control 'V-73719' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not included in CMS ARS 3.1'
  end
  control 'V-73721' do
    impact 0
    desc 'caveat', 'Not applicable for this CMS ARS 3.1 overlay, since the related security control is not applied to this system categorization in CMS ARS 3.1'
  end
end