# cms-ars-3.1-moderate-microsoft-windows-server-2016-stig-overlay
InSpec profile overlay to validate the secure configuration of Microsoft Windows Server 2016 against [DISA's](https://iase.disa.mil/stigs/Pages/index.aspx) Microsoft Windows Server 2016 STIG tailored for [CMS ARS 3.1](https://www.cms.gov/Research-Statistics-Data-and-Systems/CMS-Information-Technology/InformationSecurity/Info-Security-Library-Items/ARS-31-Publication.html) for CMS systems categorized as Moderate.

## Getting Started  
It is intended and recommended that InSpec and this profile be run from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target [ remotely over __winrm__].
    
__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

Git is required to download the latest InSpec profiles using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site. 

The following inputs must be configured in inspec.yml for the profile to run correctly. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

```

# description: 'List of authorized users in the Backup Operators Group'
backup_operators: []

# description: 'List of authorized users in the local Administrators group'
administrators: []

# description: 'List of authorized users in the local Administrators domain group'
administrators_domain: []

# description: 'List of temporary accounts on the system'
temp_account: []

# description: 'List of emergency accounts on the system'
emergency_account: []

# description: 'List of authorized users in the local Administrators domain group'
administrator_domain_group: []

# description: 'List of shared accounts on the system'
shared_accounts: []

# description: 'Set to true server has the ftp server role'
has_ftp_server_role: true

# description: 'Domain Controller forrest name'
forrest: ''

# description: 'Default administator account'
admin_account: ''

# description: 'Set to true if the system is dedicated to the management of Active Directory'
is_AD_only_system: false

# description: 'A list of all manually managed Application and Service account names'
manually_managed_app_service_accounts: []

```
## Running This Overlay
When the __"runner"__ host uses this profile overlay for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/microsoft-windows-server-2016-stig-baseline.git
git clone https://github.cms.gov/ISPG/cms-ars-3.1-moderate-microsoft-windows-server-2016-stig-overlay.git
cd cms-ars-3.1-moderate-microsoft-windows-server-2016-stig-overlay
bundle install
cd ..
inspec exec cms-ars-3.1-moderate-microsoft-windows-server-2016-stig-overlay --input-file <path_to_your_input_file/name_of_your_input_file.yml> cms-ars-3.1-moderate-microsoft-windows-server-2016-stig-overlay/static-inputs.yml -t winrm://<hostname> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```
For every successive run, follow these steps to always have the latest version of this overlay and dependent profiles:

```
cd profiles/microsoft-windows-server-2016-stig-baseline
git pull
cd ../cms-ars-3.1-moderate-microsoft-windows-server-2016-stig-overlay
git pull
bundle install
cd ..
inspec exec cms-ars-3.1-moderate-microsoft-windows-server-2016-stig-overlay --input-file <path_to_your_input_file/name_of_your_input_file.yml> cms-ars-3.1-moderate-microsoft-windows-server-2016-stig-overlay/static-inputs.yml -t winrm://<hostname> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

## Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://mitre.github.io/heimdall-lite/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.cms.gov/ISPG/cms-ars-3.1-moderate-microsoft-windows-server-2016-stig-overlay/issues/new).

## Authors
* Krisha Kola, DIFZ
* Eugene Aronne, MITRE

## Special Thanks
* Aaron Lippold, MITRE
* The MITRE InSpec Team

## License 

This project is licensed under the terms of the Apache 2.0 license excepted as noted in [LICENSE.MD](https://github.com/mitre/project/blob/master/LICENSE.md). 

### NOTICE

© 2019 The MITRE Corporation.  

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.  

### NOTICE
MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation. 

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.  

### NOTICE

DISA STIGs are published by DISA IASE, see: [https://public.cyber.mil/privacy-security/](https://public.cyber.mil/privacy-security/).
