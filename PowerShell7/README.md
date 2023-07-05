# PowerShell7
# Authors
Cliff Rodriguez
  * [Dell Technoligies](https://www.dell.com/en-us)
  * [LinkedIn](https://www.linkedin.com/in/cliff-rodriguez-6673422b/)
# Supported Platforms
* PowerProtect Data Manager 19.13
# Prerequisites
* PowerShell 7.(latest) - [github](https://github.com/PowerShell/powershell/releases)
# Conventions
* [CMDLET Guidelines](https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/strongly-encouraged-development-guidelines?view=powershell-7.3)
* CMDLET names are in lower case
* CMDLET names begin with a PowerShell [approved verb](https://learn.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7.3)
* CMDLET nouns are prefixed with dm to avoid any naming convention collisions
* CMDLET variables are in pascal case
* CMDLET bindings must be used outside of:
  * $global:ApiVersion
  * $global:AuthObject
  * $global:Port
* CMDLET help must be defined
* List module functions
  * PS> Import-Module .\dell.ppdm.psm1 -Force
  * PS> Get-Command -Module dell.ppdm
* List cmdlet help after module is imported (basic, detailed, verbose w/ examples)
  * PS> {cmdlet-name} -?
  * PS> Get-Help -Name {cmdlet-name} -Detailed
  * PS> Get-Help -Name {cmdlet-name} -Full
# Documentation
* PowerProtect Data Manager - [rest api](https://developer.dell.com/apis/4378/versions/19.13.0/docs/introduction.md)
* PowerProtect Data Manager - [info hub](https://www.dell.com/support/kbdoc/en-us/000196987/dell-powerprotect-data-manager-info-hub-product-documents-and-information?lang=en)
* PowerShell 7.(latest) - [docs](https://learn.microsoft.com/en-us/powershell)


# Examples
| Name        | Description                                                              | Environment | Category |
|:-----------:|:-------------------------------------------------------------------------|:-----------:|:--------:|
| Example-01  | Get assets based on filters                                              | ANY         | Query    |
| Example-02  | Get activities based on filters                                          | ANY         | Query    |
| Example-03  | Get alerts based on filters                                              | ANY         | Query    |
| Example-04  | Get the attached vMware vCenter                                          | VMWARE      | Query    |
| Example-05  | Get the datacenters for the defined vCenter                              | VMWARE      | Query    |
| Example-06  | Get a folder within the defined vCenter\datacenter                       | VMWARE      | Query    |
| Example-07  | Get a cluster within the defined vCenter\datacenter                      | VMWARE      | Query    |
| Example-08  | Get a resource pool within the defined vCenter\datacenter\cluster        | VMWARE      | Query    |
| Example-09  | Get an esx host within the defined vCenter\datacenter\cluster            | VMWARE      | Query    |
| Example-10  | Get the datastores attached to vCenter\datacenter\cluster\esx host       | VMWARE      | Query    |
| Example-11  | Start an ad hoc virtual machine policy based backup                      | VMWARE      | Backup   |
| Example-12  | Start an ad hoc virtual machine client based backup                      | VMWARE      | Backup   |
| Example-13  | Create a virtual machine protection policy                               | ANY         | Config   |
| Example-14  | Get the latest copy for an asset                                         | ANY         | Query    |
| Example-15  | Get attached PowerProtect DD storage systems                             | ANY         | Query    |
| Example-16  | Recover an asset from the latest copy via instant access then vmotion    | VMWARE      | Recover  |
| Example-17  | Get protection policies based on filters                                 | ANY         | Query    |
| Example-18  | Get agents registered with the system                                    | ANY         | Query    |
| Example-19  | Get a certificate from 3rd party application                             | ANY         | Query    |
| Example-20  | Deploy a protection engine                                               | VMWARE      | Config   |
| Example-21  | Get credentials based on filters                                         | ANY         | Query    |
| Example-22  | Set asset disk exclusions                                                | VMWARE      | Config   |