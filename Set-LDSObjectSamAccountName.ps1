#Requires –Version 2.0
<#
	.SYNOPSIS
		Replaces the sAMAccountName value with the value in the atrribute specified in the script parameters
        including leading padding to maintain fixed width values in the SamAccountName

	.DESCRIPTION
		Replaces the sAMAccountName value with the value in the atrribute specified in the script parameters
        including leading padding to maintain fixed width values in the SamAccountName

		All scripts are provided AS IS without warranty of any kind.

	.NOTES
		Written By:  Stephen Looney
		Written On:  06 July 2015

		Last Updated By:  
		Last Updated On:  

		Updates:

	.PARAMETER ComputerName
		Specifies the Active Directory Lightweight Domain Services instance to which to connect.
        Directory server values:
          Fully qualified directory server name
            Example: lds.looney13.com

	.PARAMETER UPNSuffix
		The UPN suffix of the LDS Object to be updated.

	.PARAMETER Attribute
		The Attribute containing the Employe Number for updating the SamAccountName

	.PARAMETER SearchBase
		Specifies an Active Directory path to search under.
        The following example shows how to set this parameter to search under an OU.
          -SearchBase "dc=looney13,dc=com"  

	.PARAMETER LogFile
		The full path to the log file

	.EXAMPLE
		.\Set-LDSObjectSamAccountName.ps1 -ComputerName "lds.looney13.com" -UPNSuffix "@looney13.com" -Attribute EmployeeID -SearchBase "DC=LOONEY13,DC=COM" -LogFile D:\LDS\Set-CompanyUser.log

	.EXAMPLE
		powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\Scripts\Set-LDSObjectSamAccountName.ps1 -ComputerName "lds.looney13.com" -UPNSuffix "@looney13.com" -Attribute EmployeeID -SearchBase "DC=LOONEY13,DC=COM" -LogFile D:\LDS\Set-CompanyUser.log

#>
[CmdletBinding()]
Param(
	[parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$ComputerName,
	
    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$UPNSuffix,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
	[string]$Attribute,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$SearchBase,

    [parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$LogFile
)

Import-Module -Name ActiveDirectory

#If log file already exists, delete it.
If (Test-Path -Path $LogFile)
{
    Remove-Item -Path $LogFile -Force
}

#Add header to the log file
Add-Content -Path $LogFile -Value "Timestamp,EventType,Message"

#If UPNSuffix does not have a leading wildcard, then add a wildcard to the beginning
If ($UPNSuffix.Substring(0,1) -ne "*")
{
    $UPNSuffix = "*" + $UPNSuffix
}

#Try to retrieve user objects from the LDS server
Try
{
    $Users = Get-ADObject -Filter {(userPrincipalName -like $UPNSuffix) -and ($Attribute -like "*")} `
        -Properties distinguishedName,$Attribute,userPrincipalName,SamAccountName -SearchBase $SearchBase `
        -SearchScope SubTree -Server $ComputerName |
        Select-Object distinguishedName,userPrincipalName,SamAccountName,$Attribute -ErrorAction Stop

    #Loop through all of the user objects that were returned from the LDS server
    ForEach ($User in $Users)
    {
	    Write-Verbose "Gettting $Attribute for $($User.userPrincipalName)"
        Add-Content -Path $LogFile -Value "$([DateTime]::Now),INFORMATION,Getting $Attribute for $($User.userPrincipalName)"
	
        #Check the lenght of the attribute containing the employee number and add the appropriate padding
        Switch (($User.$Attribute).Length)
        {
		    4 {[string]$NewSamAccountName = "Z00" + $User.$Attribute}
		    5 {[string]$NewSamAccountName = "Z0" + $User.$Attribute}
		    6 {[string]$NewSamAccountName = "Z" + $User.$Attribute}
	    }
	
	    #Output information
	    Write-Verbose "The new SamAccountName for $($User.userPrincipalName) is $NewSamAccountName"
	    Write-Verbose "Comparing  attributes for $($User.userPrincipalName)"
        Add-Content -Path $LogFile -Value "$([DateTime]::Now),INFORMATION,The new SamAccountName for $($User.userPrincipalName) is $NewSamAccountName"
        Add-Content -Path $LogFile -Value "$([DateTime]::Now),INFORMATION,Comparing attributes for $($User.userPrincipalName)"
	
        #Check if the SamAccountName matches the employee number with padding
        If ($User.SamAccountName -ne $NewSamAccountName)
        {
		    Write-Verbose "Changing SamAccountName $($User.SamAccountName) to $NewSamAccountName"
            Add-Content -Path $LogFile -Value "$([DateTime]::Now),INFORMATION,Changing SamAccountName $($User.SamAccountName) to $NewSamAccountName"
		
            Try
            {
                Set-ADObject -Identity $User.distinguishedName -Replace @{sAMAccountName=$NewSamAccountName} `
                -Server $ComputerName -ErrorAction Stop
            }
            Catch
            {
                Add-Content -Path $LogFile -Value "$([DateTime]::Now),ERROR,$Error[0].Exception.Message"
            }
	    }
        
        #Nothing to update
        Else
        {
		    Write-Verbose "SamAccountName and $Attribute already match for $($User.userPrincipalName)"
            Add-Content -Path $LogFile -Value "$([DateTime]::Now),INFORMATION,SamAccountName and $Attribute already match for $($User.userPrincipalName)"
	    }
    }
}
Catch
{
    Add-Content -Path $LogFile -Value "$([DateTime]::Now),ERROR,$Error[0].Exception.Message"
}




