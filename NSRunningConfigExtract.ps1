<#
.SYNOPSIS
    A PowerShell script for extracting the RUNNING configuration of a NetScaler appliance. This will not capture the SAVED configuration.

.DESCRIPTION
    This PowerShell script extracts RUNNING configuration of the specified NetScaler configuration using the built in NetScaler NITRO REST API. To use the script please fill in the items listed in the Declaration section.

.PARAMETER initialdirectory
    Default directory for file output

.PARAMETER SaveFileDialog
    Present Save File Dialogue prompt for file output

.PARAMETER live
    Set which NetScaler config to collect; select live or locally saved configuration

.PARAMETER TCPProtocol
    NetScaler Management GUI Protocol; https or http 

.PARAMETER hostname
    NetScaler host name

.PARAMETER username
    NetScaler administrative account

.PARAMETER password
    NetScaler Administrative password

.PARAMETER filename
    Location of the offline NetScaler configuration file
    
.PARAMETER secpasswd
    Holds the NetScaler administrative password in plain text

.PARAMETER testconnection
    Verifies the NetScaler is accessible for the script to complete

.PARAMETER cred
    Holds the NetScaler administrative credentials

.PARAMETER response
    Command used to log on to the NetScaler appliance and retrieve the live configuration

.PARAMETER savefile
    Used to reference the Get-Filename function

.PARAMETER starttext
    Read the configuration text
.PARAMETER DateStamp
    Get the current date and time to be used within the script. E.g. for the default file name
.PARAMETER DefaultSaveFileName
    Sets the default value of the file name for the configuration file being saved. Default format is "nsconf-[hostname]-[date-time].conf" 
.OUTPUTS
    NetScaler running configuration file (by default stored in the script directory)

.NOTES
    Version:            1.1
    Author:             Anthony Pearce
    Creation Date:      22/06/2016
    References:         Code Snippets have been taken from Carl Stalhood scripts - http://www.carlstalhood.com/netscaler-scripting/
    Changes:            1.2 - 06/09/2017 - Added Default File Save location, Default File Name using Date and Time, improved SaveFileDialog filterindex and default Ext, General clean up
                        1.1 - 22/06/2016 - Removed search criteria, added NetScaler connectivity check, added Save Dialog Prompt & Added .conf file type.
#>
#Requires -Version 3

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$Live = $true      # If true, download config from live NetScaler. Otherwise read local file from $LocalFilename location.
$TCPProtocol = ''   # TCP protocol used when accessing NetScaler Management GUI; use "HTTP://" or "HTTPS://"
$HostName = ''     # Leave blank to be prompted
$UserName = ''     # Leave blank to be prompted
$Password = ''     # Leave blank to be prompted
$LocalFilename = 'C:\example_file_path\nsrunning.conf' # Configuration file location

#-----------------------------------------------------------[Static Variables]-----------------------------------------------------

$DateStamp = (Get-Date -format "yyyy-MM-dd_HH-mm")

#-----------------------------------------------------------[Functions]------------------------------------------------------------

# Start SaveFileDialog Function
Function Get-FileName($initialdirectory)
    {   
        [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
        $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $SaveFileDialog.initialDirectory = $initialdirectory
        $SaveFileDialog.filter = “Text files (*.txt)|*.txt|Conf files (*.conf)|*.conf|All files (*.*)|*.*” # Sets available extensions to be used
        $SaveFileDialog.filterIndex = 2 # Sets which filter (aka file extension) to be default. In this case it will be .conf.
        $SaveFileDialog.DefaultExt = "conf"; # Sets default file extension - needed with filterindex?
        $SaveFileDialog.filename = $DefaultSaveFileName
        $SaveFileDialog.ShowDialog() | Out-Null
        $SaveFileDialog.filename
    }
 
# End SaveFileDialog Function

#-----------------------------------------------------------[Execution]------------------------------------------------------------
# Start Script

if ($live) {
    # Connect to NetScaler and download running config
    if (-not $hostname) {
       $hostname = read-host "Enter NetScaler URL (e.g. 10.20.30.40) "
    }
    if (-not $username) {
       $username = read-host "Enter username for $hostname "
    }
    if ($password) {
        $secpasswd = ConvertTo-SecureString $password -AsPlainText -Force
    } else {
        $secpasswd = read-host "Enter password for $username " -AsSecureString
    }
    
    # Set Default hostname
    $DefaultSaveFileName = $hostname + '_livebackup_' + $DateStamp # Default FileName for exported configuration file. Default format is "nsconf_[hostname]_[date_time].conf"

    # NetScaler connectivity check      
    Write-output 'Starting NetScaler Connectivity Check'

    $TestConnection = Test-Connection -computername $hostname.trimStart($TCPProtocol) -quiet

	if ($TestConnection -eq $true)  {
		Write-Output "NetScaler connection verified, continuing..."
    }
	else {
		Write-host "NetScaler cannot be contacted - exiting script!"
		exit
    }
       
    # Log on to the NetScaler Appliance
    $cred = New-Object System.Management.Automation.PSCredential ($username, $secpasswd)
    # Ignore Cert Errors
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    # Download config from appliance
    $response = Invoke-RestMethod -uri "$hostname/nitro/v1/config/nsrunningconfig" -Credential $cred `
    -Headers @{"Content-Type"="application/vnd.com.citrix.netscaler.nsrunningconfig+json"} -Method GET
    # Split config into multiple objects and save output
    $SaveFile = Get-Filename
    $starttext = $response.nsrunningconfig.response.split([environment]::NewLine) | out-file $SaveFile

} 

else {
    # Or, read config from file
    $starttext = Get-Content $LocalFileName
}