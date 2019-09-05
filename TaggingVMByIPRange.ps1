
#region variables
$stringBuilder = New-Object System.Text.StringBuilder
                                                            
[string]    $LoginName =                   ""                                           # Azure username, something@something.onmicrosoft.com 
[string]    $SecurePasswordLocation =      ""                                           # Path and filename for the secure password file c:\Whatever\securePassword.txt.  Set to prompt for password if this is blank.
[string]    $LogFileNameAndPath =          ""                                           # If $enabledLogFile is true, the script will write to a log file in this path.  Include FileName, example c:\whatever\file.log
[bool]      $RunPasswordPrompt =           $true                                        # Uses Read-Host to prompt the user at the command prompt to enter password and username if $LoginName is blank.  this will create the text file in $SecurePasswordLocation.
[bool]      $AzureForGovernment =          $true                                        # Set to $true if running cmdlets against Microsoft azure for government
[bool]      $EnableLogFile =               $false                                       # If enabled a log file will be written to $LogFileNameAndPath.
[bool]      $ConnectToAzureAd =            $false                                       # This will connect to Azure-AD and allow you to run commands against Azure Active Directoryusing Connect-AzureRM cmdlets instead of Connect-AzAccount

#Variables for tagging VMs
[bool]      $ListVmsOnly =                  $false                                      # Setting to $true will only output the names of the vms that would have been tagged.  Useful if you want to ensure you have the correct filter
[string]    $IPRangeToInclude =             "192.168.1.*"                               # Example, if looking for devices in the 192.168.0.0 /16 range, you could enter 192.168.* as the value
$Newtags =                                  @{Purpose="Lab"}                            # Should be able to add multiple vaules here, it's a standard hashtable
$ExemptMachines =                           @{}                                         # @{'SQL-1'="SQL-1";'Web-01'="Web-01"} Add hostnames to the exempt list in the form of Hostname="Hostname"
#endregion 

#region Functions - Add your own functions here.  Leave AzureLogin as-is
####Functions######################################################################################################################################################################################################
function AzureLogin
{
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory=$false)]
        [bool] $RunPasswordPrompt = $false,
        [Parameter(Mandatory=$false)]
        [string] $SecurePasswordLocation,
        [Parameter(Mandatory=$false)]
        [string] $LoginName,
        [Parameter(Mandatory=$false)]
        [bool] $AzureForGov = $false,
        [Parameter(Mandatory=$false)]
        [bool] $ConnectToAzureAd = $false
    )

    try 
    {
        $success = $false
        
        # if(!($SecurePasswordLocation -match '(\w)[.](\w)') )
        # {
        #     write-host "Encrypted password file ends in a directory, this needs to end in a filename.  Exiting..."
        #     return $false # could make success false
        # }
        if($RunPasswordPrompt)
        {
            #if fails return false
            if($LoginName)
            {
                Read-Host -Prompt "Enter your password for $($LoginName)" -assecurestring | convertfrom-securestring | out-file $SecurePasswordLocation
            }
            else 
            {
                $LoginName = Read-Host -Prompt "Enter your username"
                if($SecurePasswordLocation)
                {
                    Read-Host -Prompt "Enter your password for $($LoginName)" -assecurestring | convertfrom-securestring | out-file $SecurePasswordLocation
                } 
                else 
                {
                    $password = Read-Host -Prompt "Enter your password for $($LoginName)" -assecurestring
                }
                
            }
            #Read-Host -Prompt "Enter your password for $($LoginName)" -assecurestring | convertfrom-securestring | out-file $SecurePasswordLocation
        }
        else 
        {
            #no prompt, does the password file exist
            if(!(Test-Path $SecurePasswordLocation))
            {
                write-host "There isn't a password file in the location you specified $($SecurePasswordLocation)."
                Read-host "Password file not found, Enter your password" -assecurestring | convertfrom-securestring | out-file $SecurePasswordLocation
                #return false if fail 
                if(!(Test-Path -Path $SecurePasswordLocation)){return Write-Host "Path doesn't exist: $($SecurePasswordLocation)"; $false}
            } 
        }
        try 
        {
            if(!($password)){$password = Get-Content $SecurePasswordLocation | ConvertTo-SecureString}
            
            $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $LoginName, $password 
            $success = $true
        }
        catch {$success = $false}
        try 
        {
            if($success)
            {
                #connect AD or Az
                if($ConnectToAzureAd)
                {
                    if($AzureForGov){Connect-AzureAD -Credential $cred -EnvironmentName AzureUSGovernment | Out-Null}
                    else{Connect-AzureAD -Credential $cred | Out-Null}
                    $context = Get-AzureADUser -Top 1
                    if($context){$success = $true}   
                    else{$success = $false}
                }
                else 
                {
                    if($AzureForGov){Connect-AzAccount -Credential $cred -EnvironmentName AzureUSGovernment | Out-Null}
                    else{Connect-AzAccount -Credential $cred | Out-Null}
                    $context = Get-AzContext
                    if($context.Subscription.Name){$success = $true}
                    else{$success = $false}
                }
                if(!($success))
                {
                  # error logging into account or user doesn't have subscription rights, exit
                  $success = $false
                  throw "Failed to login, exiting..."
                  #exit
                }   
            }
        }
        catch{$success = $false} 
    }
    catch {$success = $false}
    return $success
}

function Write-Logging()
{
    param
    (
        [string] $Message,
        [string] $LogFileNameAndPath
    )
    
    try 
    {
        $success = $false
        $dateTime = Get-Date -Format yyyyMMddTHHmmss
        $null = $stringBuilder.Append($dateTime.ToString())
        $null = $stringBuilder.Append( "`t==>>`t")
        $null = $stringBuilder.AppendLine( $Message)
        $stringBuilder.ToString() | Out-File -FilePath $LogFileNameAndPath -Append
        $stringBuilder.Clear()
        $success = $true 
    }
    catch {$success = $false}
    return $success
}
#endregion



####Begin Code######################################################################################################################################################################################################
try 
{
    if($EnableLogFile){Write-Logging -Message "Starting script" -LogFileNameAndPath $LogFileNameAndPath | Out-Null}
    $success = AzureLogin -RunPasswordPrompt $RunPasswordPrompt -SecurePasswordLocation $SecurePasswordLocation -LoginName $LoginName -AzureForGov $AzureForGovernment -ConnectToAzureAd $ConnectToAzureAd
    if($success)
    {
        if($EnableLogFile){Write-Logging -Message "Login Succeeded" -LogFileNameAndPath $LogFileNameAndPath | Out-Null}
        #Login Successful
        Write-Host "Login Succeeded"
 
        if(!($ConnectToAzureAd))
        {
            #Run commands using the Azure Az cmdlets ###########################
            if($EnableLogFile){Write-Logging -Message "Getting VMs" -LogFileNameAndPath $LogFileNameAndPath | Out-Null}
            $vms = Get-AzVm 
            if($EnableLogFile){Write-Logging -Message "Getting NICs" -LogFileNameAndPath $LogFileNameAndPath | Out-Null}
            $nics = Get-AzNetworkInterface | Where-Object VirtualMachine -NE $null
            foreach($nic in $nics)
            {
                try {
                    if($EnableLogFile){Write-Logging -Message ("Checking for private IP match for nic = " + $nic.Name) -LogFileNameAndPath $LogFileNameAndPath | Out-Null}
                    $vm = $vms | Where-Object -Property Id -EQ $nic.VirtualMachine.id # link the VM to the NIC
                    $privateip =  $nic.IpConfigurations | Where-Object {$_.PrivateIpAddress -like $IPRangeToInclude} | Select-Object -ExpandProperty PrivateIpAddress
                    if(!($privateip)){ continue }
                    else {
                        if($EnableLogFile){Write-Logging -Message ("Private IP match found: " + $privateip) -LogFileNameAndPath $LogFileNameAndPath | Out-Null}
                        #Write-Host $vm.Name
                        $exemptMachine = $false
                        foreach($name in $ExemptMachines.Values)
                        {
                            if($vm.Name -eq $name)
                            {
                                if($EnableLogFile){Write-Logging -Message ($vm.Name + " is exempted.") -LogFileNameAndPath $LogFileNameAndPath | Out-Null}
                                $exemptMachine = $true; 
                                break
                            }
                        }
                        if($exemptMachine){continue}

                        if($ListVmsOnly)
                        {
                            if($EnableLogFile){Write-Logging -Message ("List VM only: " + $vm.Name) -LogFileNameAndPath $LogFileNameAndPath | Out-Null}
                            Write-Host $vm.Name
                            continue
                        }
                        #determine if we have to append tags
                        $currentTagsOrig = (Get-AzResource -ResourceGroupName $vm.ResourceGroupName -Name $vm.Name).Tags
                        $currentTags = $currentTagsOrig
                        $dirty = $false
                        if($currentTags)
                        {
                            foreach($key in $Newtags.Keys)
                            {
                                if($currentTags.Keys.Contains($key))
                                {
                                    #duplicate, overwrite
                                    if(!($currentTags[$key] -eq $Newtags[$key]))
                                    {
                                        if($EnableLogFile){Write-Logging -Message ("Overwriting current tag of " + $currentTags[$key] + " with value " + $Newtags[$key]) -LogFileNameAndPath $LogFileNameAndPath | Out-Null}
                                        $currentTags[$key] = $Newtags[$key]
                                        $dirty = $true
                                    } 
                                } 
                                else 
                                {
                                    #new key, add
                                    $currentTags.Add($key, $Newtags[$key])
                                    $dirty = $true
                                }
                            }
                        }
                        #check if there is a need to submit
                        if($dirty)
                        {
                            if($EnableLogFile){Write-Logging -Message ("Submitting tags") -LogFileNameAndPath $LogFileNameAndPath | Out-Null}
                            $results = Set-AzResource -ResourceName $vm.Name -ResourceGroupName $vm.ResourceGroupName -ResourceType "Microsoft.Compute/VirtualMachines" -Tag $currentTags -Force
                            
                            #check the results of the submission
                            if($results.Properties.ProvisioningState)
                            {
                                if($EnableLogFile){Write-Logging -Message ("Provisioning state = " + $results.Properties.ProvisioningState) -LogFileNameAndPath $LogFileNameAndPath | Out-Null}
                                continue
                            }
                            else 
                            {
                                if($EnableLogFile){Write-Logging -Message ("Provisioning state is null, might be an issue with the tag submission.") -LogFileNameAndPath $LogFileNameAndPath | Out-Null}
                                #failed, log?
                            }
                        }
                        else {
                            if($EnableLogFile){Write-Logging -Message ("No change to VM: " + $vm.Name) -LogFileNameAndPath $LogFileNameAndPath | Out-Null}
                        }
                    }
                }
                catch {
                    if($EnableLogFile){Write-Logging -Message ("Error: " + $_.Exception.Message) -LogFileNameAndPath $LogFileNameAndPath | Out-Null}
                    if($EnableLogFile){Write-Logging -Message ("Continuing") -LogFileNameAndPath $LogFileNameAndPath | Out-Null}
                    continue
                }
            }
        }
        else 
        {
            #Run commands using the AzureAd cmdlets ####################################

        }
    }
    else 
    {
        #Login Failed 
        Write-Host "Login Failed or No Access"
        if($EnableLogFile){Write-Logging -Message "Login Failed or No Access" -LogFileNameAndPath $LogFileNameAndPath | Out-Null}
    }
}
catch 
{
    #Login Failed with Error
    if($EnableLogFile){Write-Logging -Message "Login Failed $_.Exception.Message" -LogFileNameAndPath $LogFileNameAndPath | Out-Null}
    #$_.Exception.Message
}
Write-Logging -Message "Ending Script" -LogFileNameAndPath $LogFileNameAndPath | Out-Null