function Import-Modules {
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory = $true, HelpMessage="Provide a module name", ValueFromPipeline = $true)] $Module
    )
    if (!(Get-Module | Where-Object {$_.Name -eq $Module})) {
        Import-Module $Module
    }
}
function Get-RegistryValue {
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory = $true, HelpMessage="Provide a path", ValueFromPipeline = $true)] $Path,
        [Parameter(Position=1, Mandatory = $true, HelpMessage="Provide a name", ValueFromPipeline = $true)] $Name,
        [Parameter(Position=2, Mandatory = $true, HelpMessage="Provide a value", ValueFromPipeline = $true)] $Value
    )
    try {
        $GetValue = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($GetValue -eq $Value) {
            return $true
        }
    }
    catch {
        return $false
    }
    return $false
}
function Get-ADFSAuditing {
    $DistinguishedName = $(Get-ADDomain).DistinguishedName
    try {
        $Auditing = (Get-Acl -Path "AD:CN=ADFS,CN=Microsoft,CN=Program Data,$DistinguishedName" -Audit -ErrorAction SilentlyContinue).Audit

    foreach ($Audit in $Auditing) {
        if (($Audit.IdentityReference -eq "Everyone") -and ($Audit.InheritanceType -eq "All") -and ($Audit.ObjectType -eq "00000000-0000-0000-0000-000000000000") -and ($Audit.ActiveDirectoryRights -match "ReadProperty") -and ($Audit.ActiveDirectoryRights -match "WriteProperty")) {
            return $true
        }
    }
    return $false
}
catch {

}
}
function Get-ExchangeAuditing {
    $DistinguishedName = $(Get-ADDomain).DistinguishedName
    $Auditing = (Get-Acl -Path "AD:CN=Configuration,$DistinguishedName" -audit).Audit
    foreach ($Audit in $Auditing) {
        if (($Audit.IdentityReference -eq "Everyone") -and ($Audit.InheritanceType -eq "All") -and ($Audit.ObjectType -eq "00000000-0000-0000-0000-000000000000") -and ($Audit.ActiveDirectoryRights -match "WriteProperty")) {
            return $true
        }
    }
    return $false
}
function Get-ObjectAuditing {
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory = $true, HelpMessage="Provide an object", ValueFromPipeline = $true)] $Object
    )
    $DistinguishedName = $(Get-ADDomain).DistinguishedName
    $Auditing = (Get-Acl -Path "AD:$DistinguishedName" -Audit).Audit
    foreach ($Audit in $Auditing) {
        if (($Audit.IdentityReference -eq "Everyone") -and ($Audit.InheritanceType -eq "Descendents") -and ($Audit.InheritedObjectType -eq $Object) -and ($Audit.ActiveDirectoryRights -match "CreateChild") -and ($Audit.ActiveDirectoryRights -match "DeleteChild") -and ($Audit.ActiveDirectoryRights -match "Self") -and ($Audit.ActiveDirectoryRights -match "WriteProperty") -and ($Audit.ActiveDirectoryRights -match "DeleteTree") -and ($Audit.ActiveDirectoryRights -match "ExtendedRight") -and ($Audit.ActiveDirectoryRights -match "Delete") -and ($Audit.ActiveDirectoryRights -match "WriteDacl") -and ($Audit.ActiveDirectoryRights -match "WriteOwner")) {
            return $true
        }
    }
    return $false
}
function Get-AdvancedAuditing {
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory = $true, HelpMessage="Provide a policy", ValueFromPipeline = $true)] $Policy
    )
    $TypeDefinition = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Audit
{
    public class AuditPol
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.U1)]
        public static extern bool AuditQuerySystemPolicy(
            [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1), In]
            Guid[] pSubCategoryGuids,
            uint dwPolicyCount,
            out IntPtr ppAuditPolicy);

        public static IEnumerable<AUDIT_POLICY_INFORMATION> AuditQuerySystemPolicy([In] Guid[] pSubCategoryGuids)
        {
            IntPtr ppAuditPolicy;
            if (!AuditQuerySystemPolicy(pSubCategoryGuids, (uint) pSubCategoryGuids.Length, out ppAuditPolicy))
                return new AUDIT_POLICY_INFORMATION[0];

            return ToIEnum<AUDIT_POLICY_INFORMATION>(ppAuditPolicy, pSubCategoryGuids.Length);
        }

        public static IEnumerable<T> ToIEnum<T>(IntPtr ptr, int count, int prefixBytes = 0)
        {
            if (count != 0 && !(ptr == IntPtr.Zero))
            {
                int stSize = Marshal.SizeOf(typeof(T));
                for (int i = 0; i < count; ++i)
                    yield return ToStructure<T>(new IntPtr(ptr.ToInt64() + prefixBytes + i * stSize));
            }
        }

        public static T ToStructure<T>(IntPtr ptr, long allocatedBytes = -1)
        {
            Type type = typeof(T).IsEnum ? Enum.GetUnderlyingType(typeof(T)) : typeof(T);
            if (allocatedBytes < 0L || allocatedBytes >= (long) Marshal.SizeOf(type))
            {
                return (T) Marshal.PtrToStructure(ptr, type);
            }

            throw new InsufficientMemoryException();
        }

        public struct AUDIT_POLICY_INFORMATION
        {
            public Guid AuditSubCategoryGuid;
            public AuditCondition AuditingInformation;
            public Guid AuditCategoryGuid;
        }

        public enum AuditCondition : uint
        {
            /// <summary>Do not change auditing options for the specified event type.
            /// <para>This value is valid for the AuditSetSystemPolicy and AuditQuerySystemPolicy functions.</para></summary>
            POLICY_AUDIT_EVENT_UNCHANGED = 0,

            /// <summary>Audit successful occurrences of the specified event type.
            /// <para>This value is valid for the AuditSetSystemPolicy and AuditQuerySystemPolicy functions.</para></summary>
            POLICY_AUDIT_EVENT_SUCCESS = 1,

            /// <summary>Audit failed attempts to cause the specified event type.
            /// <para>This value is valid for the AuditSetSystemPolicy and AuditQuerySystemPolicy functions.</para></summary>
            POLICY_AUDIT_EVENT_FAILURE = 2,

            /// <summary>Do not audit the specified event type.
            /// <para>This value is valid for the AuditSetSystemPolicy and AuditQuerySystemPolicy functions.</para></summary>
            POLICY_AUDIT_EVENT_NONE = 4,

            /// <summary>Do not change auditing options for the specified event type.
            /// <para>This value is valid for the AuditSetPerUserPolicy and AuditQueryPerUserPolicy functions.</para></summary>
            PER_USER_POLICY_UNCHANGED = 0,

            /// <summary>Audit successful occurrences of the specified event type.
            /// <para>This value is valid for the AuditSetPerUserPolicy and AuditQueryPerUserPolicy functions.</para></summary>
            PER_USER_AUDIT_SUCCESS_INCLUDE = POLICY_AUDIT_EVENT_SUCCESS, // 0x00000001

            /// <summary>Do not audit successful occurrences of the specified event type.
            /// <para>This value is valid for the AuditSetPerUserPolicy and AuditQueryPerUserPolicy functions.</para></summary>
            PER_USER_AUDIT_SUCCESS_EXCLUDE = POLICY_AUDIT_EVENT_FAILURE, // 0x00000002

            /// <summary>Audit failed attempts to cause the specified event type.
            /// <para>This value is valid for the AuditSetPerUserPolicy and AuditQueryPerUserPolicy functions.</para></summary>
            PER_USER_AUDIT_FAILURE_INCLUDE = POLICY_AUDIT_EVENT_NONE, // 0x00000004

            /// <summary>Do not audit failed attempts to cause the specified event type.
            /// <para>This value is valid for the AuditSetPerUserPolicy and AuditQueryPerUserPolicy functions.</para></summary>
            PER_USER_AUDIT_FAILURE_EXCLUDE = 8,

            /// <summary>Do not audit the specified event type.
            /// <para>This value is valid for the AuditSetPerUserPolicy and AuditQueryPerUserPolicy functions.</para></summary>
            PER_USER_AUDIT_NONE = 16, // 0x00000010
        }

        public static int GetPolicy(String uid)
        {
            var guid = new Guid(uid);
            var result = AuditQuerySystemPolicy(new[] {guid});
            foreach (var info in result)
            {
                return (int) info.AuditingInformation;
            }

            return -1;
        }
    }
}
'@
    Add-Type -TypeDefinition $TypeDefinition -Language CSharp

    $result = [Audit.AuditPol]::GetPolicy($Policy)
    if ($Result -eq 3) {
        return $true
    }
    return $false
}
function New-CustomEvent {
    [CmdletBinding()]
    param ( 
        [Parameter(Position=0, Mandatory = $false, HelpMessage="Provide eventlog name", ValueFromPipeline = $true)] $EventLog  = "Application",
        [Parameter(Position=1, Mandatory = $false, HelpMessage="Provide event source", ValueFromPipeline = $true)]  $Source    = "MDIAuditingChecker",
        [Parameter(Position=2, Mandatory = $false, HelpMessage="Provide event source", ValueFromPipeline = $true)]  $EventID   = "1337",
        [Parameter(Position=3, Mandatory = $true, HelpMessage="Provide event message", ValueFromPipeline = $false)] $Message
    )
    $EventMessage = @()
    $EventMessage += $Message | ConvertTo-Json
    $EventMessage += foreach ($Key in $Message.Keys) {
        '{0}:{1}' -f $Key, $Message.$Key
    }
    $id = New-Object System.Diagnostics.EventInstance($EventID,$null,2)
    $Object = New-Object System.Diagnostics.EventLog;
    $Object.Log = $EventLog;
    $Object.Source = $Source;
    $Object.WriteEvent($id, @($EventMessage))
}

Import-Modules -Module ActiveDirectory

$AuditNTLMInDomain = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "auditntlmindomain" -Value 7
$RestrictSendingNTLMTraffic = Get-RegistryValue -Path "HKLM:\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0" -Name "restrictsendingntlmtraffic" -Value 1
$AuditReceivingNTLMTraffic = Get-RegistryValue -Path "HKLM:\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0" -Name "auditreceivingntlmtraffic" -Value 2

$15FieldEngineering = Get-RegistryValue -Path "HKLM:\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Diagnostics" -Name "15 Field Engineering" -Value 5
$ExpensiveSearchResultsThreshold = Get-RegistryValue -Path "HKLM:\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters" -Name "Expensive Search Results Threshold" -Value 1
$InefficientSearchResultsThreshold = Get-RegistryValue -Path "HKLM:\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters" -Name "Inefficient Search Results Threshold" -Value 1
$SearchTimeThresholdMsecs = Get-RegistryValue -Path "HKLM:\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters" -Name "Search Time Threshold (msecs)" -Value 1

$ADFSAuditing = Get-ADFSAuditing
$ExchangeAuditing = Get-ExchangeAuditing

$ObjectAuditingUser = Get-ObjectAuditing -Object "bf967aba-0de6-11d0-a285-00aa003049e2"
$ObjectAuditingGroups = Get-ObjectAuditing -Object "bf967a9c-0de6-11d0-a285-00aa003049e2"
$ObjectAuditingComputer = Get-ObjectAuditing -Object "bf967a86-0de6-11d0-a285-00aa003049e2"
$ObjectAuditingGroupManagedServiceAccount = Get-ObjectAuditing -Object "7b8b558a-93a5-4af7-adca-c017e67f1057"
$ObjectAuditingManagedServiceAccount = Get-ObjectAuditing -Object "ce206244-5827-4a86-ba1c-1c0c386c1b64"

$AuditCredentialValidation = Get-AdvancedAuditing -Policy "0cce923f-69ae-11d9-bed3-505054503030"
$AuditComputerAccountManagement = Get-AdvancedAuditing -Policy "0cce9238-69ae-11d9-bed3-505054503030"
$AuditDistributionGroupManagement = Get-AdvancedAuditing -Policy "0cce9236-69ae-11d9-bed3-505054503030"
$AuditSecurityGroupManagement = Get-AdvancedAuditing -Policy "0cce9237-69ae-11d9-bed3-505054503030"
$AuditUserAccountManagement = Get-AdvancedAuditing -Policy "0cce9235-69ae-11d9-bed3-505054503030"
$AuditDirectoryServiceAccess = Get-AdvancedAuditing -Policy "0cce923b-69ae-11d9-bed3-505054503030"
$AuditDirectoryServiceChanges = Get-AdvancedAuditing -Policy "0cce923c-69ae-11d9-bed3-505054503030"
$AuditSecuritySystemExtension = Get-AdvancedAuditing -Policy "0cce9211-69ae-11d9-bed3-505054503030"

$EventData = [ordered]@{
    Description = "Microsoft Defender for Identity Auditing Checker"
    AuditNTLMInDomain = $AuditNTLMInDomain
    RestrictSendingNTLMTraffic = $RestrictSendingNTLMTraffic
    AuditReceivingNTLMTraffic = $AuditReceivingNTLMTraffic
    FieldEngineering = $15FieldEngineering
    ExpensiveSearchResultsThreshold = $ExpensiveSearchResultsThreshold
    InefficientSearchResultsThreshold = $InefficientSearchResultsThreshol
    SearchTimeThresholdMsecs = $SearchTimeThresholdMsecs
    ADFSObjectAuditing = $ADFSAuditing
    ExchangeAuditing = $ExchangeAuditing
    ObjectAuditingUser = $ObjectAuditingUser
    ObjectAuditingGroups = $ObjectAuditingGroups
    ObjectAuditingComputer = $ObjectAuditingComputer
    ObjectAuditingGroupManagedServiceAccount = $ObjectAuditingGroupManagedServiceAccount
    ObjectAuditingManagedServiceAccount = $ObjectAuditingManagedServiceAccount
    AuditCredentialValidation = $AuditCredentialValidation
    AuditComputerAccountManagement = $AuditComputerAccountManagement
    AuditDistributionGroupManagement = $AuditDistributionGroupManagement
    AuditSecurityGroupManagement = $AuditSecurityGroupManagement
    AuditUserAccountManagement = $AuditUserAccountManagement
    AuditDirectoryServiceAccess = $AuditDirectoryServiceAccess
    AuditDirectoryServiceChanges = $AuditDirectoryServiceChanges
    AuditSecuritySystemExtension = $AuditSecuritySystemExtension
}

$Message = @"
Microsoft Defender for Identity Auditing Checker`n
AuditNTLMInDomain = $AuditNTLMInDomain
RestrictSendingNTLMTraffic = $RestrictSendingNTLMTraffic
AuditReceivingNTLMTraffic = $AuditReceivingNTLMTraffic
15FieldEngineering = $15FieldEngineering
ExpensiveSearchResultsThreshold = $ExpensiveSearchResultsThreshold
InefficientSearchResultsThreshold = $InefficientSearchResultsThreshold
SearchTimeThresholdMsecs = $SearchTimeThresholdMsecs
ADFSObjectAuditing = $ADFSAuditing
ExchangeAuditing = $ExchangeAuditing
ObjectAuditingUser = $ObjectAuditingUser
ObjectAuditingGroups = $ObjectAuditingGroups
ObjectAuditingComputer = $ObjectAuditingComputer
ObjectAuditingGroupManagedServiceAccount = $ObjectAuditingGroupManagedServiceAccount
ObjectAuditingManagedServiceAccount = $ObjectAuditingManagedServiceAccount
AuditCredentialValidation = $AuditCredentialValidation
AuditComputerAccountManagement = $AuditComputerAccountManagement
AuditDistributionGroupManagement = $AuditDistributionGroupManagement
AuditSecurityGroupManagement = $AuditSecurityGroupManagement
AuditUserAccountManagement = $AuditUserAccountManagement
AuditDirectoryServiceAccess = $AuditDirectoryServiceAccess
AuditDirectoryServiceChanges = $AuditDirectoryServiceChanges
AuditSecuritySystemExtension = $AuditSecuritySystemExtension
"@

New-CustomEvent -Message $EventData