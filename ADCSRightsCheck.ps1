using namespace System.Collections.Generic
using namespace System.Security.Principal
using namespace System.DirectoryServices

function Get-ADCertificateTemplates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [pscredential]$Credential
    )

    # Import required modules
    Import-Module ActiveDirectory

    # Define the enrollment flags using an ordered dictionary
    $flags = [ordered]@{
        1 = "INCLUDE_SYMMETRIC_ALGORITHMS"
        2 = "PEND_ALL_REQUESTS"
        4 = "PUBLISH_TO_KRA_CONTAINER"
        8 = "PUBLISH_TO_DS"
        16 = "AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE"
        32 = "AUTO_ENROLLMENT"
        64 = "DOMAIN_AUTHENTICATION_NOT_REQUIRED"
        128 = "PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT"
        256 = "USER_INTERACTION_REQUIRED"
        512 = "REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE"
        1024 = "ALLOW_ENROLL_ON_BEHALF_OF"
        2048 = "ADD_OCSP_NOCHECK"
        4096 = "ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL"
        8192 = "NOREVOCATIONINFOINISSUEDCERTS"
        16384 = "INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS"
        32768 = "ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT"
        65536 = "ISSUANCE_POLICIES_FROM_REQUEST"
        131072 = "SKIP_AUTO_RENEWAL"
        262144 = "NO_SECURITY_EXTENSION"
        524288 = "IGNORE_EMPTY_CRL_DP"
        1048576 = "ENFORCE_KEY_USAGE_EXTENSION"
        2097152 = "ENFORCE_ENCRYPTION_KEY_USAGE"
        4194304 = "REQUIRE_OCSP_REVOCATION_CHECK"
        8388608 = "REQUIRE_CRL_REVOCATION_CHECK"
        16777216 = "REQUIRE_OCSP_OR_CRL_REVOCATION_CHECK"
        33554432 = "REQUIRE_OCSP_AND_CRL_REVOCATION_CHECK"
        67108864 = "DISABLE_LEGACY_CRYPTO"
        134217728 = "ENABLE_PRE_WINDOWS_10_CRYPTO"
        268435456 = "REQUIRE_DIRECTORY_BASED_CERTIFICATE_ISSUANCE_POLICY_PROCESSING"
        536870912 = "ENABLE_CERTIFICATE_APPLICATION_POLICY"
        1073741824 = "DISABLE_ROUTER_CERTIFICATE_AUTO_ENROLLMENT"
        2147483648 = "NO_TEMPLATE_VERSION_UPGRADE_SCHEMA_CHECK"
    }

    # Function to map enrollment flags to their descriptions
    function Get-EnrollmentFlagDescriptions([Int64]$enrollmentFlag) {
        $flags.GetEnumerator().Where{$enrollmentFlag -band [Int64]$_.Key}.ForEach{$_.Value} -join ", "
    }

    # Function to get calculated rights
    function Get-CalculatedRights([ActiveDirectorySecurity]$sd) {
        $rights = [Dictionary[string, List[string]]]::new()
        
        $sd.GetAccessRules($true, $true, [SecurityIdentifier]).ForEach{
            $identity = $_.IdentityReference.Translate([NTAccount]).Value
            if (-not $rights.ContainsKey($identity)) {
                $rights[$identity] = [List[string]]::new()
            }
            $rights[$identity].Add("$($_.ActiveDirectoryRights) ($($_.AccessControlType))")
        }
        
        $rights.GetEnumerator().ForEach{
            "$($_.Key): $($_.Value -join ', ')"
        } -join '; '
    }

    # Prepare parameters for AD cmdlets
    $adParams = @{}
    if ($Server) { $adParams['Server'] = $Server }
    if ($Credential) { $adParams['Credential'] = $Credential }

    # Set the search base for the Configuration Naming Context
    $configNC = (Get-ADRootDSE @adParams).configurationNamingContext

    # Search for certificate template objects
    $certificateTemplates = Get-ADObject -Filter 'objectClass -eq "pKICertificateTemplate"' -SearchBase $configNC -Properties * @adParams

    # Process and display the certificate template information
    $certificateTemplates | ForEach-Object {
        $sd = $_.nTSecurityDescriptor
        
        [PSCustomObject]@{
            Name = $_.Name
            DisplayName = $_.DisplayName
            DistinguishedName = $_.DistinguishedName
            ObjectClass = $_.ObjectClass
            Created = $_.Created
            Modified = $_.Modified
            'msPKI-Cert-Template-OID' = $_.'msPKI-Cert-Template-OID'
            'msPKI-Enrollment-Flag' = $_.'msPKI-Enrollment-Flag'
            EnrollmentFlagDescriptions = Get-EnrollmentFlagDescriptions $_.'msPKI-Enrollment-Flag'
            SDDL = $sd.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
            CalculatedRights = Get-CalculatedRights $sd
        }
    } | Format-Table -AutoSize -Wrap
}
