#Requires -Version 7
class PolicyTypes : System.Management.Automation.IValidateSetValuesGenerator
{
    [String[]] GetValidValues()
    {
        return @('Group', 'ServicePrincipal', 'Application')
    }
}


function BuildScopes
{
    <#
    .SYNOPSIS
    Create Scopes block based on provided policy type
    #>
    param(
        [parameter(Mandatory = $true)]
        [object]$TargetObject,

        [parameter(Mandatory = $true)]
        [ValidateSet([PolicyTypes])]
        [string]$PolicyType
    )

    switch -regex ($PolicyType)
    {
        'Group'
        {
            return @{
                '@odata.type'   = '#microsoft.graph.principalResourceMembershipsScope'
                principalScopes = @(
                    @{
                        '@odata.type' = '#microsoft.graph.accessReviewQueryScope'
                        'query'       = "/v1.0/users?`$filter=userType eq 'Guest'"
                        'queryType'   = 'MicrosoftGraph'
                    }
                )
                resourceScopes  = @(
                    @{
                        '@odata.type' = '#microsoft.graph.accessReviewQueryScope'
                        'query'       = "/v1.0/groups/$($TargetObject.Id)/members/microsoft.graph.user/?`$count=true&`$filter=(userType eq 'Guest')"
                        'queryType'   = 'MicrosoftGraph'
                    },
                    @{
                        '@odata.type' = '#microsoft.graph.accessReviewQueryScope'
                        'query'       = "/beta/teams/$($TargetObject.Id)/channels?`$filter=membershipType eq 'shared'"
                        'queryType'   = 'MicrosoftGraph'
                    }
                )
            }
        }
        'ServicePrincipal|Application'
        {
            return @{
                '@odata.type'   = '#microsoft.graph.principalResourceMembershipsScope'
                principalScopes = @(
                    @{
                        '@odata.type' = '#microsoft.graph.accessReviewQueryScope'
                        'query'       = "/v1.0/users?`$filter=userType eq 'Guest'"
                        'queryType'   = 'MicrosoftGraph'
                    },
                    @{
                        '@odata.type' = '#microsoft.graph.accessReviewQueryScope'
                        'query'       = "./members/microsoft.graph.user/?`$count=true&`$filter=(userType eq 'Guest')"
                        'queryType'   = 'MicrosoftGraph'
                        'queryRoot'   = '/v1.0/groups'
                    }
                )
                resourceScopes  = @(
                    @{
                        '@odata.type' = '#microsoft.graph.accessReviewQueryScope'
                        'query'       = "/v1.0/servicePrincipals/$($TargetObject.Id)"
                        'queryType'   = 'MicrosoftGraph'
                    }
                )
            }
        }
    }
}
function ApplyPolicy
{
    <#
    .SYNOPSIS
    ApplyPolicy creates and applies a new governance policy

    .DESCRIPTION
    ApplyPolicy creates and applies a new governance policy on the specified object

    .PARAMETER PolicyTarget
    Object to apply policy to

    .PARAMETER PolicyType
    Type of policy to create based on object type
        Group
        ServicePrincipal
        Application

    .PARAMETER Start
    DateTime of when policy is to go into effect

    .PARAMETER FallbackReviewers
    Array of fallback reviewers to assign

    #>
    param(
        [parameter(Mandatory = $true)]
        [object]$PolicyTarget,

        [parameter(Mandatory = $true)]
        [ValidateSet([PolicyTypes])]
        [string]$PolicyType,

        [parameter(Mandatory = $true)]
        [datetime]$Start,

        [parameter(Mandatory = $true)]
        [String[]]$FallbackReviewers
    )

    #build start date string
    $startDate = $Start.ToString('yyyy-MM-dd')

    #region CreatorInfo
    if ($null -eq $CreatedBy)
    {
        $createdBy = @{
            id                = $PolicyTarget.Owners[0].Id
            displayName       = $PolicyTarget.Owners[0].AdditionalProperties.displayName
            userPrincipalName = $PolicyTarget.Owners[0].AdditionalProperties.userPrincipalName
        }
    }
    #endregion CreatorInfo

    #region params
    # Main param builder
    #
    $BannerText = 'Guest membership access review'
    #
    $ReviewTarget = $PolicyTarget.Id
    # If the owners were found via application we need to get the objectId of the app to correctly set reviews
    if ($PolicyType -eq 'Application')
    {
        $ReviewTarget = (Get-MgApplication -Filter "appid eq '$($PolicyTarget.AppId)'").Id
    }
    $params = @{
        CreatedBy               = $createdBy
        DisplayName             = "$BannerText - $($PolicyTarget.DisplayName)"
        DescriptionForAdmins    = "$BannerText- $($PolicyTarget.DisplayName)"
        DescriptionForReviewers = 'Access by guests to Microsoft corporate resources, including via groups or app assignments, should reviewed regularly. For more details, please see: https://aka.ms/GuestReview'
        Scope                   = BuildScopes -TargetObject $PolicyTarget -PolicyType $PolicyType
        Reviewers               = @(
            @{
                Query     = "/$($PolicyType)s/$ReviewTarget/owners"
                QueryType = 'MicrosoftGraph'
            }
        )
        Settings                = @{
            MailNotificationsEnabled        = $true
            ReminderNotificationsEnabled    = $true
            JustificationRequiredOnApproval = $false
            InstanceDurationInDays          = 30
            RecommendationsEnabled          = $true
            # Apply actions by default if reviewers failed to perform review
            DefaultDecisionEnabled          = $true
            DefaultDecision                 = 'Deny'
            AutoApplyDecisionsEnabled       = $true
            ApplyActions                    = @(
                @{
                    '@odata.type' = '#microsoft.graph.removeAccessApplyAction'
                }
            )
            # Set recommendation to look at users inactive over the last 90 days
            recommendationInsightSettings   = @(
                @{
                    '@odata.type'                  = '#microsoft.graph.userLastSignInRecommendationInsightSetting'
                    recommendationLookBackDuration = 'P90D'
                    signInScope                    = 'tenant'
                }
            )
            # Semi-annual review cycle
            Recurrence                      = @{
                Pattern = @{
                    type     = 'absoluteMonthly'
                    Interval = 6
                }
                Range   = @{
                    type      = 'noEnd'
                    StartDate = $StartDate
                }
            }
        }
    }
    #endregion params
    #region fallbackreviewers
    # Only add param if list is non-null
    if ($FallbackReviewers.Count -gt 0)
    {
        $FallbackReviewList = @()
        foreach ($r in $FallbackReviewers)
        {
            $FallbackReviewList += @{
                Query     = "/users/$r"
                QueryType = 'MicrosoftGraph'
            }
        }
        $params.Add('FallbackReviewers', $FallbackReviewList)
    }
    #endregion fallbackreviewers

    try
    {
        $ret = New-MgIdentityGovernanceAccessReviewDefinition -BodyParameter $params -ErrorAction Stop
        Write-Verbose "Successfully created AR for $($PolicyTarget.Id)/$($PolicyTarget.DisplayName)"
        [PSCustomObject]@{
            AccessReviewId      = $ret.Id
            PolicyType          = $PolicyType
            ImplementedDateTime = Get-Date -Format 'yyyy-MM-dd'
            StartDateTime       = $Start
            TargetObject        = $PolicyTarget.Id
        }
    }
    catch
    {
        Write-Error "Failed to create AR for $($PolicyTarget.Id)/$($PolicyTarget.DisplayName): $_"
    }
}
#region Reviewers
<#
    ValidateBackupReviewers - perform lookup on provided entries to ensure valid accounts
    Add entries to hashtable to reduce subsequent graph calls
    Build list of reviewers for inclusion in New-MgIdentityGovernanceAccessReviewDefinition params
#>
function ValidateBackupReviewers
{
    [OutputType([String[]])]
    param(
        [parameter(Mandatory = $true)]
        [String[]]$reviewList
    )

    $validReviewers = @()
    foreach ($user in $reviewList)
    {
        if ($_userTable.ContainsKey($user))
        {
            $validReviewers += $_userTable[$user]
        }
        else
        {
            try
            {
                $u = Get-MgUser -UserId $user -ExpandProperty manager -ErrorAction Stop
                Write-Verbose "Added user $user to reviewers list"
                $_userTable.Add($user, $u.Id)
                AddOwnerManager -ownerId $u.Id -managerId $u.Manager.Id
                $validReviewers += $u.Id
            }
            catch
            {
                Write-Verbose "Unable to resolve $user as valid reviewer"
            }
        }
    }
    $validReviewers
}
function AddOwnerManager
{
    param(
        [parameter(Mandatory = $true)]
        [String]$ownerId,
        [parameter(Mandatory = $true)]
        [String]$managerId
    )

    if ($_managerList.ContainsKey($o))
    {
        if (-not [string]::IsNullOrEmpty($_managerList[$o]))
        {
            $mlist += $_managerList[$ownerId]
        }
        else
        {
            Write-Verbose "Adding $($mgr.Id) for owner $o"
            $_managerList.Add($ownerId, $managerId)
        }
    }
}
<#
    RetrieveOwnerManagers - perform lookup of managers for provided entries
    Add entries to hashtable to reduce subsequent graph calls
    Build list of reviewers for inclusion in New-MgIdentityGovernanceAccessReviewDefinition params
#>
function RetrieveOwnerManagers
{
    [OutputType([String[]])]
    param(
        [parameter(Mandatory = $true)]
        [String[]]$ownerList
    )

    $mlist = @()
    foreach ($o in $ownerList)
    {
        if ($_managerList.ContainsKey($o) -and -not [string]::IsNullOrEmpty($_managerList[$o]))
        {
            $mlist += $_managerList[$o]
        }
        else
        {
            # Should never get here as manager should've been added during user retrieval and $expand
            $mgr = Get-MgUserManager -UserId $o -ErrorAction SilentlyContinue
            if ($null -ne $mgr)
            {
                Write-Verbose "Adding $($mgr.Id) for owner $o"
                $_managerList.Add($o, $mgr.Id)
                $mlist += $mgr.Id
            }
            else
            {
                $_managerList.Add($o, $null)
            }
        }
    }
    $mlist
}
#endregion Reviewers
#
# https://learn.microsoft.com/en-us/azure/templates/microsoft.authorization/accessreviewscheduledefinitions?pivots=deployment-language-bicep
# https://github.com/microsoftgraph/microsoft-graph-docs/blob/main/api-reference/beta/api/accessreviewset-post-definitions.md
# https://learn.microsoft.com/en-us/graph/api/accessreviewset-post-definitions?view=graph-rest-beta&tabs=http
function Set-AzureGovernancePolicy
{
    <#
    .SYNOPSIS
    Set access review policy on an group

    .DESCRIPTION
    The Set-AzureGovernancePolicy cmdlet applies a default access review policy in the specified object(s)

    .PARAMETER Id
    Specifies the id (ObjectId) of an object in Azure Active Directory

    .PARAMETER Start
    Date to start the access review

    .PARAMETER ProcessLegacyGroups
    Process objects with less than required owner count

    .PARAMETER BackupReviewers
    Optional list of backup reviewers to add to access review.  If not specified, function will attempt to create backup reviewers based on object owners' managers

    .PARAMETER CreatedById
    Optional object id of object to assign as creator of reviews.  Default is FirstOrDefault owner of object

    .PARAMETER LogFilePath
    Optiona destination path for reporting purposes

   .PARAMETER PolicyType
    Type of policy for object object type
        Group
        ServicePrincipal
        Application

    .EXAMPLE
    '7fce970a-291c-4674-a556-37c1e82df090', '9a0f0187-ad3d-4f69-8bb1-5287dac84acc' | Set-AzureGovernancePolicy -StartDate '5-1-2024' -PolicyType Group

    .EXAMPLE
    (Get-MgGroup -Filter "startswith(displayName,'ADO')" -CountVariable gcount -ConsistencyLevel Eventual).Id | Set-AzureGovernancePolicy -PolicyType Group -ProcessLegacyGroups:$true

    .LINK
    https://learn.microsoft.com/en-us/graph/api/accessreviewset-post-definitions?view=graph-rest-beta&tabs=http
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'ObjectId of the target object')]
        [Alias('ObjectId')]
        [ValidatePattern('^([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}$')]
        [string]$Id,

        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [datetime]$StartDate,

        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [string[]]$BackupReviewers,

        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true)]
        [bool]$ProcessLegacyGroups = $false,

        [parameter(Mandatory = $false)]
        [String]$CreatedById,

        [parameter(Mandatory = $false)]
        [String[]]$LogFilePath,

        [Parameter(Mandatory = $true)]
        [ValidateSet([PolicyTypes])]
        [string]$PolicyType
    )

    Begin
    {
        # Test for authenticated session before any pipeline activity
        $ctx = Get-MgContext
        if ($null -eq $ctx)
        {
            throw 'You must be authenticated using Connect-MgGraph'
        }
        # Save home tenantId for app check
        $_homeTenant = $ctx.TenantId
        if ($null -eq $StartDate)
        {
            $StartDate = (Get-Date).AddDays(5)
        }
        $_managerList = @{}
        $_userTable = @{}

        if ($null -eq $CreatedById)
        {
            Write-Warning 'CreatedBy not set, using application owner as default'
        }
        else
        {
            try
            {
                $u = Get-MgUser -UserId $CreatedById -Property id, displayname, userprincipalname -ErrorAction Stop
                $createdBy = @{
                    Id                = $u.Id
                    displayName       = $u.DisplayName
                    userPrincipalName = $u.UserPrincipalName
                }
            }
            catch
            {
                Write-Warning "Unable to retrieve $CreatedById, using application owner as default"
            }
        }
    }

    Process
    {
        $validBackupReviewers = @()

        switch ($PolicyType)
        {
            'Group'
            {
                # Validate group and owners
                try
                {
                    $target = Get-MgGroup -GroupId $id -ExpandProperty owners -Property id, displayName, owners
                }

                catch
                {
                    Write-Error "Error retrieving information for group $Id - $_"
                    return $null
                }

                $target = $grp
                $ownerList = $target.Owners
                break
            }
            'ServicePrincipal'
            {
                # Validate Service Principal and owners
                try
                {
                    $sp = Get-MgServicePrincipal -ServicePrincipalId $id -ExpandProperty Owners -Property id, displayname, owners, appid, AppOwnerOrganizationId
                }

                catch
                {
                    Write-Error "Error retrieving information for group $Id - $_"
                    continue
                }

                $target = $sp
                $ownerlist = $sp.owners
                # If SP is missing owners, check to see if it's registered in the home tenant and try ownership from there
                if (($null -eq $ownerList -or $ownerlist.Count -eq 0) -and $target.AppOwnerOrganizationId -eq $_homeTenant)
                {
                    Write-Warning "SP $id missing mandatory owners count, checking app registration for owners"
                    $app = Get-MgApplication -Filter "appid eq '$($sp.appid)'" -Property owners -ExpandProperty owners -ErrorAction SilentlyContinue
                    If ($null -eq $app -or $app.owners.count -eq 0)
                    {
                        if ($WriteWarningsToFile)
                        {
                            "Application $($app.DisplayName) missing mandatory owner count, skipping AR processing" | Out-File -FilePath $WarningOutputFilePath -Append -Encoding ascii #easier to read for me than the 2&>1 stuff
                        }
                        # Nothing here, time to leave
                        return
                    }
                    Else
                    {
                        $ownerlist = $app.Owners
                        $PolicyType = 'Application'
                    }
                }
                # Set ProcessLegacyGroups to bypass later group-based AR skip
                $ProcessLegacyGroups = $true
            }
        }

        #region buildownerlists
        # If the object has less than the mandated 2 users and we're not processing legacy groups then notify and skip
        if ($ownerListCount -lt 2 -and -not $ProcessLegacyGroups)
        {
            Write-Warning "$PolicyType $id missing mandatory owner count, skipping AR processing"
            If ($WriteWarningsToFile)
            {
                "$PolicyType $id missing mandatory owner count, skipping AR processing" | Out-File -FilePath $WarningOutputFilePath -Append -Encoding ascii #easier to read for me than the 2&>1 stuff
            }
            continue
        }
        # In cases where there is no owner, require backup reviewer be provided or notify and continue pipeline
        if ($ownerList.Count -eq 0 -and $BackupReviewers.Count -eq 0)
        {
            Write-Warning "$PolicyType $id has no reviewers available, skipping AR processing"
            If ($LogFilePath)
            {
                "$PolicyType $id has no reviewers available, skipping AR processing" | Out-File -FilePath $LogFilePath -Append -Encoding ascii #easier to read for me than the 2&>1 stuff
            }
            continue
        }
        # Owners present so build list to include managers and any provided backup reviewers
        if ($ownerList.Count -gt 0)
        {
            $validBackupReviewers = @(RetrieveOwnerManagers -ownerList $ownerList.Id | Sort-Object -Unique)
        }

        if ($BackupReviewers.Count -gt 0)
        {
            $validBackupReviewers += ValidateBackupReviewers -reviewList $BackupReviewers
        }
        if ($validBackupReviewers.Count -eq 0)
        {
            Write-Warning "No fallback reviews available for $PolicyType $($target.Id)"
            If ($LogFilePath)
            {
                "No fallback reviews available for $PolicyType $($target.Id)" | Out-File -FilePath $LogFilePath -Append -Encoding ascii #easier to read for me than the 2&>1 stuff
            }
        }
        #endregion buildownerlists

        ApplyPolicy -PolicyTarget $target -PolicyType $PolicyType -Start $StartDate -FallbackReviewers $validBackupReviewers
    }

}
$spid = '50541732-c369-4b60-b0cb-340a2cd9a833'
#$spid = '13fbfc35-8dab-48ed-bdb4-21f632e8ce67'
Set-AzureGovernancePolicy -Id $spid -PolicyType ServicePrincipal #  -Verbose
