# Overlapping rules: Sagan-converted and SigmaHQ

A precise, confidence-tiered list of the rule pairs that overlap between the converted Sagan corpus and SigmaHQ. Each pair sits in the single strongest tier its evidence earns.

> **This is a point-in-time snapshot.** Both corpora change daily, so the pairs below are valid only for the exact commits pinned here. Against a later state of either repository the list may be wrong; regenerate it with `sagan2sigma-inventory` after updating the corpora.

## Provenance

- Generated: 2026-08-06
- Engine: rsigma 0.21.0
- Conversion profile: `rsigma-syslog`

| Corpus | Commit | Committed | Source |
| --- | --- | --- | --- |
| sagan-rules | `142303c749801b4882b73a36e94e8d76f79e7500` | 2026-08-05T14:53:40-04:00 | https://github.com/quadrantsec/sagan-rules.git |
| SigmaHQ | `8eaafff1f2845a696050e05e72ba1140ee190698` | 2026-08-05T10:52:16+02:00 | https://github.com/SigmaHQ/sigma.git |

Total overlapping pairs listed: **2056**.

## Confidence tiers

Read top to bottom: the first tiers are established by running the engine, the last two are lexical leads for a human to review and are **not** grounds to retire a rule.

| Tier | Pairs | Backed by | What it means |
| --- | ---: | --- | --- |
| **Confirmed by both analyses** | 6 | overlap engine + witness invariant, and conceptual | The engine confirmed both rules fire on one synthesised event, they are log-source compatible, and independently the conceptual analysis found them searching for the same distinctive terms. Strongest evidence available; review these first. |
| **Behaviourally confirmed coverage (tested)** | 58 | overlap engine + witness-fires-both invariant | Every event synthesised from the converted rule also fired the SigmaHQ rule (or each fired all of the other's), log sources are compatible, and the witness event is attached and replayable. Deploying SigmaHQ makes the converted rule redundant on the evidence. |
| **Behaviourally related, not coverage (tested)** | 18 | overlap engine (co-firing tested) | The two fired together on at least one event, log sources are compatible, but neither contains the other (an overlap), or the converted rule is the broader of the two. Related, not interchangeable. |
| **Cross-log-source co-firing (tested, not deployable)** | 516 | overlap engine (co-firing tested); log-source gate | The engine confirmed the two fire on one event, but their log sources differ, so in production the SigmaHQ rule would not see that event. Usually a SigmaHQ keyword rule matching a common word in another product's raw text. Not deployable coverage; recorded for completeness. |
| **Conceptual candidate, strong lexical match (review)** | 289 | conceptual lexical similarity only | No behavioural co-firing was found, but the two rules share distinctive search terms strongly enough to suggest they detect the same thing. A lead for human review, not a tested fact. |
| **Conceptual candidate, weaker lexical match (review)** | 1169 | conceptual lexical similarity only | A weaker lexical similarity, near the floor. A candidate to skim, most useful read alongside its shared terms. |

## Confirmed by both analyses (6)

The engine confirmed both rules fire on one synthesised event, they are log-source compatible, and independently the conceptual analysis found them searching for the same distinctive terms. Strongest evidence available; review these first.

| Sagan SID | Converted rule | SigmaHQ rule | SigmaHQ path | Relation | Events | Shared terms |
| --- | --- | --- | --- | --- | ---: | --- |
| `5008438` | [WINDOWS-AUTH] A member was added to a security-enabled | A Member Was Added to a Security-Enabled Global Group | `rules/windows/builtin/security/account_management/win_security_member_added_security_enabled_global_group.yml` | `SAGAN_REDUNDANT` | 2 | security-enabled, global, member, added, group |
| `5003764` | [WINDOWS-SECURITY] An attempt was made to set the Direc | Password Change on Directory Service Restore Mode (DSRM | `rules/windows/builtin/security/win_security_susp_dsrm_password_change.yml` | `SAGAN_REDUNDANT` | 1 | restore, made, mode, administrator, password, set |
| `5009383` | [WINDOWS-SECURITY] An attempt was made to set the Direc | Password Change on Directory Service Restore Mode (DSRM | `rules/windows/builtin/security/win_security_susp_dsrm_password_change.yml` | `SAGAN_REDUNDANT` | 1 | restore, made, mode, administrator, password, set |
| `5003767` | [WINDOWS-SECURITY] A replay attack was detected | Replay Attack Detected | `rules/windows/builtin/security/win_security_replay_attack_detected.yml` | `SAGAN_REDUNDANT` | 1 | replay, attack |
| `5009379` | [WINDOWS-SECURITY] A replay attack was detected | Replay Attack Detected | `rules/windows/builtin/security/win_security_replay_attack_detected.yml` | `SAGAN_REDUNDANT` | 1 | replay, attack |
| `5013825` | [WINDOWS-MISC] NetLogon event with mimikatz string (Zer | Zerologon Exploitation Using Well-known Tools | `rules/windows/builtin/system/netlogon/win_system_possible_zerologon_exploitation_using_wellknown_tools.yml` | `SAGAN_REDUNDANT` | 1 | zerologon, mimikatz |

## Behaviourally confirmed coverage (tested) (58)

Every event synthesised from the converted rule also fired the SigmaHQ rule (or each fired all of the other's), log sources are compatible, and the witness event is attached and replayable. Deploying SigmaHQ makes the converted rule redundant on the evidence.

| Sagan SID | Converted rule | SigmaHQ rule | SigmaHQ path | Relation | Events | Shared terms |
| --- | --- | --- | --- | --- | ---: | --- |
| `5007131` | [WINDOWS-POWERSHELL] Keylogger Detected | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5009344` | [WINDOWS-POWERSHELL] Keylogger Detected | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5010477` | [WINDOWS-POWERSHELL] Mimikatz Keyword In Script | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5010479` | [WINDOWS-POWERSHELL] Mimikatz Command Line Parameters ( | Mimikatz Use | `rules/windows/builtin/win_alert_mimikatz_keywords.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5010480` | [WINDOWS-POWERSHELL] Mimikatz Command Line Parameters ( | Mimikatz Use | `rules/windows/builtin/win_alert_mimikatz_keywords.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5006792` | [WINDOWS-MALWARE] Potato ransomware file extension dete | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 3 |  |
| `5006838` | [WINDOWS-MALWARE] VBRansom 7 ransomware file extension | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 3 |  |
| `5006993` | [WINDOWS-MALWARE] Potato ransomware file extension dete | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 3 |  |
| `5007033` | [WINDOWS-MALWARE] VBRansom 7 ransomware file extension | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 3 |  |
| `5008868` | [WINDOWS-MALWARE] Potato ransomware file extension dete | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 3 |  |
| `5008914` | [WINDOWS-MALWARE] VBRansom 7 ransomware file extension | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 3 |  |
| `5009069` | [WINDOWS-MALWARE] Potato ransomware file extension dete | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 3 |  |
| `5009109` | [WINDOWS-MALWARE] VBRansom 7 ransomware file extension | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 3 |  |
| `5001695` | [WINDOWS-AUTH] CRITICAL - User added to Domain Administ | Group Modification Logging | `deprecated/windows/win_security_group_modification_logging.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5001695` | [WINDOWS-AUTH] CRITICAL - User added to Domain Administ | A Member Was Added to a Security-Enabled Global Group | `rules/windows/builtin/security/account_management/win_security_member_added_security_enabled_global_group.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5008438` | [WINDOWS-AUTH] A member was added to a security-enabled | Group Modification Logging | `deprecated/windows/win_security_group_modification_logging.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5008480` | [WINDOWS-AUTH] User added to Domain Administrators grou | Group Modification Logging | `deprecated/windows/win_security_group_modification_logging.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5008480` | [WINDOWS-AUTH] User added to Domain Administrators grou | A Member Was Added to a Security-Enabled Global Group | `rules/windows/builtin/security/account_management/win_security_member_added_security_enabled_global_group.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5009439` | [WINDOWS-SECURITY] Code integrity determined that the i | Failed Code Integrity Checks | `rules/windows/builtin/security/win_security_codeintegrity_check_failure.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5013680` | [WINDOWS-AUTH] User removed from Domain Administrators | Group Modification Logging | `deprecated/windows/win_security_group_modification_logging.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5013680` | [WINDOWS-AUTH] User removed from Domain Administrators | A Member Was Removed From a Security-Enabled Global Gro | `rules/windows/builtin/security/account_management/win_security_member_removed_security_enabled_global_group.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5013940` | [CISCO-IOS] WebUI Accessed by cisco_tac_admin or cisco_ | Exploitation Indicators Of CVE-2023-20198 | `rules-emerging-threats/2023/Exploits/CVE-2023-20198/cisco_syslog_cve_2023_20198_ios_xe_web_ui.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5014335` | [MS-DEFENDER] Windows Defender has detected CobaltStrik | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5014335` | [MS-DEFENDER] Windows Defender has detected CobaltStrik | Windows Defender Threat Detected | `rules/windows/builtin/windefend/win_defender_threat.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5014336` | [MS-DEFENDER] Windows Defender has detected RunDLLExec | Windows Defender Threat Detected | `rules/windows/builtin/windefend/win_defender_threat.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5000123` | [SYSLOG] Oversized packet - ping of death? | Suspicious Log Entries | `rules/linux/builtin/lnx_shell_susp_log_entries.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002090` | [WINDOWS-APPLOCKER] Allowed program to execute | AppLocker Application Would Have Been Blocked | `rules/windows/builtin/applocker/win_applocker_application_would_have_been_blocked.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002091` | [WINDOWS-APPLOCKER] Application blocked | AppLocker Prevented Application or Script from Running | `rules/windows/builtin/applocker/win_applocker_application_was_prevented_from_running.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002093` | [WINDOWS-APPLOCKER] Allowed MSI/Script, but would have | AppLocker Application Would Have Been Blocked | `rules/windows/builtin/applocker/win_applocker_application_would_have_been_blocked.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002094` | [WINDOWS-APPLOCKER] Prevent MSI/Script to execute | AppLocker Prevented Application or Script from Running | `rules/windows/builtin/applocker/win_applocker_application_was_prevented_from_running.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002096` | [WINDOWS-APPLOCKER] Package application audited | AppLocker Application Would Have Been Blocked | `rules/windows/builtin/applocker/win_applocker_application_would_have_been_blocked.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002097` | [WINDOWS-APPLOCKER] Package application disabled | AppLocker Prevented Application or Script from Running | `rules/windows/builtin/applocker/win_applocker_application_was_prevented_from_running.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002099` | [WINDOWS-APPLOCKER] Package application installation au | AppLocker Application Would Have Been Blocked | `rules/windows/builtin/applocker/win_applocker_application_would_have_been_blocked.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002100` | [WINDOWS-APPLOCKER] Package application installation di | AppLocker Prevented Application or Script from Running | `rules/windows/builtin/applocker/win_applocker_application_was_prevented_from_running.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5003769` | [WINDOWS-SECURITY] SID History was added to an account | Addition of SID History to Active Directory Object | `rules/windows/builtin/security/win_security_susp_add_sid_history.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5003770` | [WINDOWS-SECURITY] An attempt to add SID History to an | Addition of SID History to Active Directory Object | `rules/windows/builtin/security/win_security_susp_add_sid_history.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005654` | [LINUX-AUDITD] /tmp/ysocereal.jar execution | Suspicious Activity in Shell Commands | `rules/linux/builtin/lnx_shell_susp_commands.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5006110` | [ONELOGIN] USER_ASSUMED_USER | OneLogin User Assumed Another User | `rules/identity/onelogin/onelogin_assumed_another_user.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5008410` | [WINDOWS-APPLOCKER] Allowed program to execute | AppLocker Application Would Have Been Blocked | `rules/windows/builtin/applocker/win_applocker_application_would_have_been_blocked.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5008411` | [WINDOWS-APPLOCKER] Application blocked | AppLocker Prevented Application or Script from Running | `rules/windows/builtin/applocker/win_applocker_application_was_prevented_from_running.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5008413` | [WINDOWS-APPLOCKER] Allowed MSI/Script, but would have | AppLocker Application Would Have Been Blocked | `rules/windows/builtin/applocker/win_applocker_application_would_have_been_blocked.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5008414` | [WINDOWS-APPLOCKER] Prevent MSI/Script to execute | AppLocker Prevented Application or Script from Running | `rules/windows/builtin/applocker/win_applocker_application_was_prevented_from_running.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5008416` | [WINDOWS-APPLOCKER] Package application audited | AppLocker Application Would Have Been Blocked | `rules/windows/builtin/applocker/win_applocker_application_would_have_been_blocked.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5008417` | [WINDOWS-APPLOCKER] Package application disabled | AppLocker Prevented Application or Script from Running | `rules/windows/builtin/applocker/win_applocker_application_was_prevented_from_running.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5008419` | [WINDOWS-APPLOCKER] Package application installation au | AppLocker Application Would Have Been Blocked | `rules/windows/builtin/applocker/win_applocker_application_would_have_been_blocked.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5008420` | [WINDOWS-APPLOCKER] Package application installation di | AppLocker Prevented Application or Script from Running | `rules/windows/builtin/applocker/win_applocker_application_was_prevented_from_running.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5009381` | [WINDOWS-SECURITY] SID History was added to an account | Addition of SID History to Active Directory Object | `rules/windows/builtin/security/win_security_susp_add_sid_history.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5009382` | [WINDOWS-SECURITY] An attempt to add SID History to an | Addition of SID History to Active Directory Object | `rules/windows/builtin/security/win_security_susp_add_sid_history.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010515` | [CISCO-SCA] AWS Logging Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010525` | [CISCO-SCA] Azure Firewall Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010527` | [CISCO-SCA] Azure Key Vaults Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010532` | [CISCO-SCA] Azure Resource Group Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010554` | [CISCO-SCA] High Bandwidth Unidirectional Traffic | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013571` | [WINDOWS-SECURITY] Log on using Non-Standard Workstatio | Failed Logon From Public IP | `rules/windows/builtin/security/account_management/win_security_susp_failed_logon_source.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013825` | [WINDOWS-MISC] NetLogon event with mimikatz string (Zer | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013855` | [WINDOWS-SYSMON] Windows Defender has detected malware | Windows Defender Threat Detected | `rules/windows/builtin/windefend/win_defender_threat.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017396` | [WINDOWS-SECURITY] Hidden Scheduled Task Created - Crit | Remote Schtasks Creation | `unsupported/windows/win_remote_schtask.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `9870004` | [EXPERIMENTAL][WINDOWS-SECURITY] SMB - Anonymous Access | Certificate Exported From Local Certificate Store | `rules/windows/builtin/certificate_services_client_lifecycle_system/win_certificateservicesclient_lifecycle_system_cert_exported.yml` | `SAGAN_REDUNDANT` | 1 |  |

## Behaviourally related, not coverage (tested) (18)

The two fired together on at least one event, log sources are compatible, but neither contains the other (an overlap), or the converted rule is the broader of the two. Related, not interchangeable.

| Sagan SID | Converted rule | SigmaHQ rule | SigmaHQ path | Relation | Events | Shared terms |
| --- | --- | --- | --- | --- | ---: | --- |
| `5003204` | [WINDOWS-MALWARE] Bad Rabbit Malware scheduled task det | Remote Schtasks Creation | `unsupported/windows/win_remote_schtask.yml` | `OVERLAP` | 4 |  |
| `5008753` | [WINDOWS-MALWARE] Bad Rabbit Malware scheduled task det | Remote Schtasks Creation | `unsupported/windows/win_remote_schtask.yml` | `OVERLAP` | 4 |  |
| `5013568` | [WINDOWS-SECURITY] Log on using default linux workstati | Failed Logon From Public IP | `rules/windows/builtin/security/account_management/win_security_susp_failed_logon_source.yml` | `OVERLAP` | 4 |  |
| `5001880` | [WINDOWS-AUTH] User account created | Local User Creation | `rules/windows/builtin/security/win_security_user_creation.yml` | `OVERLAP` | 2 |  |
| `5003397` | [WINDOWS-SECURITY] A new trust was created to a domain | A New Trust Was Created To A Domain | `rules/windows/builtin/security/win_security_susp_add_domain_trust.yml` | `OVERLAP` | 2 |  |
| `5008485` | [WINDOWS-AUTH] Potential Windows User Enumeration - Use | Failed Logon From Public IP | `rules/windows/builtin/security/account_management/win_security_susp_failed_logon_source.yml` | `OVERLAP` | 2 |  |
| `5008486` | [WINDOWS-AUTH] Windows Brute force - User Correct but I | Failed Logon From Public IP | `rules/windows/builtin/security/account_management/win_security_susp_failed_logon_source.yml` | `OVERLAP` | 2 |  |
| `5008487` | [WINDOWS-AUTH] Windows Brute force - User Is Locked Out | Failed Logon From Public IP | `rules/windows/builtin/security/account_management/win_security_susp_failed_logon_source.yml` | `OVERLAP` | 2 |  |
| `5008488` | [WINDOWS-AUTH] Windows Brute force - User Account Disab | Failed Logon From Public IP | `rules/windows/builtin/security/account_management/win_security_susp_failed_logon_source.yml` | `OVERLAP` | 2 |  |
| `5008489` | [WINDOWS-AUTH] Windows Brute force - User Login Attempt | Failed Logon From Public IP | `rules/windows/builtin/security/account_management/win_security_susp_failed_logon_source.yml` | `OVERLAP` | 2 |  |
| `5008538` | [WINDOWS-AUTH] User account created | Local User Creation | `rules/windows/builtin/security/win_security_user_creation.yml` | `OVERLAP` | 2 |  |
| `5009276` | [WINDOWS-MISC] System time has changed | Unauthorized System Time Modification | `rules/windows/builtin/security/win_security_susp_time_modification.yml` | `OVERLAP` | 2 |  |
| `5009393` | [WINDOWS-SECURITY] A new trust was created to a domain | A New Trust Was Created To A Domain | `rules/windows/builtin/security/win_security_susp_add_domain_trust.yml` | `OVERLAP` | 2 |  |
| `5000114` | [SYSLOG] Possible unknown problem on a system | Suspicious Named Error | `rules/linux/builtin/syslog/lnx_syslog_susp_named.yml` | `OVERLAP` | 1 |  |
| `5004782` | [WINDOWS-AUTH] Vulnerable Netlogon/Zerologon connection | Vulnerable Netlogon Secure Channel Connection Allowed | `rules/windows/builtin/system/netlogon/win_system_vul_cve_2020_1472.yml` | `SAGAN_BROADER` | 1 |  |
| `5008570` | [WINDOWS-AUTH] Vulnerable Netlogon/Zerologon connection | Vulnerable Netlogon Secure Channel Connection Allowed | `rules/windows/builtin/system/netlogon/win_system_vul_cve_2020_1472.yml` | `SAGAN_BROADER` | 1 |  |
| `5009299` | [WINDOWS-MISC] Potential Kerberoasting Activity Detecte | Potential AS-REP Roasting via Kerberos TGT Requests | `rules/windows/builtin/security/win_security_kerberos_asrep_roasting.yml` | `SAGAN_BROADER` | 1 |  |
| `5009299` | [WINDOWS-MISC] Potential Kerberoasting Activity Detecte | PetitPotam Suspicious Kerberos TGT Request | `rules/windows/builtin/security/win_security_petitpotam_susp_tgt_request.yml` | `SAGAN_BROADER` | 1 |  |

## Cross-log-source co-firing (tested, not deployable) (516)

The engine confirmed the two fire on one event, but their log sources differ, so in production the SigmaHQ rule would not see that event. Usually a SigmaHQ keyword rule matching a common word in another product's raw text. Not deployable coverage; recorded for completeness.

| Sagan SID | Converted rule | SigmaHQ rule | SigmaHQ path | Relation | Events | Shared terms |
| --- | --- | --- | --- | --- | ---: | --- |
| `` | Aggregate of rules setting Sagan bit create_enabled | Local User Creation | `rules/windows/builtin/security/win_security_user_creation.yml` | `OVERLAP` | 4 |  |
| `5000184` | [FTPD] File deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5002006` | [WINDOWS-MALWARE] Suspicious Tool Event | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `OVERLAP` | 4 |  |
| `5007157` | [WINDOWS-POWERSHELL] Create Volume Shadow Copy | Cisco Stage Data | `rules/network/cisco/aaa/cisco_cli_moving_data.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5007704` | [WINDOWS-MALWARE] Possible ProxyShell V2 Dropped File d | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5007713` | [WINDOWS-MALWARE] Possible ProxyShell V2 WebShell file | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5007713` | [WINDOWS-MALWARE] Possible ProxyShell V2 WebShell file | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 4 |  |
| `5007714` | [WINDOWS-MALWARE] Possible ProxyShell V2 WebShell file | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5007714` | [WINDOWS-MALWARE] Possible ProxyShell V2 WebShell file | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 4 |  |
| `5007715` | [WINDOWS-MALWARE] Possible ProxyShell V2 WebShell file | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 4 |  |
| `5007716` | [WINDOWS-MALWARE] Possible ProxyShell V2 WebShell file | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 4 |  |
| `5007717` | [WINDOWS-MALWARE] Possible ProxyShell V2 WebShell file | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 4 |  |
| `5007718` | [WINDOWS-MALWARE] Possible ProxyShell V2 WebShell file | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 4 |  |
| `5007719` | [WINDOWS-MALWARE] Possible ProxyShell V2 WebShell file | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 4 |  |
| `5007720` | [WINDOWS-MALWARE] Possible ProxyShell V2 WebShell file | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 4 |  |
| `5007721` | [WINDOWS-MALWARE-HUNTING] Possible ProxyShell V2 WebShe | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5007721` | [WINDOWS-MALWARE-HUNTING] Possible ProxyShell V2 WebShe | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 4 |  |
| `5007722` | [WINDOWS-MALWARE-HUNTING] Possible ProxyShell V2 WebShe | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 4 |  |
| `5007723` | [WINDOWS-MALWARE-HUNTING] Possible ProxyShell V2 WebShe | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 4 |  |
| `5007724` | [WINDOWS-MALWARE-HUNTING] Possible ProxyShell V2 WebShe | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 4 |  |
| `5008354` | [WINDOWS-SECURITY] Exfil software rclone detected | Cisco Stage Data | `rules/network/cisco/aaa/cisco_cli_moving_data.yml` | `OVERLAP` | 4 |  |
| `5008684` | [WINDOWS-MALWARE] Suspicious Tool Event | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `OVERLAP` | 4 |  |
| `5009202` | [WINDOWS-MALWARE] Possible ProxyShell V2 Dropped File d | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5009370` | [WINDOWS-POWERSHELL] Create Volume Shadow Copy | Cisco Stage Data | `rules/network/cisco/aaa/cisco_cli_moving_data.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5010485` | [WINDOWS-SECURITY] Comsrvc MiniDump Command | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5010486` | [WINDOWS-SECURITY] Comsrvc MiniDump Command | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5010738` | [WINDOWS-MISC] Command line options used by ExploitRemo | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `OVERLAP` | 4 |  |
| `5010910` | [WINDOWS-SECURITY] Possible Rclone Exfil CommandLine Pa | Cisco Stage Data | `rules/network/cisco/aaa/cisco_cli_moving_data.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5011141` | [CARBONBLACK-APP-CONTROL] Custom Rule deleted (Info) | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5011144` | [CARBONBLACK-APP-CONTROL] Device Rule deleted (Info) | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5011151` | [CARBONBLACK-APP-CONTROL] File ban deleted (Info) | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5011175` | [CARBONBLACK-APP-CONTROL] Publisher ban deleted (Info) | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5011178` | [CARBONBLACK-APP-CONTROL] Registry Rule deleted (Info) | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5013870` | [WINDOWS-SECURITY] LSASS Dump via ProcDump | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5013875` | [WINDOWS-SYSMON] Credential Dumping Tools Service Execu | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `OVERLAP` | 4 |  |
| `5013876` | [WINDOWS-SECURITY] Credential Access - Copy NTDS file | Cisco Stage Data | `rules/network/cisco/aaa/cisco_cli_moving_data.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5013923` | [WINDOWS-SECURITY] Copy from a remote host | Cisco Stage Data | `rules/network/cisco/aaa/cisco_cli_moving_data.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5014182` | [AWS-CLOUDTRAIL] Find Metric Keywords | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 4 |  |
| `5014323` | [WINDOWS-SECURITY] NET USER Command Executed for User M | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 4 |  |
| `5014550` | [WINDOWS-SECURITY] Comsrvc MiniDump Command | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5014551` | [WINDOWS-SECURITY] Comsrvc MiniDump Command | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5014556` | [WINDOWS-SECURITY] Possible Rclone Exfil CommandLine Pa | Cisco Stage Data | `rules/network/cisco/aaa/cisco_cli_moving_data.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5014662` | [BitdefenderGZ] Malicious File Detected (Blocked) | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 4 |  |
| `5014664` | [BitdefenderGZ] Malicious Process Detected (Blocked) | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 4 |  |
| `5014666` | [BitdefenderGZ] Malicious Entity Detected (Blocked) | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 4 |  |
| `5014675` | [BitdefenderGZ] Hyper Detect event (Blocked) | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 4 |  |
| `5015073` | [WINDOWS-SECURITY] Atera Stop/Delete Service | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 4 |  |
| `5015074` | [WINDOWS-SECURITY] Atera Stop/Delete Service | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 4 |  |
| `5015081` | [WINDOWS-SECURITY] Backup Removed via WBAdmin | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5015180` | [WINDOWS-SECURITY] WFP Blocked a Connection from Window | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5015181` | [WINDOWS-SECURITY] WFP Blocked a Connection from Elasti | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5015184` | [WINDOWS-SECURITY] WFP Blocked a Connection from Sentin | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5015186` | [WINDOWS-SECURITY] WFP Blocked a Connection from CyberR | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5015188` | [WINDOWS-SECURITY] WFP Blocked a Connection from Carbon | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5015189` | [WINDOWS-SECURITY] WFP Blocked a Connection from Tanium | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5015190` | [WINDOWS-SECURITY] WFP Blocked a Connection from Palo A | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5015193` | [WINDOWS-SECURITY] WFP Blocked a Connection from ESET I | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5015195` | [WINDOWS-SECURITY] WFP Blocked a Connection from TrendM | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5015500` | [MSAPI-EXCHANGE] Admin Audit Inbox Rule w/ DeleteMessag | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5015512` | [WINDOWS-SECURITY] Batch File Added to Registry | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5015936` | [WINDOWS-SECURITY] Batch File Inserted Into The Registr | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 4 |  |
| `5100143` | Microsoft Domain Controller detected | AppLocker Prevented Application or Script from Running | `rules/windows/builtin/applocker/win_applocker_application_was_prevented_from_running.yml` | `OVERLAP` | 4 |  |
| `5000924` | [FORTINET] Administrator removed logs | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 3 |  |
| `5002929` | [CARBONBLACK-APP-CONTROL] Agent blocked an attempt to d | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 3 |  |
| `5007053` | [WINDOWS-MALWARE] TeslaCrypt ransomware file extension | Cisco Local Accounts | `rules/network/cisco/aaa/cisco_cli_local_accounts.yml` | `SAGAN_REDUNDANT` | 3 |  |
| `5009207` | [WINDOWS-MALWARE] Possible ProxyShell V2 WebShell file | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 3 |  |
| `5009208` | [WINDOWS-MALWARE] Possible ProxyShell V2 WebShell file | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 3 |  |
| `5009215` | [WINDOWS-MALWARE-HUNTING] Possible ProxyShell V2 WebShe | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 3 |  |
| `5013538` | [WINDOWS-MISC] POST to machine2.aspx (CVE-2023-34362) | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 3 |  |
| `5013539` | [WINDOWS-MISC] POST to /moveitisapi/moveitisapi.dll (CV | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 3 |  |
| `5013540` | [WINDOWS-MISC] POST to /guestaccess.aspx (CVE-2023-3436 | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 3 |  |
| `5013541` | [WINDOWS-MISC] POST to /guestaccess.aspx with parameter | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 3 |  |
| `5013542` | [WINDOWS-MISC] File Upload (CVE-2023-34362) | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 3 |  |
| `5013543` | [WINDOWS-MISC] GET /human2.aspx (CVE-2023-34362) | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 3 |  |
| `5014394` | [FORTINET] Administrator removed logs | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 3 |  |
| `5015938` | [WINDOWS-SYSMON] Suspicious Process Executed From Windo | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 3 |  |
| `5017048` | [WINDOWS-MISC] POST to ToolPane.aspx - Critical | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 3 |  |
| `5017049` | [WINDOWS-MISC] Get Request to spinstall0.aspx - Critica | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 3 |  |
| `5017209` | [DYNAMIC] Netscaler Logs Detected | Cisco Local Accounts | `rules/network/cisco/aaa/cisco_cli_local_accounts.yml` | `OVERLAP` | 3 |  |
| `5017360` | [CROWDSTRIKE] Possible Credential Dumping - TGS self re | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 3 |  |
| `5000157` | [APACHE] Attempt to access forbidden directory index | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5013812` | [WINDOWS-SYSMON] Possible ntds file backup | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5013868` | [WINDOWS-MISC] ProcDump64 Installed as a Service | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5014324` | [WINDOWS-POWERSHELL] PowerShell Retrieve Users | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5014325` | [WINDOWS-POWERSHELL] PowerShell Script to find all Comp | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5015075` | [WINDOWS-SECURITY] Atera Registry Key Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5015182` | [WINDOWS-SECURITY] WFP Blocked a Connection from Trelli | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5015183` | [WINDOWS-SECURITY] WFP Blocked a Connection from Qualys | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5015185` | [WINDOWS-SECURITY] WFP Blocked a Connection from Cylanc | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5015187` | [WINDOWS-SECURITY] WFP Blocked a Connection from Carbon | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5015191` | [WINDOWS-SECURITY] WFP Blocked a Connection from Cisco | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5015192` | [WINDOWS-SECURITY] WFP Blocked a Connection from FortiE | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5015194` | [WINDOWS-SECURITY] WFP Blocked a Connection from Harfan | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5017056` | [WINDOWS-MISC] Request to /_vti_pvt/service.cnf | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `OVERLAP` | 2 |  |
| `5017128` | [PRISMA] Prisma Access Web Shell Detection - Medium Sev | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5017129` | [PRISMA] Prisma Access Web Shell Detection - High Sever | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5017130` | [PRISMA] Prisma Access Web Shell Detection - Critical S | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 2 |  |
| `5100164` | Azure Eventhub Active Directory detected | AppLocker Prevented Application or Script from Running | `rules/windows/builtin/applocker/win_applocker_application_was_prevented_from_running.yml` | `OVERLAP` | 2 |  |
| `5000099` | [ATTACK] Stack overflow attempt with SEGV [Solaris] | Buffer Overflow Attempts | `rules/linux/builtin/lnx_buffer_overflows.yml` | `SAGAN_REDUNDANT` | 1 | stack, overflow, code, execute |
| `5005278` | [MS-DEFENDER] Real-Time Protection Is Disabled | Windows Defender Real-time Protection Disabled | `rules/windows/builtin/windefend/win_defender_real_time_protection_disabled.yml` | `EQUIVALENT` | 1 | real-time, protection, disabled |
| `5005276` | [MS-DEFENDER] Real-Time Protection Recovered From A Fai | Windows Defender Real-Time Protection Failure/Restart | `rules/windows/builtin/windefend/win_defender_real_time_protection_errors.yml` | `SAGAN_REDUNDANT` | 1 | real-time, protection |
| `5005275` | [MS-DEFENDER] Real-Time Protection Encountered An Error | Windows Defender Real-Time Protection Failure/Restart | `rules/windows/builtin/windefend/win_defender_real_time_protection_errors.yml` | `SAGAN_REDUNDANT` | 1 | real-time, protection |
| `5005243` | [MS-DEFENDER] Antimalware Platform Restored An Item Fro | Win Defender Restored Quarantine File | `rules/windows/builtin/windefend/win_defender_restored_quarantine_file.yml` | `EQUIVALENT` | 1 | restored, quarantine |
| `5000046` | [SQUID] @CGIDIRScgiwrap attempt | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5000056` | [SYSLOG] Kernel TCP/IP redirect attempt | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5000072` | [OPENSSH] Message without user-IP and context | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5000101` | [BIND] Invalid DNS packet. Possible attack | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5000114` | [SYSLOG] Possible unknown problem on a system | Apache Segmentation Fault | `rules/web/product/apache/web_apache_segfault.yml` | `SAGAN_BROADER` | 1 |  |
| `5000180` | [ASTERISK] Login session failed [invalid user] [0/5] | Cisco Local Accounts | `rules/network/cisco/aaa/cisco_cli_local_accounts.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5000221` | [PUREFTPD] Attempt to Access Invalid Directory Detected | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5000366` | [ATTACK] Heap overflow in the Solaris cachefsd service | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5000376` | [SYSLOG] User or group was deleted from the system | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5000379` | [XINETD] Excessive number connections to a service | Suspicious Log Entries | `rules/linux/builtin/lnx_shell_susp_log_entries.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5000934` | [FORTINET] Access profile deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5000950` | [FORTINET] L2TP/PPTP/PPPoE Max connection reached | Cisco Collect Data | `rules/network/cisco/aaa/cisco_cli_collect_data.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5000979` | [SNORT] Attempted Information Leak | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5000980` | [SNORT] Information Leak | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5000981` | [SNORT] Large Scale Information Leak | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5000993` | [SNORT] An attempted login using a suspicious username | Cisco Local Accounts | `rules/network/cisco/aaa/cisco_cli_local_accounts.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5001010` | [SNORT] Attempt to login by a default username and pass | Cisco Local Accounts | `rules/network/cisco/aaa/cisco_cli_local_accounts.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5001025` | [KISMET] AP spoof with less-secure encryption | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5001222` | [CITRIX] Netscaler - AppFw Field Format violation | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5001554` | [HUAWEI] ATCKDF - Redirect attack | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5001558` | [HUAWEI] ATCKDF - Tear drop attack | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5001612` | [NETSCREEN] Teardrop attack | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5001797` | [WEB-ATTACKS] DirBuster Web App Scan in Progress | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002615` | [SONICWALL] Firewall Rule Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002632` | [SONICWALL] Intrusion Detection - Back Orifice Attack D | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002638` | [SONICWALL] VPN PKI - Bad CRL format | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002663` | [SONICWALL] Network Access - Dropped access from non-de | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002664` | [SONICWALL] Intrusion Detection - Bounce attack dropped | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002665` | [SONICWALL] Intrusion Detection - Spoof attack dropped | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002667` | [SONICWALL] Guest account deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002676` | [SONICWALL] Possible IP spoof dropped | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002679` | [SONICWALL] Intrusion Detection - Land attack dropped | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002687` | [SONICWALL] Intrusion Detection - Net Spy attack droppe | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002688` | [SONICWALL] Intrusion Detection - NetBus attack dropped | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002691` | [SONICWALL] Intrusion Detection - Ping of Death dropped | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002697` | [SONICWALL] Intrusion Detection - Priority attack dropp | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002708` | [SONICWALL] Intrusion Detection - RIPper attack dropped | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002711` | [SONICWALL] Intrusion Detection - Senna Spy attack drop | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002719` | [SONICWALL] Intrusion Detection - Source routed IP pack | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002720` | [SONICWALL] Intrusion Detection - Spank attack dropped | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002722` | [SONICWALL] Intrusion Detection - Striker attack droppe | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002723` | [SONICWALL] Intrusion Detection - Sub Seven attack drop | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002728` | [SONICWALL] Intrusion Detection - TCP Xmas Tree dropped | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002772` | [ScreenOS] Juniper ScreenOS Login for Suspicious Admin | Cisco Local Accounts | `rules/network/cisco/aaa/cisco_cli_local_accounts.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002803` | [WINDOWS-SYSMON] vssadmin.exe Delete Shadows execution. | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002810` | [WINDOWS-SYSMON] Suspicious WMIC call - shadowcopy dele | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002810` | [WINDOWS-SYSMON] Suspicious WMIC call - shadowcopy dele | Cisco Stage Data | `rules/network/cisco/aaa/cisco_cli_moving_data.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5002943` | [ASTERISK] Brute force login session failed [invalid us | Cisco Local Accounts | `rules/network/cisco/aaa/cisco_cli_local_accounts.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5003203` | [WINDOWS-AUTH] SAM Database Unable to Lock Account | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5003346` | [PASSWORDSTATE] Password Reset Task Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5003350` | [PASSWORDSTATE] Discovery Job Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5003351` | [PASSWORDSTATE] Document Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5003355` | [PASSWORDSTATE] Privileged Account Credentials Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5003363` | [PASSWORDSTATE] Security Group Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5003368` | [PASSWORDSTATE] Password Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5003370` | [PASSWORDSTATE] Password List Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5004308` | [ZINGBOX] Manufacturer default username and password in | Cisco Local Accounts | `rules/network/cisco/aaa/cisco_cli_local_accounts.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5004311` | [ZINGBOX] Unencrypted sensitive information in HTTP req | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5004314` | [ZINGBOX] Username same as password in FTP login | Cisco Local Accounts | `rules/network/cisco/aaa/cisco_cli_local_accounts.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005234` | [MS-DEFENDER] Antimalware Scan Started | CVE-2023-40477 Potential Exploitation - WinRAR Applicat | `rules-emerging-threats/2023/Exploits/CVE-2023-40477/win_application_exploit_cve_2023_40477_winrar_crash.yml` | `SAGAN_BROADER` | 1 |  |
| `5005234` | [MS-DEFENDER] Antimalware Scan Started | CVE-2024-49113 Exploitation Attempt - LDAP Nightmare | `rules-emerging-threats/2024/Exploits/CVE-2024-49113/win_application_error_exploit_cve_2024_49113_ldap_nightmare.yml` | `SAGAN_BROADER` | 1 |  |
| `5005234` | [MS-DEFENDER] Antimalware Scan Started | LSASS Crash Via Netlogon Stack Buffer Overflow - CVE-20 | `rules-emerging-threats/2026/Exploits/CVE-2026-41089/win_application_error_exploit_cve_2026_41089_lsass_netlogon_crash.yml` | `SAGAN_BROADER` | 1 |  |
| `5005234` | [MS-DEFENDER] Antimalware Scan Started | LSASS Process Crashed - Application | `rules/windows/builtin/application/application_error/win_application_error_lsass_crash.yml` | `SAGAN_BROADER` | 1 |  |
| `5005234` | [MS-DEFENDER] Antimalware Scan Started | Microsoft Malware Protection Engine Crash | `rules/windows/builtin/application/application_error/win_application_error_msmpeng_crash.yml` | `SAGAN_BROADER` | 1 |  |
| `5005235` | [MS-DEFENDER] Antimalware Scan Completed | Microsoft Malware Protection Engine Crash - WER | `rules/windows/builtin/application/windows_error_reporting/win_application_msmpeng_crash_wer.yml` | `SAGAN_BROADER` | 1 |  |
| `5005235` | [MS-DEFENDER] Antimalware Scan Completed | Crash Dump Created By Operating System | `rules/windows/builtin/system/microsoft_windows_wer_systemerrorreporting/win_system_crash_dump_created.yml` | `SAGAN_BROADER` | 1 |  |
| `5005240` | [MS-DEFENDER] Antimalware Engine Found Potential Malwar | Windows Defender Threat Detected | `rules/windows/builtin/windefend/win_defender_threat.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005241` | [MS-DEFENDER] Action Performed Against Potential Malwar | Certificate Exported From Local Certificate Store | `rules/windows/builtin/certificate_services_client_lifecycle_system/win_certificateservicesclient_lifecycle_system_cert_exported.yml` | `EQUIVALENT` | 1 |  |
| `5005247` | [MS-DEFENDER] Antimalware Platform Deleted History Of M | Windows Defender Malware Detection History Deletion | `rules/windows/builtin/windefend/win_defender_history_delete.yml` | `EQUIVALENT` | 1 |  |
| `5005249` | [MS-DEFENDER] Antimalware Platform Detected Suspicious | Windows Defender Threat Detected | `rules/windows/builtin/windefend/win_defender_threat.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005250` | [MS-DEFENDER] Antimalware Platform Detected Potential M | Windows Defender AMSI Trigger Detected | `rules/windows/builtin/windefend/win_defender_malware_detected_amsi_source.yml` | `SAGAN_BROADER` | 1 |  |
| `5005250` | [MS-DEFENDER] Antimalware Platform Detected Potential M | Windows Defender Threat Detected | `rules/windows/builtin/windefend/win_defender_threat.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005251` | [MS-DEFENDER] Action Performed Against Potential Malwar | Windows Defender Threat Detected | `rules/windows/builtin/windefend/win_defender_threat.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005252` | [MS-DEFENDER] Critical Error When Trying To Take Action | RedSun - TieringEngineService.exe Detected as EICAR Tes | `rules-emerging-threats/2026/Exploits/RedSun/win_defender_exploit_redsun_tiering_engine_detected_as_eicar.yml` | `SAGAN_BROADER` | 1 |  |
| `5005258` | [MS-DEFENDER] Antimalware Engine Updated Successfully | Windows Firewall Settings Have Been Changed | `rules/windows/builtin/firewall_as/win_firewall_as_setting_change.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005259` | [MS-DEFENDER] Antimalware Engine Update Failed | USB Device Plugged | `rules/windows/builtin/driverframeworks/win_usb_device_plugged.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005259` | [MS-DEFENDER] Antimalware Engine Update Failed | Windows Firewall Settings Have Been Changed | `rules/windows/builtin/firewall_as/win_firewall_as_setting_change.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005260` | [MS-DEFENDER] Problem Loading Antimalware Definitions | Uncommon New Firewall Rule Added In Windows Firewall Ex | `rules/windows/builtin/firewall_as/win_firewall_as_add_rule.yml` | `OVERLAP` | 1 |  |
| `5005260` | [MS-DEFENDER] Problem Loading Antimalware Definitions | New Firewall Rule Added In Windows Firewall Exception L | `rules/windows/builtin/firewall_as/win_firewall_as_add_rule_susp_folder.yml` | `SAGAN_BROADER` | 1 |  |
| `5005260` | [MS-DEFENDER] Problem Loading Antimalware Definitions | New Firewall Rule Added In Windows Firewall Exception L | `rules/windows/builtin/firewall_as/win_firewall_as_add_rule_wmiprvse.yml` | `OVERLAP` | 1 |  |
| `5005261` | [MS-DEFENDER] Out of Date Antimalware Platform | Firewall Rule Modified In The Windows Firewall Exceptio | `rules-threat-hunting/windows/builtin/firewall_as/win_firewall_as_change_rule.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005262` | [MS-DEFENDER] Platform Update Failed | A Rule Has Been Deleted From The Windows Firewall Excep | `rules/windows/builtin/firewall_as/win_firewall_as_delete_rule.yml` | `OVERLAP` | 1 |  |
| `5005278` | [MS-DEFENDER] Real-Time Protection Is Disabled | Windows Defender Threat Detection Disabled | `deprecated/windows/win_defender_disabled.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005280` | [MS-DEFENDER] Antimalware Platform Configuration Change | Windows Defender Exclusions Added | `rules/windows/builtin/windefend/win_defender_config_change_exclusion_added.yml` | `SAGAN_BROADER` | 1 |  |
| `5005280` | [MS-DEFENDER] Antimalware Platform Configuration Change | Windows Defender Exploit Guard Tamper | `rules/windows/builtin/windefend/win_defender_config_change_exploit_guard_tamper.yml` | `SAGAN_BROADER` | 1 |  |
| `5005280` | [MS-DEFENDER] Antimalware Platform Configuration Change | Windows Defender Submit Sample Feature Disabled | `rules/windows/builtin/windefend/win_defender_config_change_sample_submission_consent.yml` | `SAGAN_BROADER` | 1 |  |
| `5005280` | [MS-DEFENDER] Antimalware Platform Configuration Change | Windows Defender Configuration Changes | `rules/windows/builtin/windefend/win_defender_suspicious_features_tampering.yml` | `SAGAN_BROADER` | 1 |  |
| `5005284` | [MS-DEFENDER] Scanning For Viruses is Enabled | Windows Defender Threat Detection Disabled | `deprecated/windows/win_defender_disabled.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005284` | [MS-DEFENDER] Scanning For Viruses is Enabled | Windows Defender Virus Scanning Feature Disabled | `rules/windows/builtin/windefend/win_defender_virus_scan_disabled.yml` | `EQUIVALENT` | 1 |  |
| `5005287` | [MS-DEFENDER] Antimalware Platform Is Expired | Windows Defender Threat Detection Disabled | `deprecated/windows/win_defender_disabled.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005287` | [MS-DEFENDER] Antimalware Platform Is Expired | Windows Defender Grace Period Expired | `rules/windows/builtin/windefend/win_defender_antimalware_platform_expired.yml` | `EQUIVALENT` | 1 |  |
| `5005309` | [CLOUDTRAIL] IAM cloudtrail event detected - (DeleteAcc | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005310` | [CLOUDTRAIL] IAM cloudtrail event detected - (DeleteAcc | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005311` | [CLOUDTRAIL] IAM cloudtrail event detected - (DeleteAcc | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005312` | [CLOUDTRAIL] IAM cloudtrail event detected - (DeleteGro | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005313` | [CLOUDTRAIL] IAM cloudtrail event detected - (DeleteGro | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005314` | [CLOUDTRAIL] IAM cloudtrail event detected - (DeleteIns | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005315` | [CLOUDTRAIL] IAM cloudtrail event detected - (DeleteLog | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005316` | [CLOUDTRAIL] IAM cloudtrail event detected - (DeleteOpe | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005317` | [CLOUDTRAIL] IAM cloudtrail event detected - (DeletePol | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005318` | [CLOUDTRAIL] IAM cloudtrail event detected - (DeletePol | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005319` | [CLOUDTRAIL] IAM cloudtrail event detected - (DeleteRol | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005320` | [CLOUDTRAIL] IAM cloudtrail event detected - (DeleteRol | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005321` | [CLOUDTRAIL] IAM cloudtrail event detected - (DeleteSAM | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005322` | [CLOUDTRAIL] IAM cloudtrail event detected - (DeleteSer | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005323` | [CLOUDTRAIL] IAM cloudtrail event detected - (DeleteSig | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005324` | [CLOUDTRAIL] IAM cloudtrail event detected - (DeleteSSH | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005325` | [CLOUDTRAIL] IAM cloudtrail event detected - (DeleteUse | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005326` | [CLOUDTRAIL] IAM cloudtrail event detected - (DeleteUse | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005327` | [CLOUDTRAIL] IAM cloudtrail event detected - (DeleteVir | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005354` | [CLOUDTRAIL] AWS Config cloudtrail event detected - (De | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005355` | [CLOUDTRAIL] AWS Config cloudtrail event detected - (De | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005356` | [CLOUDTRAIL] AWS Config cloudtrail event detected - (De | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005357` | [CLOUDTRAIL] AWS Config cloudtrail event detected - (De | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005394` | [CLOUDTRAIL] EC2 cloudtrail event detected - (DeleteCus | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005395` | [CLOUDTRAIL] EC2 cloudtrail event detected - (DeleteDhc | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005396` | [CLOUDTRAIL] EC2 cloudtrail event detected - (DeleteEgr | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005397` | [CLOUDTRAIL] EC2 cloudtrail event detected - (DeleteInt | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005398` | [CLOUDTRAIL] EC2 cloudtrail event detected - (DeleteKey | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005399` | [CLOUDTRAIL] EC2 cloudtrail event detected - (DeleteNat | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005400` | [CLOUDTRAIL] EC2 cloudtrail event detected - (DeleteNet | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005401` | [CLOUDTRAIL] EC2 cloudtrail event detected - (DeleteNet | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005402` | [CLOUDTRAIL] EC2 cloudtrail event detected - (DeleteNet | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005403` | [CLOUDTRAIL] EC2 cloudtrail event detected - (DeleteRou | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005404` | [CLOUDTRAIL] EC2 cloudtrail event detected - (DeleteRou | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005405` | [CLOUDTRAIL] EC2 cloudtrail event detected - (DeleteSec | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005406` | [CLOUDTRAIL] EC2 cloudtrail event detected - (DeleteVpc | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005407` | [CLOUDTRAIL] EC2 cloudtrail event detected - (DeleteVpc | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005408` | [CLOUDTRAIL] EC2 cloudtrail event detected - (DeleteVpn | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005409` | [CLOUDTRAIL] EC2 cloudtrail event detected - (DeleteVpn | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005410` | [CLOUDTRAIL] EC2 cloudtrail event detected - (DeleteVpn | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005432` | [CLOUDTRAIL] AutoScaling cloudtrail event detected - (P | Cisco Stage Data | `rules/network/cisco/aaa/cisco_cli_moving_data.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005433` | [CLOUDTRAIL] AutoScaling cloudtrail event detected - (D | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005435` | [CLOUDTRAIL] CloudFormation cloudtrail event detected - | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005436` | [CLOUDTRAIL] CloudFormation cloudtrail event detected - | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005437` | [CLOUDTRAIL] CloudFormation cloudtrail event detected - | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005438` | [CLOUDTRAIL] CloudFormation cloudtrail event detected - | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005439` | [CLOUDTRAIL] Certificate Manager cloudtrail event detec | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005443` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005444` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005445` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005446` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005447` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005448` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005449` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005450` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005451` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005452` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005453` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005454` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005455` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005456` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005457` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005457` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005458` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005458` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005459` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005459` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005460` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005460` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005461` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005462` | [CLOUDTRAIL] Direct Connect cloudtrail event detected - | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005465` | [CLOUDTRAIL] EFS cloudtrail event detected - (DeleteFil | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005466` | [CLOUDTRAIL] EFS cloudtrail event detected - (DeleteMou | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005474` | [CLOUDTRAIL] Elastic Beanstalk cloudtrail event detecte | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005475` | [CLOUDTRAIL] Elastic Beanstalk cloudtrail event detecte | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005476` | [CLOUDTRAIL] Elastic Beanstalk cloudtrail event detecte | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005477` | [CLOUDTRAIL] Elastic Beanstalk cloudtrail event detecte | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005488` | [CLOUDTRAIL] ElastiCache cloudtrail event detected - (D | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005496` | [CLOUDTRAIL] ELB cloudtrail event detected - (DeleteLis | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005497` | [CLOUDTRAIL] ELB cloudtrail event detected - (DeleteLoa | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005498` | [CLOUDTRAIL] ELB cloudtrail event detected - (DeleteLoa | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005499` | [CLOUDTRAIL] ELB cloudtrail event detected - (DeleteRul | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005500` | [CLOUDTRAIL] ELB cloudtrail event detected - (DeleteTar | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005514` | [CLOUDTRAIL] Redshift cloudtrail event detected - (Dele | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005527` | [CLOUDTRAIL] RDS cloudtrail event detected - (DeleteDBC | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005528` | [CLOUDTRAIL] RDS cloudtrail event detected - (DeleteDBC | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005529` | [CLOUDTRAIL] RDS cloudtrail event detected - (DeleteDBC | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005530` | [CLOUDTRAIL] RDS cloudtrail event detected - (DeleteDBI | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005531` | [CLOUDTRAIL] RDS cloudtrail event detected - (DeleteDBP | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005532` | [CLOUDTRAIL] RDS cloudtrail event detected - (DeleteDBS | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005533` | [CLOUDTRAIL] RDS cloudtrail event detected - (DeleteDBS | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005534` | [CLOUDTRAIL] RDS cloudtrail event detected - (DeleteDBS | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005535` | [CLOUDTRAIL] RDS cloudtrail event detected - (DeleteOpt | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005554` | [CLOUDTRAIL] Route 53 cloudtrail event detected - (Dele | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005556` | [CLOUDTRAIL] S3 cloudtrail event detected - (DeleteBuck | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005557` | [CLOUDTRAIL] S3 cloudtrail event detected - (DeleteBuck | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005558` | [CLOUDTRAIL] S3 cloudtrail event detected - (DeleteBuck | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005559` | [CLOUDTRAIL] S3 cloudtrail event detected - (DeleteBuck | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005560` | [CLOUDTRAIL] S3 cloudtrail event detected - (DeleteBuck | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005561` | [CLOUDTRAIL] S3 cloudtrail event detected - (DeleteBuck | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005584` | [CLOUDTRAIL] WAF cloudtrail event detected - (DeleteByt | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005585` | [CLOUDTRAIL] WAF cloudtrail event detected - (DeleteGeo | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005586` | [CLOUDTRAIL] WAF cloudtrail event detected - (DeleteIPS | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005587` | [CLOUDTRAIL] WAF cloudtrail event detected - (DeleteRat | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005588` | [CLOUDTRAIL] WAF cloudtrail event detected - (DeleteReg | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005589` | [CLOUDTRAIL] WAF cloudtrail event detected - (DeleteReg | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005590` | [CLOUDTRAIL] WAF cloudtrail event detected - (DeleteRul | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005591` | [CLOUDTRAIL] WAF cloudtrail event detected - (DeleteSiz | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005592` | [CLOUDTRAIL] WAF cloudtrail event detected - (DeleteSql | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005593` | [CLOUDTRAIL] WAF cloudtrail event detected - (DeleteWeb | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005594` | [CLOUDTRAIL] WAF cloudtrail event detected - (DeleteXss | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005672` | [LINUX-AUDITD] mkdir starting with a space | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005673` | [LINUX-AUDITD] mkdir starting with a period | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005700` | [MICROSOFT-ATP] Ransomware alert | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005711` | [CHECKPOINT] Action Replace Malicious Code | Modifying Crontab | `rules/linux/builtin/cron/lnx_cron_crontab_file_modification.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005767` | [DYNAMIC] Mimecast logs detected via message | Cisco Stage Data | `rules/network/cisco/aaa/cisco_cli_moving_data.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005900` | [DARKTRACE] A device performed an unusual connection to | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005906` | [DARKTRACE] A device has deleted an anomalous volume of | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005937` | [CONFLUENT] Kafka Broker ACL Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005938` | [CONFLUENT] Kafka Cluster Link Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005939` | [CONFLUENT] Kafka Group Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005940` | [CONFLUENT] Kafka Record Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005941` | [CONFLUENT] Kafka Topic Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5005945` | [CONFLUENT] Kafka Committed Offset for Partition in Con | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5006006` | [GCP] Firewall Policy Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5006008` | [GCP] Instance Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5006009` | [GCP] Instance - Access Configuration Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5007161` | [NINJARMM] Bitdefender - Threat Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5007204` | [MCAS] Mass Delete | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5007349` | [SOPHOS] Remnants deleted of Potentially Unwanted App | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5007351` | [SOPHOS] Threat remnants deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5007826` | [WINDOWS-SYSMON] Possible DLL Hijacking of directmanipu | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5008345` | [WINDOWS-SYSMON] CMD executed from spool directory | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5008380` | [WINDOWS-CLIPBOARD] copy from share drive to local C: c | Cisco Stage Data | `rules/network/cisco/aaa/cisco_cli_moving_data.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5008550` | [WINDOWS-AUTH] Possible Windows Broken Domain Trust [25 | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5008554` | [WINDOWS-AUTH] SAM Database Unable to Lock Account | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5008651` | [WINDOWS-CLIPBOARD] copy from share drive to local C: c | Cisco Stage Data | `rules/network/cisco/aaa/cisco_cli_moving_data.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5009781` | [WINDOWS-SYSMON] vssadmin.exe Delete Shadows execution. | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5009782` | [WINDOWS-SYSMON] Suspicious WMIC call - shadowcopy dele | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5009782` | [WINDOWS-SYSMON] Suspicious WMIC call - shadowcopy dele | Cisco Stage Data | `rules/network/cisco/aaa/cisco_cli_moving_data.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5009891` | [WINDOWS-SYSMON] Possible DLL Hijacking of directmanipu | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010217` | [WINDOWS-SYSMON] CMD executed from spool directory | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010325` | [DYNAMIC] MSAPI-AzureAD logs detected via program | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010387` | [AWS-GUARDDUTY] GuardDuty event detected (Impact:S3/Ano | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010430` | [AWS-GUARDDUTY] GuardDuty event detected (Trojan:EC2/Dr | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010431` | [AWS-GUARDDUTY] GuardDuty event detected (Trojan:EC2/Dr | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010503` | [CISCO-SCA] Attendance Drop | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010567` | [CISCO-SCA] Meterpreter Command and Control Success | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010742` | [CyberArk] Delete Directory Map | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010742` | [CyberArk] Delete Directory Map | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010773` | [CyberArk] Delete Location | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010787` | [CyberArk] Add Safe (More Secured Than Station) | Cisco Collect Data | `rules/network/cisco/aaa/cisco_cli_collect_data.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010791` | [CyberArk] Update Safe (More Secured Than Station) | Cisco Collect Data | `rules/network/cisco/aaa/cisco_cli_collect_data.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010795` | [CyberArk] Delete Safe | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010796` | [CyberArk] Delete Safe | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010798` | [CyberArk] Delete Safe | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010801` | [CyberArk] Delete Folder | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010803` | [CyberArk] Get License Information | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010806` | [CyberArk] Undelete File | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010810` | [CyberArk] Delete Safe (Has Unexpired Files) | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010816` | [CyberArk] Delete User | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010817` | [CyberArk] Delete Your User | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010821` | [CyberArk] Delete Folder (Has Unexpired Files) | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010825` | [CyberArk] Delete Folder (Has Locked Files) | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010830` | [CyberArk] Add Directory Map LDAP Branch | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010831` | [CyberArk] Update Directory Map LDAP Branch | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010832` | [CyberArk] Delete Directory Map LDAP Branch | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010832` | [CyberArk] Delete Directory Map LDAP Branch | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010834` | [CyberArk] List Directory Map LDAP Branches | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010840` | [CyberArk] Update Directory Map | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010841` | [CyberArk] Add Directory Map | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010844` | [CyberArk] Delete Group Member | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010846` | [CyberArk] Delete Group | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010848` | [CyberArk] Delete Folder | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010849` | [CyberArk] Delete Rule | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010861` | [CyberArk] Delete Privileged Command failed | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010864` | [CyberArk] Delete Privileged Command | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010890` | [CyberArk] Delete SSH Public Keys Failed | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010899` | [TENABLE] An administrator deleted a user account | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5010945` | [GITHUB] Item Deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5011973` | [AWS-COGNITO] AWS Cognito event detected (AdminDeleteUs | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5011974` | [AWS-COGNITO] AWS Cognito event detected (AdminDeleteUs | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5012008` | [AWS-COGNITO] AWS Cognito event detected (DeleteGroup) | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5012009` | [AWS-COGNITO] AWS Cognito event detected (DeleteIdentit | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5012010` | [AWS-COGNITO] AWS Cognito event detected (DeleteResourc | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5012011` | [AWS-COGNITO] AWS Cognito event detected (DeleteUser) | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5012012` | [AWS-COGNITO] AWS Cognito event detected (DeleteUserAtt | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5012013` | [AWS-COGNITO] AWS Cognito event detected (DeleteUserPoo | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5012014` | [AWS-COGNITO] AWS Cognito event detected (DeleteUserPoo | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5012015` | [AWS-COGNITO] AWS Cognito event detected (DeleteUserPoo | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5012139` | [MSEXCHANGE-MANAGEMENT] antispam-antimalware Cmdlet Del | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5012742` | [MSEXCHANGE-MANAGEMENT] mailboxes Cmdlet Undo-SoftDelet | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5012957` | [MSEXCHANGE-MANAGEMENT] policy-and-compliance Cmdlet Ge | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5012958` | [MSEXCHANGE-MANAGEMENT] policy-and-compliance Cmdlet Ge | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5012959` | [MSEXCHANGE-MANAGEMENT] policy-and-compliance Cmdlet Ge | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5012960` | [MSEXCHANGE-MANAGEMENT] policy-and-compliance Cmdlet Ge | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5012961` | [MSEXCHANGE-MANAGEMENT] policy-and-compliance Cmdlet Ge | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5012962` | [MSEXCHANGE-MANAGEMENT] policy-and-compliance Cmdlet Ge | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5012982` | [MSEXCHANGE-MANAGEMENT] policy-and-compliance Cmdlet Ne | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5012996` | [MSEXCHANGE-MANAGEMENT] policy-and-compliance Cmdlet Re | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013010` | [MSEXCHANGE-MANAGEMENT] policy-and-compliance Cmdlet Se | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013021` | [MSEXCHANGE-MANAGEMENT] policy-and-compliance Cmdlet St | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013022` | [MSEXCHANGE-MANAGEMENT] policy-and-compliance Cmdlet St | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013083` | [MSEXCHANGE-MANAGEMENT] policy-and-compliance-dlp Cmdle | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013084` | [MSEXCHANGE-MANAGEMENT] policy-and-compliance-dlp Cmdle | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013098` | [MSEXCHANGE-MANAGEMENT] policy-and-compliance-dlp Cmdle | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013099` | [MSEXCHANGE-MANAGEMENT] policy-and-compliance-dlp Cmdle | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013110` | [MSEXCHANGE-MANAGEMENT] policy-and-compliance-dlp Cmdle | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013111` | [MSEXCHANGE-MANAGEMENT] policy-and-compliance-dlp Cmdle | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013120` | [MSEXCHANGE-MANAGEMENT] policy-and-compliance-dlp Cmdle | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013121` | [MSEXCHANGE-MANAGEMENT] policy-and-compliance-dlp Cmdle | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013247` | [MSEXCHANGE-MANAGEMENT] powershell-v2-module Cmdlet Get | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013558` | [WINDOWS-POWERSHELL] ShadowCopy Deleted | Cisco Stage Data | `rules/network/cisco/aaa/cisco_cli_moving_data.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013616` | [AIRTABLES] deleteUser event detected | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013622` | [AIRTABLES] deleteServiceAccount event detected | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013708` | MSAPI AzureAD device detected | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013730` | [DYNAMIC] RansomCare logs detected via program. | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013731` | [RANSOMCARE][CRITICAL & CALL] Critical Alert | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013733` | [NETWRIX] Active Directory Security Group Added | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013744` | [NETWRIX] Active Directory User Added | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013952` | [DUO] admin deleted an object | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5013969` | [DUO] bypass code deleted for user | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5014363` | [FORTINET] Malicious File Detected - Direction Outgoing | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5014404` | [FORTINET] Access profile deleted | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5014421` | [FORTINET] L2TP/PPTP/PPPoE Max connection reached | Cisco Collect Data | `rules/network/cisco/aaa/cisco_cli_collect_data.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5014645` | [MSAPI-AZUREAD] Security Operator role assigned to Memb | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5014646` | [MSAPI-AZUREAD] CRITICAL - Security Administrator role | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5014647` | [MSAPI-AZUREAD] CRITICAL - User Administrator role assi | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5014656` | [MSAPI-AZUREAD] Partner Tier2 Support role assigned to | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5014657` | [MSAPI-AZUREAD] Privileged Role Administrator role assi | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5014734` | [BOMGAR] Beyond Trust change_username | Cisco Local Accounts | `rules/network/cisco/aaa/cisco_cli_local_accounts.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015211` | [BOX] Files Copied in Excess (100/5Mins) | Cisco Stage Data | `rules/network/cisco/aaa/cisco_cli_moving_data.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015212` | [BOX] Files Deleted in Excess (50/5Mins) | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015234` | [BOX] Copying items blocked due to information barrier | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015234` | [BOX] Copying items blocked due to information barrier | Cisco Stage Data | `rules/network/cisco/aaa/cisco_cli_moving_data.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015235` | [BOX] Transferring items blocked due to information bar | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015258` | [NETSKOPE] Deleted Netskope SSO admin Event Detected | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015587` | [Barracuda] Incident Response Deleted Email Detected | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015632` | [Barracuda] WAF Directory Traversal Attack in JSON Data | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015651` | [Barracuda] WAF Directory Traversal in Header | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015659` | [Barracuda] WAF Directory Traversal Beyond Root | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015679` | [Barracuda] WAF Directory Traversal in Parameter | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015810` | [Barracuda] WAF Directory Traversal in GraphQL Payload | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015821` | [Barracuda] WAF Redirect ACL matched | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015837` | [MICROSOFT_DEFENDER_ENDPOINT] Ransomware Informational | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015837` | [MICROSOFT_DEFENDER_ENDPOINT] Ransomware Informational | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015838` | [MICROSOFT_DEFENDER_ENDPOINT] Ransomware Low Alert Dete | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015839` | [MICROSOFT_DEFENDER_ENDPOINT] Ransomware Medium Alert D | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015840` | [MICROSOFT_DEFENDER_ENDPOINT] Ransomware High Alert Det | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015841` | [MICROSOFT_DEFENDER_ENDPOINT] Malware Informational Ale | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015845` | [MICROSOFT_DEFENDER_ENDPOINT] Phishing Informational Al | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015849` | [MICROSOFT_DEFENDER_ENDPOINT] Potentially Unwanted Soft | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015853` | [MICROSOFT_DEFENDER_ENDPOINT] SuspiciousActivity Inform | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015857` | [MICROSOFT_DEFENDER_ENDPOINT] Exploit Informational Ale | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015865` | [MICROSOFT_DEFENDER_ENDPOINT] InitialAccess Information | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015869` | [MICROSOFT_DEFENDER_ENDPOINT] Execution Informational A | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015873` | [MICROSOFT_DEFENDER_ENDPOINT] Persistence Informational | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015877` | [MICROSOFT_DEFENDER_ENDPOINT] PrivilegeEscalation Infor | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015881` | [MICROSOFT_DEFENDER_ENDPOINT] DefenseEvasion Informatio | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015885` | [MICROSOFT_DEFENDER_ENDPOINT] CredentialAccess Informat | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015889` | [MICROSOFT_DEFENDER_ENDPOINT] Discovery Informational A | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015893` | [MICROSOFT_DEFENDER_ENDPOINT] LateralMovement Informati | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015897` | [MICROSOFT_DEFENDER_ENDPOINT] Collection Informational | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015901` | [MICROSOFT_DEFENDER_ENDPOINT] Exfiltration Informationa | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015905` | [MICROSOFT_DEFENDER_ENDPOINT] CommandAndControl Informa | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015909` | [MICROSOFT_DEFENDER_ENDPOINT] Impact Informational Aler | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015913` | [MICROSOFT_DEFENDER_ENDPOINT] PreAttack Informational A | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015917` | [MICROSOFT_DEFENDER_ENDPOINT] Unknown/Other Information | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5015939` | [WINDOWS-SYSMON] Program Executed From Temp Directory v | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5016590` | [CROWDSTRIKE] A process associated with ransomware was | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5016596` | [CROWDSTRIKE] A suspicious process, associated with pot | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5016616` | [CROWDSTRIKE] A process attempted to delete a Volume Sh | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5016619` | [CROWDSTRIKE] A MD5 hash matched a Custom Intelligence | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5016640` | [CROWDSTRIKE] A SHA256 hash matched a Custom Intelligen | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5016641` | [CROWDSTRIKE] An IP Address matched a Custom Intelligen | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5016714` | [ORACLE] OCI Audit - DeleteApp Event Detected | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5016718` | [ORACLE] OCI Audit - DeleteCredential Event Detected | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5016719` | [ORACLE] OCI Audit - DeleteDevice Event Detected | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5016731` | [ORACLE] OCI Audit - DeleteUser Event Detected | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017009` | [MICROSOFT_INTUNE] Delete MangedDevice Operation Log De | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017068` | [AWS] EC2 Delete Disk Snapshot | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017154` | [AWS] RDS Copy DB Snapshot | Cisco Stage Data | `rules/network/cisco/aaa/cisco_cli_moving_data.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017157` | [AWS] RDS Delete Relational DB Snapshot | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017203` | [DYNAMIC] Cisco-IOS Logs Detected | Exploitation Indicators Of CVE-2023-20198 | `rules-emerging-threats/2023/Exploits/CVE-2023-20198/cisco_syslog_cve_2023_20198_ios_xe_web_ui.yml` | `OVERLAP` | 1 |  |
| `5017217` | [PURE_STORAGE] Multiple Pending File Deletions From A S | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017305` | [FORTINET] Malicious File Detected - Direction Outgoing | Cisco Discovery | `rules/network/cisco/aaa/cisco_cli_discovery.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017408` | [SOPHOS_FIREWALL] Firewall ATP Module - Malware Detecte | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017410` | [SOPHOS_FIREWALL] DNS ATP Module - Malware Detected And | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017412` | [SOPHOS_FIREWALL] IPS ATP Module - Malware Detected And | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017414` | [SOPHOS_FIREWALL] Web ATP Module - Malware Detected And | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017570` | [CROWDSTRIKE] Suspicious Execution - Blocked: Mimikatz | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017571` | [CROWDSTRIKE] Suspicious Execution - Killed: Mimikatz p | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017572` | [CROWDSTRIKE] Suspicious Execution Detected - Mimikatz | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017576` | [CROWDSTRIKE] Suspicious Execution - Blocked: Procdump | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017577` | [CROWDSTRIKE] Suspicious Execution - Killed: Procdump l | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017578` | [CROWDSTRIKE] Suspicious Execution Detected - Procdump | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017579` | [CROWDSTRIKE] comsvcs.dll MiniDump usage initiated - Bl | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017580` | [CROWDSTRIKE] comsvcs.dll MiniDump usage initiated - Ki | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017581` | [CROWDSTRIKE] Suspicious Execution Detected - comsvcs.d | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017582` | [CROWDSTRIKE] LSASS-targeting execution artifacts obser | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017583` | [CROWDSTRIKE] LSASS-targeting execution artifacts obser | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017584` | [CROWDSTRIKE] Suspicious Execution Detected - LSASS-tar | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017585` | [CROWDSTRIKE] Invoke-Mimikatz executed via PowerShell - | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017586` | [CROWDSTRIKE] Invoke-Mimikatz executed via PowerShell - | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017587` | [CROWDSTRIKE] Suspicious Execution Detected - Invoke-Mi | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017591` | [CROWDSTRIKE] LaZagne credential harvesting binary exec | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017592` | [CROWDSTRIKE] LaZagne credential harvesting binary exec | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017593` | [CROWDSTRIKE] Suspicious Execution Detected - LaZagne c | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017615` | [CROWDSTRIKE] Suspicious Impact: Ransomware file operat | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017754` | [CROWDSTRIKE] Possible Impact Detected - A Process Dele | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017755` | [CROWDSTRIKE] Possible Impact Blocked - A Process Delet | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017756` | [CROWDSTRIKE] Possible Impact Killed - A Process Delete | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017779` | [CROWDSTRIKE] Machine Learning Analysis Blocked - Mimik | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017780` | [CROWDSTRIKE] Machine Learning Analysis Blocked - Mimik | Relevant Anti-Virus Signature Keywords In Application L | `rules/windows/builtin/application/Other/win_av_relevant_match.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017829` | [SOPHOS_FIREWALL] Firewall ATP Module - Malware Detecte | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017831` | [SOPHOS_FIREWALL] DNS ATP Module - Malware Detected And | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017833` | [SOPHOS_FIREWALL] IPS ATP Module - Malware Detected And | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5017835` | [SOPHOS_FIREWALL] Web ATP Module - Malware Detected And | Suspicious SQL Query | `rules/category/database/db_anomalous_query.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `5100136` | Cisco device detected | Cisco Local Accounts | `rules/network/cisco/aaa/cisco_cli_local_accounts.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `991014` | [AWS] EC2 Copy Snapshot | Cisco Stage Data | `rules/network/cisco/aaa/cisco_cli_moving_data.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `991017` | [AWS] EC2 Delete Snapshot | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |
| `991023` | [AWS] RDS Delete DB Snapshot | Cisco File Deletion | `rules/network/cisco/aaa/cisco_cli_file_deletion.yml` | `SAGAN_REDUNDANT` | 1 |  |

## Conceptual candidate, strong lexical match (review) (289)

No behavioural co-firing was found, but the two rules share distinctive search terms strongly enough to suggest they detect the same thing. A lead for human review, not a tested fact.

| Sagan SID | Converted rule | SigmaHQ rule | SigmaHQ path | Lexical | Shared terms |
| --- | --- | --- | --- | ---: | --- |
| `5013849` | [WINDOWS-SYSMON] Remote Thread Creation Ttdinject.exe P | Remote Thread Creation Ttdinject.exe Proxy | `rules/windows/create_remote_thread/create_remote_thread_win_ttdinjec.yml` | 0.96 | ttdinject.exe, thread, proxy, remote, creation |
| `5013875` | [WINDOWS-SYSMON] Credential Dumping Tools Service Execu | Credential Dumping Tools Service Execution | `deprecated/windows/driver_load_win_mal_creddumper.yml` | 0.90 | fgexec, servpw, dumpsvc, mimidrv, gsecdump, cachedump |
| `5013875` | [WINDOWS-SYSMON] Credential Dumping Tools Service Execu | Credential Dumping Tools Service Execution - Security | `rules/windows/builtin/security/win_security_mal_creddumper.yml` | 0.90 | fgexec, servpw, dumpsvc, mimidrv, gsecdump, cachedump |
| `5000890` | [JUNIPER] BGP missing MD5 digest | Juniper BGP Missing MD5 | `rules/network/juniper/bgp/juniper_bgp_missing_md5.yml` | 0.88 | digest, bgp, missing, md5, juniper |
| `5013875` | [WINDOWS-SYSMON] Credential Dumping Tools Service Execu | Credential Dumping Tools Service Execution - System | `rules/windows/builtin/system/service_control_manager/win_system_mal_creddumper.yml` | 0.88 | fgexec, servpw, dumpsvc, mimidrv, gsecdump, cachedump |
| `5013844` | [WINDOWS-SYSMON] Bumblebee Remote Thread Creation | Potential Bumblebee Remote Thread Creation | `rules-emerging-threats/2022/Malware/Bumblebee/create_remote_thread_win_malware_bumblebee.yml` | 0.88 | imagingdevices.exe, wabmig.exe, bumblebee, wab.exe, thread, rundll32.e |
| `5010732` | [WINDOWS-POWERSHELL] Possible obfuscated script with mu | Split A File Into Pieces | `rules/macos/process_creation/proc_creation_macos_split_file_into_pieces.yml` | 0.85 | split |
| `5010733` | [WINDOWS-POWERSHELL] Possible obfuscated script with mu | Split A File Into Pieces | `rules/macos/process_creation/proc_creation_macos_split_file_into_pieces.yml` | 0.85 | split |
| `5010732` | [WINDOWS-POWERSHELL] Possible obfuscated script with mu | Split A File Into Pieces - Linux | `rules/linux/auditd/syscall/lnx_auditd_split_file_into_pieces.yml` | 0.83 | split |
| `5010733` | [WINDOWS-POWERSHELL] Possible obfuscated script with mu | Split A File Into Pieces - Linux | `rules/linux/auditd/syscall/lnx_auditd_split_file_into_pieces.yml` | 0.83 | split |
| `5013806` | [WINDOWS-SYSMON] PowerShell Scripts Run by a Services | PowerShell Scripts Run by a Services | `deprecated/windows/driver_load_win_powershell_script_installed_as_service.yml` | 0.78 | pwsh, run, scripts, powershell |
| `5013807` | [WINDOWS-SYSMON] PowerShell Scripts Run by a Services | PowerShell Scripts Run by a Services | `deprecated/windows/driver_load_win_powershell_script_installed_as_service.yml` | 0.78 | pwsh, run, scripts, powershell |
| `5100011` | bash shell in use | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.77 | bash, shell |
| `5013847` | [WINDOWS-SYSMON] CreateRemoteThread API and LoadLibrary | CreateRemoteThread API and LoadLibrary | `rules-threat-hunting/windows/create_remote_thread/create_remote_thread_win_loadlibrary.yml` | 0.77 | loadlibrarya, kernel32.dll, loadlibrary, createremotethread, api |
| `5007157` | [WINDOWS-POWERSHELL] Create Volume Shadow Copy | Create Volume Shadow Copy with Powershell | `rules/windows/powershell/powershell_script/posh_ps_create_volume_shadow_copy.yml` | 0.76 | clientaccessible, win32_shadowcopy, shadow, volume, copy, create |
| `5003403` | [WINDOWS-SECURITY] A security-enabled global group was | A Security-Enabled Global Group Was Deleted | `rules/windows/builtin/security/account_management/win_security_security_enabled_global_group_deleted.yml` | 0.76 | security-enabled, global, group |
| `5009370` | [WINDOWS-POWERSHELL] Create Volume Shadow Copy | Create Volume Shadow Copy with Powershell | `rules/windows/powershell/powershell_script/posh_ps_create_volume_shadow_copy.yml` | 0.76 | clientaccessible, win32_shadowcopy, shadow, volume, copy, create |
| `5005634` | [LINUX-AUDITD] /dev/tcp access | Suspicious Use of /dev/tcp | `rules/linux/builtin/lnx_susp_dev_tcp.yml` | 0.75 | dev/tcp |
| `5007863` | [WINDOWS-SYSMON] Possible DLL Hijacking of edputil.dll | Potential Edputil.DLL Sideloading | `rules/windows/image_load/image_load_side_load_edputil.yml` | 0.75 | edputil.dll, dll |
| `5009928` | [WINDOWS-SYSMON] Possible DLL Hijacking of edputil.dll | Potential Edputil.DLL Sideloading | `rules/windows/image_load/image_load_side_load_edputil.yml` | 0.75 | edputil.dll, dll |
| `5009399` | [WINDOWS-SECURITY] A security-enabled global group was | A Security-Enabled Global Group Was Deleted | `rules/windows/builtin/security/account_management/win_security_security_enabled_global_group_deleted.yml` | 0.75 | security-enabled, global, group |
| `5002317` | [BASH] /dev/tcp access | Suspicious Use of /dev/tcp | `rules/linux/builtin/lnx_susp_dev_tcp.yml` | 0.74 | dev/tcp, bash |
| `5100011` | bash shell in use | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.74 | bash, shell |
| `5005765` | [WINDOWS-POWERSHELL] Suspicious Download using IEX | Suspicious PowerShell Download and Execute Pattern | `rules/windows/process_creation/proc_creation_win_powershell_susp_download_patterns.yml` | 0.73 | net.webclient, new-object, downloadstring, iex, download, powershell |
| `5006610` | [WINDOWS-POWERSHELL] Suspicious Download using IEX | Suspicious PowerShell Download and Execute Pattern | `rules/windows/process_creation/proc_creation_win_powershell_susp_download_patterns.yml` | 0.73 | net.webclient, new-object, downloadstring, iex, download, powershell |
| `5009401` | [WINDOWS-SECURITY] A security-enabled global group was | A Security-Enabled Global Group Was Deleted | `rules/windows/builtin/security/account_management/win_security_security_enabled_global_group_deleted.yml` | 0.73 | security-enabled, global, group |
| `5009323` | [WINDOWS-POWERSHELL] Suspicious Download using IEX | Suspicious PowerShell Download and Execute Pattern | `rules/windows/process_creation/proc_creation_win_powershell_susp_download_patterns.yml` | 0.73 | net.webclient, new-object, downloadstring, iex, download, powershell |
| `5009337` | [WINDOWS-POWERSHELL] Suspicious Download using IEX | Suspicious PowerShell Download and Execute Pattern | `rules/windows/process_creation/proc_creation_win_powershell_susp_download_patterns.yml` | 0.73 | net.webclient, new-object, downloadstring, iex, download, powershell |
| `5017926` | [MSAPI-SECURITYCOMPLIANCECENTER] User Restricted From S | Microsoft 365 - User Restricted from Sending Email | `rules/cloud/m365/threat_management/microsoft365_user_restricted_from_sending_email.yml` | 0.73 | sending, securitycompliancecenter, restricted, email |
| `5013898` | [WINDOWS-SECURITY] Powershell Get-Process | Suspicious Process Discovery With Get-Process | `rules/windows/powershell/powershell_script/posh_ps_susp_get_process.yml` | 0.72 | get-process |
| `5008438` | [WINDOWS-AUTH] A member was added to a security-enabled | A Member Was Removed From a Security-Enabled Global Gro | `rules/windows/builtin/security/account_management/win_security_member_removed_security_enabled_global_group.yml` | 0.72 | security-enabled, global, member, group |
| `5100106` | Microsoft MSSQL server detected | MSSQL Server Failed Logon | `rules/windows/builtin/application/mssqlserver/win_mssql_failed_logon.yml` | 0.72 | mssql, server |
| `5017060` | [AWS] S3 Enumeration (Multiple ListBuckets Events) | Potential Bucket Enumeration on AWS | `rules/cloud/aws/cloudtrail/aws_enum_buckets.yml` | 0.72 | listbuckets, s3.amazonaws.com, enumeration, aws |
| `5008821` | [WINDOWS-MALWARE] Various ransomware file extension det | OneLogin User Account Locked | `rules/identity/onelogin/onelogin_user_account_locked.yml` | 0.70 | locked |
| `5009015` | [WINDOWS-MALWARE] Various ransomware file extension det | OneLogin User Account Locked | `rules/identity/onelogin/onelogin_user_account_locked.yml` | 0.70 | locked |
| `5015176` | [WINDOWS-SECURITY] EDRSilencer Detected | HackTool - EDRSilencer Execution | `rules/windows/process_creation/proc_creation_win_hktl_edrsilencer.yml` | 0.70 | edrsilencer.exe, edrsilencer, security |
| `5007156` | [WINDOWS-POWERSHELL] Dnscat Exfil Tool Execution | Dnscat Execution | `deprecated/windows/posh_ps_dnscat_execution.yml` | 0.69 | dnscat, start-dnscat2, tool, execution |
| `5013849` | [WINDOWS-SYSMON] Remote Thread Creation Ttdinject.exe P | Use of TTDInject.exe | `rules/windows/process_creation/proc_creation_win_lolbin_ttdinject.yml` | 0.69 | ttdinject.exe |
| `5009369` | [WINDOWS-POWERSHELL] Dnscat Exfil Tool Execution | Dnscat Execution | `deprecated/windows/posh_ps_dnscat_execution.yml` | 0.69 | dnscat, start-dnscat2, tool, execution |
| `5010577` | [CISCO-SCA] New IP Scanner | Renamed PingCastle Binary Execution | `rules/windows/process_creation/proc_creation_win_renamed_pingcastle.yml` | 0.68 | scanner |
| `5000165` | [APACHE] Mod_Security Access denied | Multiple Modsecurity Blocks | `unsupported/other/modsec_mulitple_blocks.yml` | 0.68 | mod_security, mod_security-message, modsecurity, denied |
| `5010518` | [CISCO-SCA] AWS Root Account Used | AWS Root Credentials | `rules/cloud/aws/cloudtrail/aws_root_account_usage.yml` | 0.68 | root, aws |
| `5013898` | [WINDOWS-SECURITY] Powershell Get-Process | PowerShell Get-Process LSASS in ScriptBlock | `rules/windows/powershell/powershell_script/posh_ps_susp_getprocess_lsass.yml` | 0.68 | get-process, powershell |
| `5010577` | [CISCO-SCA] New IP Scanner | PUA - PingCastle Execution From Potentially Suspicious | `rules/windows/process_creation/proc_creation_win_pua_pingcastle_script_parent.yml` | 0.67 | scanner |
| `5013805` | [WINDOWS-SYSMON] PowerShell Rundll32 Remote Thread Crea | Remote Thread Creation Via PowerShell | `rules-threat-hunting/windows/create_remote_thread/create_remote_thread_win_powershell_generic.yml` | 0.67 | thread, pwsh.exe, remote, creation, powershell |
| `5014657` | [MSAPI-AZUREAD] Privileged Role Administrator role assi | User Added to an Administrator's Azure AD Role | `rules/cloud/azure/audit_logs/azure_ad_user_added_to_admin_role.yml` | 0.67 | member, role, administrator, add |
| `5100011` | bash shell in use | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.67 | bash, shell |
| `5010484` | [WINDOWS-SECURITY] Password Protected Zip File Opened | Password Protected ZIP File Opened | `rules/windows/builtin/security/win_security_susp_opened_encrypted_zip.yml` | 0.67 | microsoft_windows_shell_zipfolder, opened, protected, zip, password |
| `5008442` | [WINDOWS-AUTH] A member was added to a security-enabled | A Member Was Added to a Security-Enabled Global Group | `rules/windows/builtin/security/account_management/win_security_member_added_security_enabled_global_group.yml` | 0.67 | security-enabled, member, added, group |
| `5010482` | [WINDOWS-POWERSHELL] Net.WebClient DownloadString | Suspicious PowerShell Download and Execute Pattern | `rules/windows/process_creation/proc_creation_win_powershell_susp_download_patterns.yml` | 0.67 | net.webclient, new-object, downloadstring, powershell |
| `5014549` | [WINDOWS-SECURITY] Password Protected Zip File Opened | Password Protected ZIP File Opened | `rules/windows/builtin/security/win_security_susp_opened_encrypted_zip.yml` | 0.66 | microsoft_windows_shell_zipfolder, opened, protected, zip, password |
| `5007940` | [WINDOWS-SYSMON] Possible DLL Hijacking of mpsvc.dll | Potential DLL Sideloading Of MpSvc.DLL | `rules/windows/image_load/image_load_side_load_mpsvc.yml` | 0.66 | mpsvc.dll, dll |
| `5003403` | [WINDOWS-SECURITY] A security-enabled global group was | A Member Was Added to a Security-Enabled Global Group | `rules/windows/builtin/security/account_management/win_security_member_added_security_enabled_global_group.yml` | 0.66 | security-enabled, global, group |
| `5010005` | [WINDOWS-SYSMON] Possible DLL Hijacking of mpsvc.dll | Potential DLL Sideloading Of MpSvc.DLL | `rules/windows/image_load/image_load_side_load_mpsvc.yml` | 0.66 | mpsvc.dll, dll |
| `5010776` | [CyberArk] Clear User History | Cisco Clear Logs | `rules/network/cisco/aaa/cisco_cli_clear_logs.yml` | 0.65 | clear, history |
| `5009367` | [WINDOWS-POWERSHELL] Local User Created | PowerShell Create Local User | `rules/windows/powershell/powershell_script/posh_ps_create_local_user.yml` | 0.65 | new-localuser, local, powershell |
| `5003015` | [DYNAMIC] MSSQL logs detected via program. | MSSQL Server Failed Logon | `rules/windows/builtin/application/mssqlserver/win_mssql_failed_logon.yml` | 0.65 | mssql |
| `5010484` | [WINDOWS-SECURITY] Password Protected Zip File Opened | Password Protected ZIP File Opened (Email Attachment) | `rules/windows/builtin/security/win_security_susp_opened_encrypted_zip_outlook.yml` | 0.65 | microsoft_windows_shell_zipfolder, opened, protected, zip, password |
| `9870009` | [EXPERIMENTAL][WINDOWS-SECURITY] Kerberos - AS-REP Roas | Potential AS-REP Roasting via Kerberos TGT Requests | `rules/windows/builtin/security/win_security_kerberos_asrep_roasting.yml` | 0.65 | as-rep, roasting, pre-authentication, 0x17, ticket, encryption |
| `5009399` | [WINDOWS-SECURITY] A security-enabled global group was | A Member Was Added to a Security-Enabled Global Group | `rules/windows/builtin/security/account_management/win_security_member_added_security_enabled_global_group.yml` | 0.65 | security-enabled, global, group |
| `5014624` | [WINDOWS-MALWARE] Credential Dumping Via ntdsutil.exe c | Suspicious Usage Of Active Directory Diagnostic Tool (n | `rules/windows/process_creation/proc_creation_win_ntdsutil_susp_usage.yml` | 0.65 | ntdsutil.exe, ntds |
| `5014624` | [WINDOWS-MALWARE] Credential Dumping Via ntdsutil.exe c | Invocation of Active Directory Diagnostic Tool (ntdsuti | `rules/windows/process_creation/proc_creation_win_ntdsutil_usage.yml` | 0.64 | ntdsutil.exe, ntds |
| `5003403` | [WINDOWS-SECURITY] A security-enabled global group was | A Member Was Removed From a Security-Enabled Global Gro | `rules/windows/builtin/security/account_management/win_security_member_removed_security_enabled_global_group.yml` | 0.64 | security-enabled, global, group |
| `5014549` | [WINDOWS-SECURITY] Password Protected Zip File Opened | Password Protected ZIP File Opened (Email Attachment) | `rules/windows/builtin/security/win_security_susp_opened_encrypted_zip_outlook.yml` | 0.64 | microsoft_windows_shell_zipfolder, opened, protected, zip, password |
| `5007141` | [WINDOWS-POWERSHELL] Suspicious XOR Command | Suspicious XOR Encoded PowerShell Command | `rules/windows/process_creation/proc_creation_win_powershell_xor_commandline.yml` | 0.64 | xor, bxor, join, char, powershell |
| `5007690` | [WINDOWS-POWERSHELL] Possible nslookup command stager | Nslookup PwSh Download Cradle | `deprecated/windows/proc_creation_win_nslookup_pwsh_download_cradle.yml` | 0.64 | nslookup, txt, powershell |
| `5005748` | [WINDOWS-POWERSHELL] Powershell History Cleared Detecte | Clear PowerShell History - PowerShell | `rules/windows/powershell/powershell_script/posh_ps_clear_powershell_history.yml` | 0.64 | historysavestyle, savenothing, set-psreadlineoption, history, powershe |
| `5009354` | [WINDOWS-POWERSHELL] Suspicious XOR Command | Suspicious XOR Encoded PowerShell Command | `rules/windows/process_creation/proc_creation_win_powershell_xor_commandline.yml` | 0.64 | xor, bxor, join, char, powershell |
| `5013797` | [WINDOWS-SYSMON] PowerShell BitsTransfer Detected | Suspicious Bitstransfer via PowerShell | `deprecated/windows/proc_creation_win_susp_bitstransfer.yml` | 0.64 | bitstransfer, powershell.exe, powershell |
| `5008438` | [WINDOWS-AUTH] A member was added to a security-enabled | A Security-Enabled Global Group Was Deleted | `rules/windows/builtin/security/account_management/win_security_security_enabled_global_group_deleted.yml` | 0.63 | security-enabled, global, group |
| `5013805` | [WINDOWS-SYSMON] PowerShell Rundll32 Remote Thread Crea | Remote Thread Creation Via PowerShell In Uncommon Targe | `rules/windows/create_remote_thread/create_remote_thread_win_powershell_susp_targets.yml` | 0.63 | thread, rundll32.exe, pwsh.exe, remote, creation, powershell |
| `5009371` | [WINDOWS-POWERSHELL] Possible nslookup command stager | Nslookup PwSh Download Cradle | `deprecated/windows/proc_creation_win_nslookup_pwsh_download_cradle.yml` | 0.63 | nslookup, txt, powershell |
| `5009306` | [WINDOWS-POWERSHELL] Powershell History Cleared Detecte | Clear PowerShell History - PowerShell | `rules/windows/powershell/powershell_script/posh_ps_clear_powershell_history.yml` | 0.63 | historysavestyle, savenothing, set-psreadlineoption, history, powershe |
| `5009399` | [WINDOWS-SECURITY] A security-enabled global group was | A Member Was Removed From a Security-Enabled Global Gro | `rules/windows/builtin/security/account_management/win_security_member_removed_security_enabled_global_group.yml` | 0.63 | security-enabled, global, group |
| `5005487` | [CLOUDTRAIL] ElastiCache cloudtrail event detected - (C | AWS ElastiCache Security Group Created | `rules/cloud/aws/cloudtrail/aws_elasticache_security_group_created.yml` | 0.63 | createcachesecuritygroup, elasticache, elasticache.amazonaws.com |
| `5005748` | [WINDOWS-POWERSHELL] Powershell History Cleared Detecte | Clear PowerShell History - PowerShell Module | `rules/windows/powershell/powershell_module/posh_pm_clear_powershell_history.yml` | 0.63 | historysavestyle, savenothing, set-psreadlineoption, history, powershe |
| `5013923` | [WINDOWS-SECURITY] Copy from a remote host | Copy From VolumeShadowCopy Via Cmd.EXE | `rules/windows/process_creation/proc_creation_win_cmd_shadowcopy_access.yml` | 0.63 | copy, cmd.exe |
| `5008821` | [WINDOWS-MALWARE] Various ransomware file extension det | Okta User Account Locked Out | `rules/identity/okta/okta_user_account_locked_out.yml` | 0.63 | locked |
| `5009015` | [WINDOWS-MALWARE] Various ransomware file extension det | Okta User Account Locked Out | `rules/identity/okta/okta_user_account_locked_out.yml` | 0.63 | locked |
| `5009401` | [WINDOWS-SECURITY] A security-enabled global group was | A Member Was Added to a Security-Enabled Global Group | `rules/windows/builtin/security/account_management/win_security_member_added_security_enabled_global_group.yml` | 0.63 | security-enabled, global, group |
| `5009306` | [WINDOWS-POWERSHELL] Powershell History Cleared Detecte | Clear PowerShell History - PowerShell Module | `rules/windows/powershell/powershell_module/posh_pm_clear_powershell_history.yml` | 0.63 | historysavestyle, savenothing, set-psreadlineoption, history, powershe |
| `5002963` | [DYNAMIC] Bash logs detected via program. | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.63 | bash |
| `5014331` | [WINDOWS-SECURITY] User Added to Local Administrators G | User Added to Local Administrators Group | `rules/windows/process_creation/proc_creation_win_susp_add_user_local_admin_group.yml` | 0.63 | localgroup, administrators, net, added, local, add |
| `5013834` | [WINDOWS-SYSMON] DllRegisterServer Entry Function on db | Rundll32.EXE Calling DllRegisterServer Export Function | `rules-threat-hunting/windows/process_creation/proc_creation_win_rundll32_dllregisterserver.yml` | 0.62 | dllregisterserver, function, rundll32.exe |
| `9870007` | [EXPERIMENTAL][WINDOWS-SECURITY] Kerberos - Service Tic | Suspicious Kerberos RC4 Ticket Encryption | `rules/windows/builtin/security/win_security_susp_rc4_kerberos.yml` | 0.62 | rc4, 0x17, ticket, encryption, kerberos |
| `5000110` | [BIND] Zone transfer error | Potentially Suspicious File Download From ZIP TLD | `rules/windows/create_stream_hash/create_stream_hash_zip_tld_download.yml` | 0.62 | zone |
| `5017151` | [AWS] EC2 Modify Snapshot Attribute | AWS Snapshot Backup Exfiltration | `rules/cloud/aws/cloudtrail/aws_snapshot_backup_exfiltration.yml` | 0.62 | modifysnapshotattribute, snapshot, ec2, ec2.amazonaws.com, aws |
| `5014647` | [MSAPI-AZUREAD] CRITICAL - User Administrator role assi | User Added to an Administrator's Azure AD Role | `rules/cloud/azure/audit_logs/azure_ad_user_added_to_admin_role.yml` | 0.62 | member, role, administrator, add |
| `5013543` | [WINDOWS-MISC] GET /human2.aspx (CVE-2023-34362) | MOVEit CVE-2023-34362 Exploitation Attempt - Potential | `rules-emerging-threats/2023/Exploits/CVE-2023-34362-MOVEit-Transfer-Exploit/web_cve_2023_34362_known_payload_request.yml.yml` | 0.62 | human2.aspx, cve-2023-34362, get |
| `5009295` | [WINDOWS-MISC] Installation of PSEXEC service via Secur | PsExec Service File Creation | `rules/windows/file/file_event/file_event_win_sysinternals_psexec_service.yml` | 0.62 | psexec, installation |
| `5100136` | Cisco device detected | Potential CVE-2023-36884 Exploitation - Share Access | `rules-emerging-threats/2023/Exploits/CVE-2023-36884/win_security_exploit_cve_2023_36884_office_windows_html_rce_share_access_pattern.yml` | 0.62 | 0-9 |
| `5009401` | [WINDOWS-SECURITY] A security-enabled global group was | A Member Was Removed From a Security-Enabled Global Gro | `rules/windows/builtin/security/account_management/win_security_member_removed_security_enabled_global_group.yml` | 0.62 | security-enabled, global, group |
| `5015262` | [NETSKOPE] Reset password Event Detected | Password Reset By User Account | `rules/cloud/azure/audit_logs/azure_user_password_change.yml` | 0.62 | reset, password |
| `5002963` | [DYNAMIC] Bash logs detected via program. | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.62 | bash |
| `5002572` | [CYLANCE] Device - Registration | Changes to Device Registration Policy | `rules/cloud/azure/audit_logs/azure_ad_device_registration_policy_changes.yml` | 0.62 | registration, device |
| `5005623` | [LINUX-AUDITD] /etc/passwd access | Symlink Etc Passwd | `rules/linux/builtin/lnx_symlink_etc_passwd.yml` | 0.61 | etc/passwd |
| `5005656` | [LINUX-AUDITD] chmod u+s execution | Chmod Targeting Sensitive Directories | `rules/linux/process_creation/proc_creation_lnx_chmod_targeting_sensitive_directories.yml` | 0.61 | chmod |
| `5005657` | [LINUX-AUDITD] chmod +s execution | Chmod Targeting Sensitive Directories | `rules/linux/process_creation/proc_creation_lnx_chmod_targeting_sensitive_directories.yml` | 0.61 | chmod |
| `5005674` | [LINUX-AUDITD] chmod +s execution | Chmod Targeting Sensitive Directories | `rules/linux/process_creation/proc_creation_lnx_chmod_targeting_sensitive_directories.yml` | 0.61 | chmod |
| `5014646` | [MSAPI-AZUREAD] CRITICAL - Security Administrator role | User Added to an Administrator's Azure AD Role | `rules/cloud/azure/audit_logs/azure_ad_user_added_to_admin_role.yml` | 0.61 | member, role, administrator, add |
| `5008449` | [WINDOWS-AUTH] A member was added to a security-enabled | A Member Was Added to a Security-Enabled Global Group | `rules/windows/builtin/security/account_management/win_security_member_added_security_enabled_global_group.yml` | 0.61 | security-enabled, member, added, group |
| `5008363` | [WINDOWS-CLIPBOARD] Get-ADUser Command | User Discovery And Export Via Get-ADUser Cmdlet - Power | `rules/windows/powershell/powershell_script/posh_ps_user_discovery_get_aduser.yml` | 0.61 | get-aduser |
| `5006858` | [WINDOWS-MALWARE] Ruby ransomware file extension detect | Ruby Inline Command Execution | `rules/windows/process_creation/proc_creation_win_ruby_inline_command_execution.yml` | 0.61 | ruby |
| `5007055` | [WINDOWS-MALWARE] Ruby ransomware file extension detect | Ruby Inline Command Execution | `rules/windows/process_creation/proc_creation_win_ruby_inline_command_execution.yml` | 0.61 | ruby |
| `5008934` | [WINDOWS-MALWARE] Ruby ransomware file extension detect | Ruby Inline Command Execution | `rules/windows/process_creation/proc_creation_win_ruby_inline_command_execution.yml` | 0.61 | ruby |
| `5009131` | [WINDOWS-MALWARE] Ruby ransomware file extension detect | Ruby Inline Command Execution | `rules/windows/process_creation/proc_creation_win_ruby_inline_command_execution.yml` | 0.61 | ruby |
| `5005765` | [WINDOWS-POWERSHELL] Suspicious Download using IEX | Suspicious PowerShell IEX Execution Patterns | `rules/windows/process_creation/proc_creation_win_powershell_iex_patterns.yml` | 0.61 | iex, powershell |
| `5006610` | [WINDOWS-POWERSHELL] Suspicious Download using IEX | Suspicious PowerShell IEX Execution Patterns | `rules/windows/process_creation/proc_creation_win_powershell_iex_patterns.yml` | 0.61 | iex, powershell |
| `5013817` | [WINDOWS-SECURITY] Remote Access Software Installed as | Anydesk Remote Access Software Service Installation | `rules/windows/builtin/system/service_control_manager/win_system_service_install_anydesk.yml` | 0.61 | anydesk, software, remote |
| `5008634` | [WINDOWS-CLIPBOARD] Get-ADUser Command | User Discovery And Export Via Get-ADUser Cmdlet - Power | `rules/windows/powershell/powershell_script/posh_ps_user_discovery_get_aduser.yml` | 0.60 | get-aduser |
| `5009323` | [WINDOWS-POWERSHELL] Suspicious Download using IEX | PowerShell Download and Execution Cradles | `rules/windows/process_creation/proc_creation_win_powershell_download_iex.yml` | 0.60 | downloadstring, iex, download, powershell |
| `5009337` | [WINDOWS-POWERSHELL] Suspicious Download using IEX | PowerShell Download and Execution Cradles | `rules/windows/process_creation/proc_creation_win_powershell_download_iex.yml` | 0.60 | downloadstring, iex, download, powershell |
| `5009323` | [WINDOWS-POWERSHELL] Suspicious Download using IEX | Suspicious PowerShell IEX Execution Patterns | `rules/windows/process_creation/proc_creation_win_powershell_iex_patterns.yml` | 0.60 | iex, powershell |
| `5009337` | [WINDOWS-POWERSHELL] Suspicious Download using IEX | Suspicious PowerShell IEX Execution Patterns | `rules/windows/process_creation/proc_creation_win_powershell_iex_patterns.yml` | 0.60 | iex, powershell |
| `5007690` | [WINDOWS-POWERSHELL] Possible nslookup command stager | Nslookup PowerShell Download Cradle | `rules/windows/powershell/powershell_classic/posh_pc_abuse_nslookup_with_dns_records.yml` | 0.60 | nslookup, txt, powershell |
| `5012103` | [SONICWALL] Admin Login Disabled | Login to Disabled Account | `rules/cloud/azure/signin_logs/azure_login_to_disabled_account.yml` | 0.60 | disabled, login |
| `5010482` | [WINDOWS-POWERSHELL] Net.WebClient DownloadString | PowerShell Download Via Net.WebClient - PowerShell Clas | `rules/windows/powershell/powershell_classic/posh_pc_download_via_webclient.yml` | 0.60 | net.webclient, downloadstring, powershell |
| `5009371` | [WINDOWS-POWERSHELL] Possible nslookup command stager | Nslookup PowerShell Download Cradle | `rules/windows/powershell/powershell_classic/posh_pc_abuse_nslookup_with_dns_records.yml` | 0.60 | nslookup, txt, powershell |
| `5005971` | [WINDOWS-MALWARE] Rubeus successful TGT Enumeration | Register new Logon Process by Rubeus | `rules/windows/builtin/security/win_security_register_new_logon_process_by_rubeus.yml` | 0.60 | user32logonprocesss, rubeus, logon |
| `5008794` | [WINDOWS-MALWARE] Rubeus successful TGT Enumeration | Register new Logon Process by Rubeus | `rules/windows/builtin/security/win_security_register_new_logon_process_by_rubeus.yml` | 0.60 | user32logonprocesss, rubeus, logon |
| `5007937` | [WINDOWS-SYSMON] Possible DLL Hijacking of mpclient.dll | Potential Mpclient.DLL Sideloading | `rules/windows/image_load/image_load_side_load_windows_defender.yml` | 0.59 | mpclient.dll, defender, x86, program |
| `5010002` | [WINDOWS-SYSMON] Possible DLL Hijacking of mpclient.dll | Potential Mpclient.DLL Sideloading | `rules/windows/image_load/image_load_side_load_windows_defender.yml` | 0.59 | mpclient.dll, defender, x86, program |
| `5013923` | [WINDOWS-SECURITY] Copy from a remote host | Copy .DMP/.DUMP Files From Remote Share Via Cmd.EXE | `rules/windows/process_creation/proc_creation_win_cmd_copy_dmp_from_share.yml` | 0.59 | copy, cmd.exe, remote |
| `5013873` | [WINDOWS-SYSMON] KeePass Password Dumping | Remote Thread Created In KeePass.EXE | `rules/windows/create_remote_thread/create_remote_thread_win_keepass.yml` | 0.59 | keepass.exe, dumping, password |
| `5012098` | [WINDOWS-SECURITY] Inbound RDP Tunneling | Potential RDP Tunneling Via SSH | `rules/windows/process_creation/proc_creation_win_ssh_rdp_tunneling.yml` | 0.59 | ssh.exe, tunneling, rdp |
| `5000110` | [BIND] Zone transfer error | Unusual File Download from Direct IP Address | `rules/windows/create_stream_hash/create_stream_hash_susp_ip_domains.yml` | 0.59 | zone |
| `5010857` | [CyberArk] Reset Password User | Password Reset By User Account | `rules/cloud/azure/audit_logs/azure_user_password_change.yml` | 0.59 | reset, password |
| `5010858` | [CyberArk] Reset Password Your User | Password Reset By User Account | `rules/cloud/azure/audit_logs/azure_user_password_change.yml` | 0.59 | reset, password |
| `5013814` | [WINDOWS-SECURITY] TacticalRmm Remote Management Softwa | TacticalRMM Service Installation | `rules/windows/builtin/system/service_control_manager/win_system_service_install_tacticalrmm.yml` | 0.59 | tacticalrmm.exe, tacticalrmm, management, remote |
| `5015941` | [WINDOWS-SYSMON] Cobalt Strike Beacon Detected | Meterpreter or Cobalt Strike Getsystem Service Installa | `unsupported/windows/driver_load_meterpreter_or_cobaltstrike_getsystem_service_installation.yml` | 0.59 | strike, cobalt, echo, pipe, cmd.exe |
| `5013890` | [WINDOWS-SECURITY] net group domain admins command exec | Reconnaissance Activity | `rules/windows/builtin/security/win_security_susp_net_recon_activity.yml` | 0.59 | admins, net, domain, group |
| `5014561` | [WINDOWS-SECURITY] Inbound RDP Tunneling | Potential RDP Tunneling Via SSH | `rules/windows/process_creation/proc_creation_win_ssh_rdp_tunneling.yml` | 0.59 | ssh.exe, tunneling, rdp |
| `5008406` | [WINDOWS-MISC] Potential AS-REP Roasting Activity Detec | Potential AS-REP Roasting via Kerberos TGT Requests | `rules/windows/builtin/security/win_security_kerberos_asrep_roasting.yml` | 0.58 | as-rep, roasting, pre-authentication, 0x17, ticket, encryption |
| `5002963` | [DYNAMIC] Bash logs detected via program. | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.58 | bash |
| `5100126` | VNC detected | OpenCanary - VNC Connection Attempt | `rules/application/opencanary/opencanary_vnc_connection_attempt.yml` | 0.58 | vnc |
| `5100060` | systemd detected | Systemd Service Creation | `rules/linux/auditd/path/lnx_auditd_systemd_service_creation.yml` | 0.58 | systemd |
| `5009301` | [WINDOWS-MISC] Potential AS-REP Roasting Activity Detec | Potential AS-REP Roasting via Kerberos TGT Requests | `rules/windows/builtin/security/win_security_kerberos_asrep_roasting.yml` | 0.58 | as-rep, roasting, pre-authentication, 0x17, ticket, encryption |
| `5014338` | [WINDOWS-SECURITY] Possible Shadow Credentials - User U | Possible Shadow Credentials Added | `rules/windows/builtin/security/win_security_susp_possible_shadow_credentials_added.yml` | 0.58 | msds-keycredentiallink, shadow, credentials, added |
| `5013820` | [WINDOWS-SECURITY] Local PrivEsc via sc.exe | Service Security Descriptor Tampering Via Sc.EXE | `rules/windows/process_creation/proc_creation_win_sc_sdset_modification.yml` | 0.58 | sdset, sc.exe, security |
| `5008363` | [WINDOWS-CLIPBOARD] Get-ADUser Command | User Discovery And Export Via Get-ADUser Cmdlet | `rules/windows/process_creation/proc_creation_win_powershell_user_discovery_get_aduser.yml` | 0.58 | get-aduser |
| `5013921` | [WINDOWS-SECURITY] TacticalRmm Remote Management Softwa | TacticalRMM Service Installation | `rules/windows/builtin/system/service_control_manager/win_system_service_install_tacticalrmm.yml` | 0.58 | tacticalrmm.exe, tacticalrmm, management, remote |
| `5008634` | [WINDOWS-CLIPBOARD] Get-ADUser Command | User Discovery And Export Via Get-ADUser Cmdlet | `rules/windows/process_creation/proc_creation_win_powershell_user_discovery_get_aduser.yml` | 0.58 | get-aduser |
| `5014657` | [MSAPI-AZUREAD] Privileged Role Administrator role assi | App Assigned To Azure RBAC/Microsoft Entra Role | `rules/cloud/azure/audit_logs/azure_app_role_added.yml` | 0.57 | assigned, member, role, administrator, add |
| `5015511` | [WINDOWS-SECURITY] Obfuscated IP address Added to Regis | Potential CVE-2023-36884 Exploitation - Share Access | `rules-emerging-threats/2023/Exploits/CVE-2023-36884/win_security_exploit_cve_2023_36884_office_windows_html_rce_share_access_pattern.yml` | 0.57 | 0-9 |
| `5013886` | [WINDOWS-SECURITY] whoami command executed | WhoAmI as Parameter | `rules/windows/process_creation/proc_creation_win_susp_whoami_as_param.yml` | 0.57 | whoami |
| `5007791` | [WINDOWS-SYSMON] Possible DLL Hijacking of credui.dll | CredUI.DLL Loaded By Uncommon Process | `rules/windows/image_load/image_load_dll_credui_uncommon_process_load.yml` | 0.57 | credui.dll, dll |
| `5009856` | [WINDOWS-SYSMON] Possible DLL Hijacking of credui.dll | CredUI.DLL Loaded By Uncommon Process | `rules/windows/image_load/image_load_dll_credui_uncommon_process_load.yml` | 0.57 | credui.dll, dll |
| `5014657` | [MSAPI-AZUREAD] Privileged Role Administrator role assi | Privileged Account Creation | `rules/cloud/azure/audit_logs/azure_privileged_account_creation.yml` | 0.57 | member, role, privileged, add |
| `5011436` | [AWS-STS] Security Token Service event detected (GetSes | AWS STS GetSessionToken Misuse | `rules/cloud/aws/cloudtrail/aws_sts_getsessiontoken_misuse.yml` | 0.57 | getsessiontoken, sts.amazonaws.com |
| `5005663` | [LINUX-AUDITD] chmod +x of something in /tmp | Suspicious Activity in Shell Commands | `rules/linux/builtin/lnx_shell_susp_commands.yml` | 0.57 | chmod, tmp |
| `5013806` | [WINDOWS-SYSMON] PowerShell Scripts Run by a Services | PowerShell Scripts Installed as Services - Security | `rules/windows/builtin/security/win_security_powershell_script_installed_as_service.yml` | 0.56 | pwsh, scripts, powershell |
| `5013807` | [WINDOWS-SYSMON] PowerShell Scripts Run by a Services | PowerShell Scripts Installed as Services - Security | `rules/windows/builtin/security/win_security_powershell_script_installed_as_service.yml` | 0.56 | pwsh, scripts, powershell |
| `5002179` | [BASH] Remote execution attempt via CVE-2014-6271 | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.56 | bash, execution |
| `5010786` | [CyberArk] User Is Disabled | Login to Disabled Account | `rules/cloud/azure/signin_logs/azure_login_to_disabled_account.yml` | 0.56 | disabled |
| `5100033` | MySQL services detected | OpenCanary - MySQL Login Attempt | `rules/application/opencanary/opencanary_mysql_login_attempt.yml` | 0.56 | mysql |
| `5009295` | [WINDOWS-MISC] Installation of PSEXEC service via Secur | PsExec Service Installation | `rules/windows/builtin/system/service_control_manager/win_system_service_install_sysinternals_psexec.yml` | 0.56 | psexec, installation |
| `5006530` | [WINDOWS-MISC] Rubeus successful TGT Enumeration | Register new Logon Process by Rubeus | `rules/windows/builtin/security/win_security_register_new_logon_process_by_rubeus.yml` | 0.56 | user32logonprocesss, rubeus, logon |
| `5008372` | [WINDOWS-CLIPBOARD] rundll32 command with DllRegisterSe | Potential Renamed Rundll32 Execution | `rules/windows/process_creation/proc_creation_win_renamed_rundll32_dllregisterserver.yml` | 0.56 | dllregisterserver, rundll32, rundll32.exe |
| `5000110` | [BIND] Zone transfer error | Failed DNS Zone Transfer | `rules/windows/builtin/dns_server/win_dns_server_failed_dns_zone_transfer.yml` | 0.56 | zone, transfer |
| `5008358` | [WINDOWS-SECURITY] A service was installed in the syste | Potential Renamed Rundll32 Execution | `rules/windows/process_creation/proc_creation_win_renamed_rundll32_dllregisterserver.yml` | 0.56 | dllregisterserver, rundll32 |
| `5002179` | [BASH] Remote execution attempt via CVE-2014-6271 | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.56 | bash |
| `5010615` | [CISCO-SCA] Suspicious DNS Over HTTPS Activity | UNC4841 - Download Tar File From Untrusted Direct IP Vi | `rules-emerging-threats/2023/TA/UNC4841-Barracuda-ESG-Zero-Day-Exploitation/proc_creation_lnx_apt_unc4841_wget_download_tar_files_direct_ip.yml` | 0.56 | https |
| `5100136` | Cisco device detected | Obfuscated IP Via CLI | `rules/windows/process_creation/proc_creation_win_susp_obfuscated_ip_via_cli.yml` | 0.56 | 0-9 |
| `5008643` | [WINDOWS-CLIPBOARD] rundll32 command with DllRegisterSe | Potential Renamed Rundll32 Execution | `rules/windows/process_creation/proc_creation_win_renamed_rundll32_dllregisterserver.yml` | 0.56 | dllregisterserver, rundll32, rundll32.exe |
| `9870007` | [EXPERIMENTAL][WINDOWS-SECURITY] Kerberos - Service Tic | Kerberos Network Traffic RC4 Ticket Encryption | `rules/network/zeek/zeek_susp_kerberos_rc4.yml` | 0.56 | rc4, kerberoasting, ticket, encryption, kerberos, request |
| `5002572` | [CYLANCE] Device - Registration | Device Registration or Join Without MFA | `rules/cloud/azure/signin_logs/azure_ad_device_registration_or_join_without_mfa.yml` | 0.55 | registration, device |
| `5009774` | [WINDOWS-SECURITY] A service was installed in the syste | Potential Renamed Rundll32 Execution | `rules/windows/process_creation/proc_creation_win_renamed_rundll32_dllregisterserver.yml` | 0.55 | dllregisterserver, rundll32 |
| `5014647` | [MSAPI-AZUREAD] CRITICAL - User Administrator role assi | App Assigned To Azure RBAC/Microsoft Entra Role | `rules/cloud/azure/audit_logs/azure_app_role_added.yml` | 0.55 | assigned, member, role, administrator, add |
| `5010519` | [CISCO-SCA] AWS Snapshot Exfiltration | AWS Snapshot Backup Exfiltration | `rules/cloud/aws/cloudtrail/aws_snapshot_backup_exfiltration.yml` | 0.55 | snapshot, exfiltration, aws |
| `5009298` | [WINDOWS-MISC] Rubeus successful TGT Enumeration | Register new Logon Process by Rubeus | `rules/windows/builtin/security/win_security_register_new_logon_process_by_rubeus.yml` | 0.55 | user32logonprocesss, rubeus, logon |
| `5010484` | [WINDOWS-SECURITY] Password Protected Zip File Opened | Password Protected ZIP File Opened (Suspicious Filename | `rules/windows/builtin/security/win_security_susp_opened_encrypted_zip_filename.yml` | 0.55 | microsoft_windows_shell_zipfolder, opened, protected, zip, password |
| `5005765` | [WINDOWS-POWERSHELL] Suspicious Download using IEX | PowerShell Base64 Encoded IEX Cmdlet | `rules/windows/process_creation/proc_creation_win_powershell_base64_iex.yml` | 0.55 | iex, powershell |
| `5006610` | [WINDOWS-POWERSHELL] Suspicious Download using IEX | PowerShell Base64 Encoded IEX Cmdlet | `rules/windows/process_creation/proc_creation_win_powershell_base64_iex.yml` | 0.55 | iex, powershell |
| `5017599` | [CROWDSTRIKE] Suspicious Execution Detected- PsExec exe | PsExec Service File Creation | `rules/windows/file/file_event/file_event_win_sysinternals_psexec_service.yml` | 0.55 | psexec, execution |
| `5014549` | [WINDOWS-SECURITY] Password Protected Zip File Opened | Password Protected ZIP File Opened (Suspicious Filename | `rules/windows/builtin/security/win_security_susp_opened_encrypted_zip_filename.yml` | 0.55 | microsoft_windows_shell_zipfolder, opened, protected, zip, password |
| `5008372` | [WINDOWS-CLIPBOARD] rundll32 command with DllRegisterSe | Rundll32.EXE Calling DllRegisterServer Export Function | `rules-threat-hunting/windows/process_creation/proc_creation_win_rundll32_dllregisterserver.yml` | 0.55 | dllregisterserver, rundll32, rundll32.exe |
| `5005754` | [WINDOWS-POWERSHELL] DNSCAT VPN over DNS start up detec | Dnscat Execution | `deprecated/windows/posh_ps_dnscat_execution.yml` | 0.55 | dnscat, start-dnscat2 |
| `5010809` | [CyberArk] Clear Expired History | Cisco Clear Logs | `rules/network/cisco/aaa/cisco_cli_clear_logs.yml` | 0.54 | clear, history |
| `5005656` | [LINUX-AUDITD] chmod u+s execution | Suspicious Commands Linux | `rules/linux/auditd/execve/lnx_auditd_susp_cmds.yml` | 0.54 | chmod, execve |
| `5005657` | [LINUX-AUDITD] chmod +s execution | Suspicious Commands Linux | `rules/linux/auditd/execve/lnx_auditd_susp_cmds.yml` | 0.54 | chmod, execve |
| `5005674` | [LINUX-AUDITD] chmod +s execution | Suspicious Commands Linux | `rules/linux/auditd/execve/lnx_auditd_susp_cmds.yml` | 0.54 | chmod, execve |
| `5014646` | [MSAPI-AZUREAD] CRITICAL - Security Administrator role | App Assigned To Azure RBAC/Microsoft Entra Role | `rules/cloud/azure/audit_logs/azure_app_role_added.yml` | 0.54 | assigned, member, role, administrator, add |
| `5003015` | [DYNAMIC] MSSQL logs detected via program. | MSSQL XPCmdshell Option Change | `rules/windows/builtin/application/mssqlserver/win_mssql_xp_cmdshell_change.yml` | 0.54 | mssql |
| `5008643` | [WINDOWS-CLIPBOARD] rundll32 command with DllRegisterSe | Rundll32.EXE Calling DllRegisterServer Export Function | `rules-threat-hunting/windows/process_creation/proc_creation_win_rundll32_dllregisterserver.yml` | 0.54 | dllregisterserver, rundll32, rundll32.exe |
| `5009788` | [WINDOWS-SYSMON] Suspicious WMIC call - computersystem | Computer System Reconnaissance Via Wmic.EXE | `rules/windows/process_creation/proc_creation_win_wmic_recon_computersystem.yml` | 0.54 | computersystem, model, wmic |
| `5009312` | [WINDOWS-POWERSHELL] DNSCAT VPN over DNS start up detec | Dnscat Execution | `deprecated/windows/posh_ps_dnscat_execution.yml` | 0.54 | dnscat, start-dnscat2 |
| `5007813` | [WINDOWS-SYSMON] Possible DLL Hijacking of dbghelp.dll | Network Connection Initiated To AzureWebsites.NET By No | `rules/windows/network_connection/net_connection_win_domain_azurewebsites.yml` | 0.54 | x86, program |
| `5007146` | [WINDOWS-POWERSHELL] Registry Set Value for WDigest Use | Wdigest Enable UseLogonCredential | `rules/windows/registry/registry_set/registry_set_wdigest_enable_uselogoncredential.yml` | 0.54 | uselogoncredential, wdigest, hklm, value |
| `5100136` | Cisco device detected | Obfuscated IP Download Activity | `rules/windows/process_creation/proc_creation_win_susp_obfuscated_ip_download.yml` | 0.54 | 0-9 |
| `5008442` | [WINDOWS-AUTH] A member was added to a security-enabled | A Member Was Removed From a Security-Enabled Global Gro | `rules/windows/builtin/security/account_management/win_security_member_removed_security_enabled_global_group.yml` | 0.54 | security-enabled, member, group |
| `5009359` | [WINDOWS-POWERSHELL] Registry Set Value for WDigest Use | Wdigest Enable UseLogonCredential | `rules/windows/registry/registry_set/registry_set_wdigest_enable_uselogoncredential.yml` | 0.54 | uselogoncredential, wdigest, hklm, value |
| `5009878` | [WINDOWS-SYSMON] Possible DLL Hijacking of dbghelp.dll | Network Connection Initiated To AzureWebsites.NET By No | `rules/windows/network_connection/net_connection_win_domain_azurewebsites.yml` | 0.54 | x86, program |
| `5100106` | Microsoft MSSQL server detected | MSSQL XPCmdshell Option Change | `rules/windows/builtin/application/mssqlserver/win_mssql_xp_cmdshell_change.yml` | 0.54 | mssql |
| `5002306` | [BASH] Netcat execution | Interactive Bash Suspicious Children | `rules/linux/process_creation/proc_creation_lnx_susp_interactive_bash.yml` | 0.54 | ncat, netcat, bash |
| `5015515` | [WINDOWS-SYSMON] Windows Event Log Cleared | Security Eventlog Cleared | `rules/windows/builtin/security/win_security_audit_log_cleared.yml` | 0.54 | wevtutil, cleared |
| `5009772` | [WINDOWS-SECURITY] Exfil software rclone detected | Rclone Config File Creation | `rules/windows/file/file_event/file_event_win_rclone_config_files.yml` | 0.54 | rclone |
| `5013559` | [WINDOWS-FIREWALL] Firewall rule added by AnyDesk | Anydesk Remote Access Software Service Installation | `rules/windows/builtin/system/service_control_manager/win_system_service_install_anydesk.yml` | 0.54 | anydesk |
| `5013874` | [WINDOWS-SYSMON] Password Dumper Remote Thread in LSASS | Password Dumper Remote Thread in LSASS | `rules/windows/create_remote_thread/create_remote_thread_win_susp_password_dumper_lsass.yml` | 0.53 | dumper, thread, lsass.exe, lsass, password, remote |
| `5013548` | [WINDOWS-SYSMON] Powershell get-content from stream dat | Run PowerShell Script from ADS | `rules/windows/process_creation/proc_creation_win_powershell_run_script_from_ads.yml` | 0.53 | get-content, stream, data, powershell |
| `5007937` | [WINDOWS-SYSMON] Possible DLL Hijacking of mpclient.dll | Potential Mpclient.DLL Sideloading Via Defender Binarie | `rules/windows/process_creation/proc_creation_win_mpcmdrun_dll_sideload_defender.yml` | 0.53 | mpclient.dll, defender, x86, program |
| `5008357` | [WINDOWS-SECURITY] A service was installed in the syste | PowerShell Scripts Installed as Services - Security | `rules/windows/builtin/security/win_security_powershell_script_installed_as_service.yml` | 0.53 | installed, powershell |
| `5015511` | [WINDOWS-SECURITY] Obfuscated IP address Added to Regis | Obfuscated IP Via CLI | `rules/windows/process_creation/proc_creation_win_susp_obfuscated_ip_via_cli.yml` | 0.53 | 0-9, address, obfuscated |
| `5007660` | [DYNAMIC] tcp logs detected via program. | PUA - Ngrok Execution | `rules/windows/process_creation/proc_creation_win_pua_ngrok.yml` | 0.53 | tcp |
| `5100125` | Applocker detected | AppLocker Application Would Have Been Blocked | `rules/windows/builtin/applocker/win_applocker_application_would_have_been_blocked.yml` | 0.53 | applocker |
| `5005663` | [LINUX-AUDITD] chmod +x of something in /tmp | Chmod Targeting Sensitive Directories | `rules/linux/process_creation/proc_creation_lnx_chmod_targeting_sensitive_directories.yml` | 0.53 | chmod, tmp |
| `5017599` | [CROWDSTRIKE] Suspicious Execution Detected- PsExec exe | PsExec Tool Execution | `deprecated/windows/proc_creation_win_sysinternals_psexec_service_execution.yml` | 0.53 | psexec, tool, execution |
| `5010002` | [WINDOWS-SYSMON] Possible DLL Hijacking of mpclient.dll | Potential Mpclient.DLL Sideloading Via Defender Binarie | `rules/windows/process_creation/proc_creation_win_mpcmdrun_dll_sideload_defender.yml` | 0.53 | mpclient.dll, defender, x86, program |
| `5005656` | [LINUX-AUDITD] chmod u+s execution | Equation Group Indicators | `rules/linux/builtin/lnx_apt_equationgroup_lnx.yml` | 0.53 | chmod |
| `5005657` | [LINUX-AUDITD] chmod +s execution | Equation Group Indicators | `rules/linux/builtin/lnx_apt_equationgroup_lnx.yml` | 0.53 | chmod |
| `5005674` | [LINUX-AUDITD] chmod +s execution | Equation Group Indicators | `rules/linux/builtin/lnx_apt_equationgroup_lnx.yml` | 0.53 | chmod |
| `5002179` | [BASH] Remote execution attempt via CVE-2014-6271 | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.53 | bash, execution |
| `5013844` | [WINDOWS-SYSMON] Bumblebee Remote Thread Creation | Wab/Wabmig Unusual Parent Or Child Processes | `rules/windows/process_creation/proc_creation_win_wab_unusual_parents.yml` | 0.53 | wabmig.exe, bumblebee, wab.exe |
| `5013806` | [WINDOWS-SYSMON] PowerShell Scripts Run by a Services | PowerShell Scripts Installed as Services | `rules/windows/builtin/system/service_control_manager/win_system_powershell_script_installed_as_service.yml` | 0.53 | pwsh, scripts, powershell |
| `5013807` | [WINDOWS-SYSMON] PowerShell Scripts Run by a Services | PowerShell Scripts Installed as Services | `rules/windows/builtin/system/service_control_manager/win_system_powershell_script_installed_as_service.yml` | 0.53 | pwsh, scripts, powershell |
| `5007148` | [WINDOWS-POWERSHELL] Schtask Created to Base64 Decode P | Scheduled Task Executing Encoded Payload from Registry | `rules/windows/process_creation/proc_creation_win_schtasks_reg_loader_encoded.yml` | 0.53 | get-itemproperty, schtask, hkcu, frombase64string, payload, base64 |
| `5007809` | [WINDOWS-SYSMON] Possible DLL Hijacking of d3dcompiler_ | Network Connection Initiated To AzureWebsites.NET By No | `rules/windows/network_connection/net_connection_win_domain_azurewebsites.yml` | 0.53 | x86, program |
| `5009874` | [WINDOWS-SYSMON] Possible DLL Hijacking of d3dcompiler_ | Network Connection Initiated To AzureWebsites.NET By No | `rules/windows/network_connection/net_connection_win_domain_azurewebsites.yml` | 0.53 | x86, program |
| `5002954` | [WINDOWS-MISC] Event log has been cleared. | Security Eventlog Cleared | `rules/windows/builtin/security/win_security_audit_log_cleared.yml` | 0.53 | eventlog, cleared |
| `5010946` | [GITHUB] Repository Archived | GitHub Repository Archive Status Changed | `rules/application/github/audit/github_repository_archive_status_changed.yml` | 0.53 | archived, repository, github |
| `5013887` | [WINDOWS-SECURITY] net group /domain command executed | Reconnaissance Activity Using BuiltIn Commands | `unsupported/windows/proc_creation_win_correlation_susp_builtin_commands_recon.yml` | 0.53 | net1, net, domain, group |
| `5009773` | [WINDOWS-SECURITY] A service was installed in the syste | PowerShell Scripts Installed as Services - Security | `rules/windows/builtin/security/win_security_powershell_script_installed_as_service.yml` | 0.52 | installed, powershell |
| `5013549` | [WINDOWS-SYSMON] Powershell get-content from stream dat | Run PowerShell Script from ADS | `rules/windows/process_creation/proc_creation_win_powershell_run_script_from_ads.yml` | 0.52 | get-content, stream, data, powershell |
| `5013532` | [WINDOWS-SYSMON] Possible MOVEit Exploitation (CVE-2023 | MOVEit CVE-2023-34362 Exploitation Attempt - Potential | `rules-emerging-threats/2023/Exploits/CVE-2023-34362-MOVEit-Transfer-Exploit/web_cve_2023_34362_known_payload_request.yml.yml` | 0.52 | moveit, cve-2023-34362, exploitation |
| `5007659` | [DYNAMIC] systemd logs detected via program. | Systemd Service Creation | `rules/linux/auditd/path/lnx_auditd_systemd_service_creation.yml` | 0.52 | systemd |
| `5005664` | [LINUX-AUDITD] whoami execution | WhoAmI as Parameter | `rules/windows/process_creation/proc_creation_win_susp_whoami_as_param.yml` | 0.52 | whoami |
| `5004779` | [WINDOWS-MALWARE] Suspicious Powershell execution | HackTool - CrackMapExec Execution Patterns | `rules/windows/process_creation/proc_creation_win_hktl_crackmapexec_execution_patterns.yml` | 0.52 | noni, nop, exec, bypass, powershell.exe, execution |
| `5003015` | [DYNAMIC] MSSQL logs detected via program. | MSSQL XPCmdshell Suspicious Execution | `rules/windows/builtin/application/mssqlserver/win_mssql_xp_cmdshell_audit_log.yml` | 0.52 | mssql |
| `5008779` | [WINDOWS-MALWARE] Suspicious Powershell execution | HackTool - CrackMapExec Execution Patterns | `rules/windows/process_creation/proc_creation_win_hktl_crackmapexec_execution_patterns.yml` | 0.52 | noni, nop, exec, bypass, powershell.exe, execution |
| `5003372` | [PASSWORDSTATE] Password Reset Failed | Password Reset By User Account | `rules/cloud/azure/audit_logs/azure_user_password_change.yml` | 0.52 | reset, password |
| `5005356` | [CLOUDTRAIL] AWS Config cloudtrail event detected - (De | AWS Config Disabling Channel/Recorder | `rules/cloud/aws/cloudtrail/aws_config_disable_recording.yml` | 0.52 | deletedeliverychannel, config, config.amazonaws.com, aws |
| `5005364` | [CLOUDTRAIL] AWS Config cloudtrail event detected - (St | AWS Config Disabling Channel/Recorder | `rules/cloud/aws/cloudtrail/aws_config_disable_recording.yml` | 0.52 | stopconfigurationrecorder, config, config.amazonaws.com, aws |
| `5007812` | [WINDOWS-SYSMON] Possible DLL Hijacking of dbgcore.dll | Network Connection Initiated To AzureWebsites.NET By No | `rules/windows/network_connection/net_connection_win_domain_azurewebsites.yml` | 0.52 | x86, program |
| `5002999` | [DYNAMIC] Rsync logs detected via program. | Suspicious Invocation of Shell via Rsync | `rules/linux/process_creation/proc_creation_lnx_rsync_shell_spawn.yml` | 0.52 | rsyncd, rsync |
| `5007341` | [SOPHOS] Malware detected | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.52 | endpoint, sophos, threat, malware |
| `5014328` | [WINDOWS-SECURITY] Suspicious CertUtil Command Detected | Suspicious Certutil Command Usage | `deprecated/windows/proc_creation_win_certutil_susp_execution.yml` | 0.52 | verifyctl, encode, urlcache, decode, certutil |
| `5017356` | [DYNAMIC] SentinelOne Logs Detected | Potential SentinelOne Shell Context Menu Scan Command T | `rules/windows/registry/registry_set/registry_set_sentinelone_shell_context_tampering.yml` | 0.52 | sentinelone |
| `5003365` | [PASSWORDSTATE] User Account Disabled | Login to Disabled Account | `rules/cloud/azure/signin_logs/azure_login_to_disabled_account.yml` | 0.52 | disabled |
| `5007813` | [WINDOWS-SYSMON] Possible DLL Hijacking of dbghelp.dll | DNS Query To AzureWebsites.NET By Non-Browser Process | `rules/windows/dns_query/dns_query_win_domain_azurewebsites.yml` | 0.52 | x86, program |
| `5010577` | [CISCO-SCA] New IP Scanner | Advanced IP Scanner - File Event | `rules/windows/file/file_event/file_event_win_advanced_ip_scanner.yml` | 0.52 | scanner |
| `5013532` | [WINDOWS-SYSMON] Possible MOVEit Exploitation (CVE-2023 | Potential MOVEit Transfer CVE-2023-34362 Exploitation - | `rules-emerging-threats/2023/Exploits/CVE-2023-34362-MOVEit-Transfer-Exploit/file_event_win_exploit_cve_2023_34362_moveit_transfer.yml` | 0.52 | moveit, cve-2023-34362, exploitation |
| `5009877` | [WINDOWS-SYSMON] Possible DLL Hijacking of dbgcore.dll | Network Connection Initiated To AzureWebsites.NET By No | `rules/windows/network_connection/net_connection_win_domain_azurewebsites.yml` | 0.52 | x86, program |
| `5015943` | [WINDOWS-SYSMON] Suspicious File Download Using MSHTA | Invoke-Obfuscation Via Use MSHTA - System | `rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_use_mshta_services.yml` | 0.52 | mshta |
| `5009292` | [WINDOWS-MISC] Event log has been cleared. | Security Eventlog Cleared | `rules/windows/builtin/security/win_security_audit_log_cleared.yml` | 0.52 | eventlog, cleared |
| `5014630` | [LINUX-AUDITD] File Overwrite using /dev/null or /dev/z | DD File Overwrite | `rules/linux/process_creation/proc_creation_lnx_dd_file_overwrite.yml` | 0.52 | dev/zero, overwrite, dev/null |
| `5100106` | Microsoft MSSQL server detected | MSSQL XPCmdshell Suspicious Execution | `rules/windows/builtin/application/mssqlserver/win_mssql_xp_cmdshell_audit_log.yml` | 0.52 | mssql |
| `5013533` | [WINDOWS-SYSMON] Human2.aspx File Created (CVE-2023-343 | MOVEit CVE-2023-34362 Exploitation Attempt - Potential | `rules-emerging-threats/2023/Exploits/CVE-2023-34362-MOVEit-Transfer-Exploit/web_cve_2023_34362_known_payload_request.yml.yml` | 0.52 | human2.aspx, cve-2023-34362 |
| `5015511` | [WINDOWS-SECURITY] Obfuscated IP address Added to Regis | Obfuscated IP Download Activity | `rules/windows/process_creation/proc_creation_win_susp_obfuscated_ip_download.yml` | 0.52 | 0-9, address, obfuscated |
| `5009878` | [WINDOWS-SYSMON] Possible DLL Hijacking of dbghelp.dll | DNS Query To AzureWebsites.NET By Non-Browser Process | `rules/windows/dns_query/dns_query_win_domain_azurewebsites.yml` | 0.52 | x86, program |
| `5001700` | [WEB-ATTACKS] UNION ALL SELECT in URL - Possible SQL In | SQL Injection Strings In URI | `rules/web/webserver_generic/web_sql_injection_in_access_logs.yml` | 0.52 | 20all, 20select, union, select, sql, injection |
| `5017336` | [DYNAMIC] Azure Eventhub Windows MSSQL Logs Detected | MSSQL Server Failed Logon | `rules/windows/builtin/application/mssqlserver/win_mssql_failed_logon.yml` | 0.51 | mssql |
| `5100186` | SentinelOne device detected | Potential SentinelOne Shell Context Menu Scan Command T | `rules/windows/registry/registry_set/registry_set_sentinelone_shell_context_tampering.yml` | 0.51 | sentinelone |
| `5013820` | [WINDOWS-SECURITY] Local PrivEsc via sc.exe | Stop Windows Service Via Sc.EXE | `rules/windows/process_creation/proc_creation_win_sc_stop_service.yml` | 0.51 | sc.exe |
| `5013576` | [WINDOWS-SYSTEM] The System log file was cleared | Security Event Log Cleared | `deprecated/windows/win_security_event_log_cleared.yml` | 0.51 | cleared |
| `5013577` | [WINDOWS-SYSTEM] The Application log file was cleared | Security Event Log Cleared | `deprecated/windows/win_security_event_log_cleared.yml` | 0.51 | cleared |
| `5002954` | [WINDOWS-MISC] Event log has been cleared. | Security Event Log Cleared | `deprecated/windows/win_security_event_log_cleared.yml` | 0.51 | cleared |
| `5006858` | [WINDOWS-MALWARE] Ruby ransomware file extension detect | Potential Ruby Reverse Shell | `rules/linux/process_creation/proc_creation_lnx_ruby_reverse_shell.yml` | 0.51 | ruby |
| `5007055` | [WINDOWS-MALWARE] Ruby ransomware file extension detect | Potential Ruby Reverse Shell | `rules/linux/process_creation/proc_creation_lnx_ruby_reverse_shell.yml` | 0.51 | ruby |
| `5008934` | [WINDOWS-MALWARE] Ruby ransomware file extension detect | Potential Ruby Reverse Shell | `rules/linux/process_creation/proc_creation_lnx_ruby_reverse_shell.yml` | 0.51 | ruby |
| `5009131` | [WINDOWS-MALWARE] Ruby ransomware file extension detect | Potential Ruby Reverse Shell | `rules/linux/process_creation/proc_creation_lnx_ruby_reverse_shell.yml` | 0.51 | ruby |
| `5000004` | [BASH] /etc/passwd access | Symlink Etc Passwd | `rules/linux/builtin/lnx_symlink_etc_passwd.yml` | 0.51 | etc/passwd |
| `5017705` | [CROWDSTRIKE] Possible Privilege Escalation Detected - | Azure Service Principal Created | `rules/cloud/azure/audit_logs/azure_service_principal_created.yml` | 0.51 | principal, azure |
| `5014312` | [DYNAMIC] JAMF Protect logs detected via program. | JAMF MDM Potential Suspicious Child Process | `rules/macos/process_creation/proc_creation_macos_jamf_susp_child.yml` | 0.51 | jamf |
| `5015943` | [WINDOWS-SYSMON] Suspicious File Download Using MSHTA | Invoke-Obfuscation Via Use MSHTA - Security | `rules/windows/builtin/security/win_security_invoke_obfuscation_via_use_mshta_services_security.yml` | 0.51 | mshta, security |
| `5017578` | [CROWDSTRIKE] Suspicious Execution Detected - Procdump | Potential SysInternals ProcDump Evasion | `rules/windows/process_creation/proc_creation_win_sysinternals_procdump_evasion.yml` | 0.51 | procdump, lsass, dump |
| `5002616` | [SONICWALL] Firewall Rule Modified | Azure Firewall Modified or Deleted | `rules/cloud/azure/activity_logs/azure_firewall_modified_or_deleted.yml` | 0.51 | modified, firewall |
| `5002320` | [BASH] ksh shell execution | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.51 | bash, shell |
| `5002322` | [BASH] zsh shell execution | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.51 | bash, shell |
| `5007828` | [WINDOWS-SYSMON] Possible DLL Hijacking of dismcore.dll | UAC Bypass With Fake DLL | `rules/windows/image_load/image_load_uac_bypass_via_dism.yml` | 0.51 | dismcore.dll, dll |
| `5014183` | [MSAPI-SECURITYCOMPLIANCECENTER] Alert Entity Generated | Microsoft 365 - User Restricted from Sending Email | `rules/cloud/m365/threat_management/microsoft365_user_restricted_from_sending_email.yml` | 0.51 | sending, securitycompliancecenter, exceeded, email |
| `5009893` | [WINDOWS-SYSMON] Possible DLL Hijacking of dismcore.dll | UAC Bypass With Fake DLL | `rules/windows/image_load/image_load_uac_bypass_via_dism.yml` | 0.51 | dismcore.dll, dll |
| `5007809` | [WINDOWS-SYSMON] Possible DLL Hijacking of d3dcompiler_ | DNS Query To AzureWebsites.NET By Non-Browser Process | `rules/windows/dns_query/dns_query_win_domain_azurewebsites.yml` | 0.51 | x86, program |
| `5003346` | [PASSWORDSTATE] Password Reset Task Deleted | Password Reset By User Account | `rules/cloud/azure/audit_logs/azure_user_password_change.yml` | 0.51 | reset, password |
| `5002319` | [BASH] csh shell execution | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.51 | bash, shell |
| `5009874` | [WINDOWS-SYSMON] Possible DLL Hijacking of d3dcompiler_ | DNS Query To AzureWebsites.NET By Non-Browser Process | `rules/windows/dns_query/dns_query_win_domain_azurewebsites.yml` | 0.51 | x86, program |
| `5015071` | [WINDOWS-SECURITY] Impacket PsExec Named PIPE | PUA - RemCom Default Named Pipe | `rules/windows/pipe_created/pipe_created_pua_remcom_default_pipe.yml` | 0.50 | remcom, pipe, named |
| `5005649` | [LINUX-AUDITD] wget execution | Data Exfiltration with Wget | `rules/linux/auditd/execve/lnx_auditd_data_exfil_wget.yml` | 0.50 | wget, execve |
| `5013876` | [WINDOWS-SECURITY] Credential Access - Copy NTDS file | Copy From VolumeShadowCopy Via Cmd.EXE | `rules/windows/process_creation/proc_creation_win_cmd_shadowcopy_access.yml` | 0.50 | copy |
| `5009292` | [WINDOWS-MISC] Event log has been cleared. | Security Event Log Cleared | `deprecated/windows/win_security_event_log_cleared.yml` | 0.50 | cleared |
| `5013820` | [WINDOWS-SECURITY] Local PrivEsc via sc.exe | Service DACL Abuse To Hide Services Via Sc.EXE | `rules/windows/process_creation/proc_creation_win_sc_sdset_hide_sevices.yml` | 0.50 | sdset, sc.exe |
| `5002982` | [DYNAMIC] Linux kernel logs detected via program. | New Kernel Driver Via SC.EXE | `rules/windows/process_creation/proc_creation_win_sc_new_kernel_driver.yml` | 0.50 | kernel |
| `5010948` | [GITHUB] Member Invited | New Github Organization Member Added | `rules/application/github/audit/github_new_org_member.yml` | 0.50 | invited, member, github |
| `5008381` | [WINDOWS-CLIPBOARD] bitsadmin file transfer command | File Download Via Bitsadmin | `rules/windows/process_creation/proc_creation_win_bitsadmin_download.yml` | 0.50 | bitsadmin, transfer |
| `5003417` | [WINDOWS-SECURITY] Certificate Services revoked a certi | Certificate Exported From Local Certificate Store | `rules/windows/builtin/certificate_services_client_lifecycle_system/win_certificateservicesclient_lifecycle_system_cert_exported.yml` | 0.50 | certificate |
| `5013816` | [WINDOWS-SECURITY] AnyDesk Remote management Software S | Anydesk Remote Access Software Service Installation | `rules/windows/builtin/system/service_control_manager/win_system_service_install_anydesk.yml` | 0.50 | anydesk, software, remote |
| `5008652` | [WINDOWS-CLIPBOARD] bitsadmin file transfer command | File Download Via Bitsadmin | `rules/windows/process_creation/proc_creation_win_bitsadmin_download.yml` | 0.50 | bitsadmin, transfer |
| `5000006` | [BASH] make execution | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.50 | bash, execution |
| `5000007` | [BASH] make execution | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.50 | bash, execution |
| `5002668` | [SONICWALL] Guest account disabled | Login to Disabled Account | `rules/cloud/azure/signin_logs/azure_login_to_disabled_account.yml` | 0.50 | disabled |
| `5008357` | [WINDOWS-SECURITY] A service was installed in the syste | PowerShell Scripts Installed as Services | `rules/windows/builtin/system/service_control_manager/win_system_powershell_script_installed_as_service.yml` | 0.50 | installed, powershell |

## Conceptual candidate, weaker lexical match (review) (1169)

A weaker lexical similarity, near the floor. A candidate to skim, most useful read alongside its shared terms.

| Sagan SID | Converted rule | SigmaHQ rule | SigmaHQ path | Lexical | Shared terms |
| --- | --- | --- | --- | ---: | --- |
| `5007812` | [WINDOWS-SYSMON] Possible DLL Hijacking of dbgcore.dll | DNS Query To AzureWebsites.NET By Non-Browser Process | `rules/windows/dns_query/dns_query_win_domain_azurewebsites.yml` | 0.50 | x86, program |
| `5013898` | [WINDOWS-SECURITY] Powershell Get-Process | PowerShell Get-Process LSASS | `rules/windows/process_creation/proc_creation_win_powershell_getprocess_lsass.yml` | 0.50 | get-process, powershell |
| `5013899` | [WINDOWS-SECURITY] Query for WinDefend | Disable Windows Defender AV Security Monitoring | `rules/windows/process_creation/proc_creation_win_powershell_disable_defender_av_security_monitoring.yml` | 0.50 | windefend, security |
| `5007813` | [WINDOWS-SYSMON] Possible DLL Hijacking of dbghelp.dll | New Connection Initiated To Potential Dead Drop Resolve | `rules/windows/network_connection/net_connection_win_domain_dead_drop_resolvers.yml` | 0.50 | x86, program |
| `5010825` | [CyberArk] Delete Folder (Has Locked Files) | OneLogin User Account Locked | `rules/identity/onelogin/onelogin_user_account_locked.yml` | 0.50 | locked |
| `5007341` | [SOPHOS] Malware detected | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.50 | endpoint, sophos |
| `5002321` | [BASH] tcsh shell execution | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.50 | bash, shell |
| `5007145` | [WINDOWS-POWERSHELL] Registry Query for WDigest UseLogo | Wdigest Enable UseLogonCredential | `rules/windows/registry/registry_set/registry_set_wdigest_enable_uselogoncredential.yml` | 0.50 | uselogoncredential, wdigest, hklm |
| `5014227` | [CROWDSTRIKE] A suspicious process disabled Windows Def | Windows Defender Threat Detection Service Disabled | `rules/windows/builtin/system/service_control_manager/win_system_defender_disabled.yml` | 0.50 | disabled, defender |
| `5015072` | [WINDOWS-SECURITY] Atera Removal via msiexec | MsiExec Web Install | `rules/windows/process_creation/proc_creation_win_msiexec_web_install.yml` | 0.50 | msiexec |
| `5005650` | [LINUX-AUDITD] curl execution | Suspicious Curl Change User Agents - Linux | `rules/linux/process_creation/proc_creation_lnx_susp_curl_useragent.yml` | 0.50 | curl |
| `5001830` | [WEB-ATTACKS] WITOOL SQL Injection Scan | SQL Injection Strings In URI | `rules/web/webserver_generic/web_sql_injection_in_access_logs.yml` | 0.50 | union, select, sql, injection |
| `5009878` | [WINDOWS-SYSMON] Possible DLL Hijacking of dbghelp.dll | New Connection Initiated To Potential Dead Drop Resolve | `rules/windows/network_connection/net_connection_win_domain_dead_drop_resolvers.yml` | 0.50 | x86, program |
| `5009877` | [WINDOWS-SYSMON] Possible DLL Hijacking of dbgcore.dll | DNS Query To AzureWebsites.NET By Non-Browser Process | `rules/windows/dns_query/dns_query_win_domain_azurewebsites.yml` | 0.50 | x86, program |
| `5002320` | [BASH] ksh shell execution | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.50 | bash, shell, execution |
| `5002322` | [BASH] zsh shell execution | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.50 | bash, shell, execution |
| `5009358` | [WINDOWS-POWERSHELL] Registry Query for WDigest UseLogo | Wdigest Enable UseLogonCredential | `rules/windows/registry/registry_set/registry_set_wdigest_enable_uselogoncredential.yml` | 0.50 | uselogoncredential, wdigest, hklm |
| `5013923` | [WINDOWS-SECURITY] Copy from a remote host | Copy From Or To Admin Share Or Sysvol Folder | `rules/windows/process_creation/proc_creation_win_susp_copy_lateral_movement.yml` | 0.50 | copy, cmd.exe, remote |
| `9870004` | [EXPERIMENTAL][WINDOWS-SECURITY] SMB - Anonymous Access | Access To ADMIN$ Network Share | `rules/windows/builtin/security/win_security_admin_share_access.yml` | 0.50 | share, admin |
| `5009413` | [WINDOWS-SECURITY] Certificate Services revoked a certi | Certificate Exported From Local Certificate Store | `rules/windows/builtin/certificate_services_client_lifecycle_system/win_certificateservicesclient_lifecycle_system_cert_exported.yml` | 0.50 | certificate |
| `5007664` | [DYNAMIC] windows applocker logs detected via program. | AppLocker Application Would Have Been Blocked | `rules/windows/builtin/applocker/win_applocker_application_would_have_been_blocked.yml` | 0.50 | applocker |
| `5000006` | [BASH] make execution | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.49 | bash |
| `5000007` | [BASH] make execution | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.49 | bash |
| `5005751` | [WINDOWS-POWERSHELL] Powershell created local user [1/3 | PowerShell Create Local User | `rules/windows/powershell/powershell_script/posh_ps_create_local_user.yml` | 0.49 | new-localuser, local, powershell |
| `5005278` | [MS-DEFENDER] Real-Time Protection Is Disabled | Windows Defender Real-Time Protection Failure/Restart | `rules/windows/builtin/windefend/win_defender_real_time_protection_errors.yml` | 0.49 | real-time, protection |
| `5002319` | [BASH] csh shell execution | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.49 | bash, shell, execution |
| `5003417` | [WINDOWS-SECURITY] Certificate Services revoked a certi | CodeIntegrity - Blocked Driver Load With Revoked Certif | `rules/windows/builtin/code_integrity/win_codeintegrity_revoked_driver_blocked.yml` | 0.49 | revoked, certificate |
| `5100019` | Generic crond detected | New Cron File Created | `rules/linux/file_event/file_event_lnx_susp_cron_file_created.yml` | 0.49 | cron |
| `5008358` | [WINDOWS-SECURITY] A service was installed in the syste | Rundll32.EXE Calling DllRegisterServer Export Function | `rules-threat-hunting/windows/process_creation/proc_creation_win_rundll32_dllregisterserver.yml` | 0.49 | dllregisterserver, rundll32 |
| `5008380` | [WINDOWS-CLIPBOARD] copy from share drive to local C: c | Copy From VolumeShadowCopy Via Cmd.EXE | `rules/windows/process_creation/proc_creation_win_cmd_shadowcopy_access.yml` | 0.49 | copy |
| `5005649` | [LINUX-AUDITD] wget execution | Download File To Potentially Suspicious Directory Via W | `rules/linux/process_creation/proc_creation_lnx_wget_download_suspicious_directory.yml` | 0.49 | wget |
| `5010562` | [CISCO-SCA] Internal Port Scanner | Renamed PingCastle Binary Execution | `rules/windows/process_creation/proc_creation_win_renamed_pingcastle.yml` | 0.49 | scanner |
| `5016037` | [CISCO-MERAKI] Device Configuration Change Detected | Azure Device or Configuration Modified or Deleted | `rules/cloud/azure/activity_logs/azure_device_or_configuration_modified_or_deleted.yml` | 0.49 | configuration, device |
| `5008449` | [WINDOWS-AUTH] A member was added to a security-enabled | A Member Was Removed From a Security-Enabled Global Gro | `rules/windows/builtin/security/account_management/win_security_member_removed_security_enabled_global_group.yml` | 0.49 | security-enabled, member, group |
| `5009309` | [WINDOWS-POWERSHELL] Powershell created local user [1/3 | PowerShell Create Local User | `rules/windows/powershell/powershell_script/posh_ps_create_local_user.yml` | 0.49 | new-localuser, local, powershell |
| `5009773` | [WINDOWS-SECURITY] A service was installed in the syste | PowerShell Scripts Installed as Services | `rules/windows/builtin/system/service_control_manager/win_system_powershell_script_installed_as_service.yml` | 0.49 | installed, powershell |
| `5006885` | [WINDOWS-MALWARE] Bart ransomware file extension detect | Perl Inline Command Execution | `rules/windows/process_creation/proc_creation_win_perl_inline_command_execution.yml` | 0.49 | perl |
| `5007092` | [WINDOWS-MALWARE] Bart ransomware file extension detect | Perl Inline Command Execution | `rules/windows/process_creation/proc_creation_win_perl_inline_command_execution.yml` | 0.49 | perl |
| `5008651` | [WINDOWS-CLIPBOARD] copy from share drive to local C: c | Copy From VolumeShadowCopy Via Cmd.EXE | `rules/windows/process_creation/proc_creation_win_cmd_shadowcopy_access.yml` | 0.49 | copy |
| `5008961` | [WINDOWS-MALWARE] Bart ransomware file extension detect | Perl Inline Command Execution | `rules/windows/process_creation/proc_creation_win_perl_inline_command_execution.yml` | 0.49 | perl |
| `5009168` | [WINDOWS-MALWARE] Bart ransomware file extension detect | Perl Inline Command Execution | `rules/windows/process_creation/proc_creation_win_perl_inline_command_execution.yml` | 0.49 | perl |
| `5100128` | SNMP service detected | OpenCanary - SNMP OID Request | `rules/application/opencanary/opencanary_snmp_cmd.yml` | 0.49 | snmp |
| `5013729` | Apache PHP device detected | Php Inline Command Execution | `rules/windows/process_creation/proc_creation_win_php_inline_command_execution.yml` | 0.49 | php |
| `5007155` | [WINDOWS-POWERSHELL] Cmdlet Scheduled Task Created | Powershell Create Scheduled Task | `rules/windows/powershell/powershell_script/posh_ps_cmdlet_scheduled_task.yml` | 0.49 | new-scheduledtask, ps_scheduledtask, register-scheduledtask, classname |
| `5015943` | [WINDOWS-SYSMON] Suspicious File Download Using MSHTA | Invoke-Obfuscation Via Use MSHTA | `rules/windows/process_creation/proc_creation_win_hktl_invoke_obfuscation_via_use_mhsta.yml` | 0.49 | mshta |
| `991001` | [AWS] AWS ConsoleLogin | AWS ConsoleLogin Failed Authentication | `rules/cloud/aws/cloudtrail/aws_cloudtrail_console_login_failed_authentication.yml` | 0.49 | consolelogin, aws |
| `5007143` | [WINDOWS-POWERSHELL] Suspicious FromBase64String Encode | Potential CVE-2023-36884 Exploitation - Share Access | `rules-emerging-threats/2023/Exploits/CVE-2023-36884/win_security_exploit_cve_2023_36884_office_windows_html_rce_share_access_pattern.yml` | 0.49 | 0-9 |
| `5000385` | [BASH] iptables command access | Interactive Bash Suspicious Children | `rules/linux/process_creation/proc_creation_lnx_susp_interactive_bash.yml` | 0.49 | iptables, bash |
| `5009774` | [WINDOWS-SECURITY] A service was installed in the syste | Rundll32.EXE Calling DllRegisterServer Export Function | `rules-threat-hunting/windows/process_creation/proc_creation_win_rundll32_dllregisterserver.yml` | 0.49 | dllregisterserver, rundll32 |
| `5100041` | rsync client execution | Suspicious Invocation of Shell via Rsync | `rules/linux/process_creation/proc_creation_lnx_rsync_shell_spawn.yml` | 0.49 | rsync, execution |
| `5009368` | [WINDOWS-POWERSHELL] Cmdlet Scheduled Task Created | Powershell Create Scheduled Task | `rules/windows/powershell/powershell_script/posh_ps_cmdlet_scheduled_task.yml` | 0.49 | new-scheduledtask, ps_scheduledtask, register-scheduledtask, classname |
| `5017576` | [CROWDSTRIKE] Suspicious Execution - Blocked: Procdump | Potential SysInternals ProcDump Evasion | `rules/windows/process_creation/proc_creation_win_sysinternals_procdump_evasion.yml` | 0.49 | procdump, lsass, dump |
| `5002328` | [BASH] SSH remote forwarding | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.49 | bash |
| `5017705` | [CROWDSTRIKE] Possible Privilege Escalation Detected - | Azure Service Principal Removed | `rules/cloud/azure/audit_logs/azure_service_principal_removed.yml` | 0.49 | principal, azure |
| `5009413` | [WINDOWS-SECURITY] Certificate Services revoked a certi | CodeIntegrity - Blocked Driver Load With Revoked Certif | `rules/windows/builtin/code_integrity/win_codeintegrity_revoked_driver_blocked.yml` | 0.49 | revoked, certificate |
| `5002325` | [BASH] SSH dynamic forwarding | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.49 | bash |
| `5007809` | [WINDOWS-SYSMON] Possible DLL Hijacking of d3dcompiler_ | New Connection Initiated To Potential Dead Drop Resolve | `rules/windows/network_connection/net_connection_win_domain_dead_drop_resolvers.yml` | 0.49 | x86, program |
| `5017397` | [WINDOWS-SECURITY] Use Of LOLBIN Detected - wlrmdr.exe | Wlrmdr.EXE Uncommon Argument Or Child Process | `rules/windows/process_creation/proc_creation_win_wlrmdr_uncommon_child_process.yml` | 0.49 | wlrmdr.exe |
| `5010562` | [CISCO-SCA] Internal Port Scanner | PUA - PingCastle Execution From Potentially Suspicious | `rules/windows/process_creation/proc_creation_win_pua_pingcastle_script_parent.yml` | 0.49 | scanner |
| `5003105` | [WINDOWS-MISC] CRITICAL - Installation of PSEXEC servic | PsExec Service Installation | `rules/windows/builtin/system/service_control_manager/win_system_service_install_sysinternals_psexec.yml` | 0.49 | psexesvc, psexec, installation |
| `5005277` | [MS-DEFENDER] Real-Time Protection Is Enabled | Windows Defender Real-Time Protection Failure/Restart | `rules/windows/builtin/windefend/win_defender_real_time_protection_errors.yml` | 0.49 | real-time, protection |
| `5007746` | [WINDOWS-SYSMON] Possible DLL Hijacking of tosbtkbd.dll | Third Party Software DLL Sideloading | `rules/windows/image_load/image_load_side_load_third_party.yml` | 0.49 | tosbtkbd.dll, toshiba, stack, x86, program, dll |
| `5002321` | [BASH] tcsh shell execution | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.49 | bash, shell, execution |
| `5009874` | [WINDOWS-SYSMON] Possible DLL Hijacking of d3dcompiler_ | New Connection Initiated To Potential Dead Drop Resolve | `rules/windows/network_connection/net_connection_win_domain_dead_drop_resolvers.yml` | 0.49 | x86, program |
| `5009811` | [WINDOWS-SYSMON] Possible DLL Hijacking of tosbtkbd.dll | Third Party Software DLL Sideloading | `rules/windows/image_load/image_load_side_load_third_party.yml` | 0.49 | tosbtkbd.dll, toshiba, stack, x86, program, dll |
| `5013803` | [WINDOWS-SYSMON] WinWord created .vbs file | Potential Arbitrary DLL Load Using Winword | `rules/windows/process_creation/proc_creation_win_office_winword_dll_load.yml` | 0.49 | winword, winword.exe |
| `5002327` | [BASH] SSH local forwarding | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.49 | bash |
| `5014227` | [CROWDSTRIKE] A suspicious process disabled Windows Def | Windows Defender Threat Detection Disabled | `deprecated/windows/win_defender_disabled.yml` | 0.48 | disabled, defender |
| `5010947` | [GITHUB] Member Added | New Github Organization Member Added | `rules/application/github/audit/github_new_org_member.yml` | 0.48 | member, github, added |
| `5002324` | [BASH] SSH agent forwarding | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.48 | bash |
| `5000971` | [FORTINET] Admin changed another admin's password | Access To ADMIN$ Network Share | `rules/windows/builtin/security/win_security_admin_share_access.yml` | 0.48 | admin |
| `5007690` | [WINDOWS-POWERSHELL] Possible nslookup command stager | Nslookup PowerShell Download Cradle - ProcessCreation | `rules/windows/process_creation/proc_creation_win_nslookup_poweshell_download.yml` | 0.48 | nslookup, txt, powershell |
| `5015941` | [WINDOWS-SYSMON] Cobalt Strike Beacon Detected | Potential CobaltStrike Process Patterns | `rules/windows/process_creation/proc_creation_win_hktl_cobaltstrike_process_patterns.yml` | 0.48 | beacon, strike, cobalt, echo, pipe, cmd.exe |
| `5016043` | [UBIQUITI] Admin Activity - Admin Accessed UniFi Networ | Access To ADMIN$ Network Share | `rules/windows/builtin/security/win_security_admin_share_access.yml` | 0.48 | admin, network |
| `5017396` | [WINDOWS-SECURITY] Hidden Scheduled Task Created - Crit | Suspicious PowerShell Invocations - Generic | `deprecated/windows/powershell_suspicious_invocation_generic.yml` | 0.48 | hidden |
| `5017396` | [WINDOWS-SECURITY] Hidden Scheduled Task Created - Crit | Suspicious PowerShell Invocations - Generic | `rules/windows/powershell/powershell_script/posh_ps_susp_invocation_generic.yml` | 0.48 | hidden |
| `5009772` | [WINDOWS-SECURITY] Exfil software rclone detected | Rclone Activity via Proxy | `rules/web/proxy_generic/proxy_ua_rclone.yml` | 0.48 | rclone |
| `5002329` | [BASH] SSH input and output forwarding | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.48 | input, bash |
| `5005344` | [CLOUDTRAIL] IAM cloudtrail event detected - (UpdateLog | AWS User Login Profile Was Modified | `rules/cloud/aws/cloudtrail/aws_update_login_profile.yml` | 0.48 | updateloginprofile, iam.amazonaws.com, iam |
| `5007812` | [WINDOWS-SYSMON] Possible DLL Hijacking of dbgcore.dll | New Connection Initiated To Potential Dead Drop Resolve | `rules/windows/network_connection/net_connection_win_domain_dead_drop_resolvers.yml` | 0.48 | x86, program |
| `5002328` | [BASH] SSH remote forwarding | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.48 | bash |
| `5003134` | [ZSCALER] Win.Trojan.Darkcpn outbound connection | APT User Agent | `rules/web/proxy_generic/proxy_ua_apt.yml` | 0.48 | 2.0.50727, sv1, 6.0, 5.1, mozilla/4.0, msie |
| `5004779` | [WINDOWS-MALWARE] Suspicious Powershell execution | HackTool - Empire PowerShell Launch Parameters | `rules/windows/process_creation/proc_creation_win_hktl_empire_powershell_launch.yml` | 0.48 | noni, nop, exec, hidden, bypass, powershell |
| `5005650` | [LINUX-AUDITD] curl execution | Curl Usage on Linux | `rules/linux/process_creation/proc_creation_lnx_curl_usage.yml` | 0.48 | curl |
| `5008779` | [WINDOWS-MALWARE] Suspicious Powershell execution | HackTool - Empire PowerShell Launch Parameters | `rules/windows/process_creation/proc_creation_win_hktl_empire_powershell_launch.yml` | 0.48 | noni, nop, exec, hidden, bypass, powershell |
| `5013802` | [WINDOWS-SYSMON] WinWord created ps1 file | Potential Arbitrary DLL Load Using Winword | `rules/windows/process_creation/proc_creation_win_office_winword_dll_load.yml` | 0.48 | winword, winword.exe |
| `5000002` | [BASH] telnet execution | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.48 | bash, execution |
| `5002325` | [BASH] SSH dynamic forwarding | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.48 | bash |
| `5009371` | [WINDOWS-POWERSHELL] Possible nslookup command stager | Nslookup PowerShell Download Cradle - ProcessCreation | `rules/windows/process_creation/proc_creation_win_nslookup_poweshell_download.yml` | 0.48 | nslookup, txt, powershell |
| `5013914` | [WINDOWS-SECURITY] Suspicious netsh PortProxy Command D | New Port Forwarding Rule Added Via Netsh.EXE | `rules/windows/process_creation/proc_creation_win_netsh_port_forwarding.yml` | 0.48 | v4tov4, portproxy, netsh, interface, add |
| `5014407` | [FORTINET] Admin changed another admin's password | Access To ADMIN$ Network Share | `rules/windows/builtin/security/win_security_admin_share_access.yml` | 0.48 | admin |
| `5100125` | Applocker detected | AppLocker Prevented Application or Script from Running | `rules/windows/builtin/applocker/win_applocker_application_was_prevented_from_running.yml` | 0.48 | applocker |
| `5009877` | [WINDOWS-SYSMON] Possible DLL Hijacking of dbgcore.dll | New Connection Initiated To Potential Dead Drop Resolve | `rules/windows/network_connection/net_connection_win_domain_dead_drop_resolvers.yml` | 0.48 | x86, program |
| `5002327` | [BASH] SSH local forwarding | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.48 | bash |
| `5002330` | [BASH] SSH tunnel forwarding | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.48 | bash |
| `5002615` | [SONICWALL] Firewall Rule Deleted | All Rules Have Been Deleted From The Windows Firewall C | `rules/windows/builtin/firewall_as/win_firewall_as_delete_all_rules.yml` | 0.48 | firewall, deleted |
| `5010525` | [CISCO-SCA] Azure Firewall Deleted | Azure Firewall Modified or Deleted | `rules/cloud/azure/activity_logs/azure_firewall_modified_or_deleted.yml` | 0.48 | firewall, azure, deleted |
| `5010559` | [CISCO-SCA] Inbound Port Scanner | Renamed PingCastle Binary Execution | `rules/windows/process_creation/proc_creation_win_renamed_pingcastle.yml` | 0.48 | scanner |
| `5017721` | [SOPHOS_FIREWALL] Firewall Rule Added to Configuration | All Rules Have Been Deleted From The Windows Firewall C | `rules/windows/builtin/firewall_as/win_firewall_as_delete_all_rules.yml` | 0.48 | firewall, configuration |
| `5002324` | [BASH] SSH agent forwarding | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.48 | bash |
| `5005650` | [LINUX-AUDITD] curl execution | Curl Download And Execute Combination | `rules/windows/process_creation/proc_creation_win_cmd_curl_download_exec_combo.yml` | 0.48 | curl |
| `5000001` | [BASH] gcc execution | Shell Execution GCC  - Linux | `rules/linux/process_creation/proc_creation_lnx_gcc_shell_execution.yml` | 0.47 | gcc, execution |
| `5008384` | [DYNAMIC] windows clipboard logs detected via program. | Clipboard Access Via OSAScript | `rules/macos/process_creation/proc_creation_macos_clipboard_access_via_osascript.yml` | 0.47 | clipboard |
| `5005974` | [SYSTEMD] Service Failed | Systemd Service Creation | `rules/linux/auditd/path/lnx_auditd_systemd_service_creation.yml` | 0.47 | systemd |
| `5000002` | [BASH] telnet execution | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.47 | bash |
| `5009295` | [WINDOWS-MISC] Installation of PSEXEC service via Secur | PsExec Service Start | `deprecated/windows/proc_creation_win_sysinternals_psexesvc_start.yml` | 0.47 | psexec |
| `5014227` | [CROWDSTRIKE] A suspicious process disabled Windows Def | Login to Disabled Account | `rules/cloud/azure/signin_logs/azure_login_to_disabled_account.yml` | 0.47 | disabled |
| `5010514` | [CISCO-SCA] AWS Lambda Persistence | AWS New Lambda Layer Attached | `rules/cloud/aws/cloudtrail/aws_new_lambda_layer_attached.yml` | 0.47 | lambda, aws |
| `5003374` | [PASSWORDSTATE] Password Reset Task Updated | Password Reset By User Account | `rules/cloud/azure/audit_logs/azure_user_password_change.yml` | 0.47 | reset, password |
| `5010508` | [CISCO-SCA] AWS EC2 Startup Script Modified | AWS EC2 Startup Shell Script Change | `rules/cloud/aws/cloudtrail/aws_ec2_startup_script_change.yml` | 0.47 | startup, ec2, script, aws |
| `5000008` | [BASH] /bin/sh command line call | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.47 | bash |
| `5000003` | [BASH] nmap execution | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.47 | bash, execution |
| `5002571` | [CYLANCE] Device - Action Taken | Azure Device or Configuration Modified or Deleted | `rules/cloud/azure/activity_logs/azure_device_or_configuration_modified_or_deleted.yml` | 0.47 | device |
| `5013817` | [WINDOWS-SECURITY] Remote Access Software Installed as | Remote Access Tool - Anydesk Execution From Suspicious | `rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk_susp_exec.yml` | 0.47 | anydesk, software, remote |
| `5005283` | [MS-DEFENDER] Scanning For Malware is Disabled | Windows Defender Malware And PUA Scanning Disabled | `rules/windows/builtin/windefend/win_defender_malware_and_pua_scan_disabled.yml` | 0.47 | scanning, disabled, malware |
| `5000006` | [BASH] make execution | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.47 | bash, execution |
| `5000007` | [BASH] make execution | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.47 | bash, execution |
| `5010615` | [CISCO-SCA] Suspicious DNS Over HTTPS Activity | Potentially Suspicious Regsvr32 HTTP IP Pattern | `rules/windows/process_creation/proc_creation_win_regsvr32_http_ip_pattern.yml` | 0.47 | https |
| `5008380` | [WINDOWS-CLIPBOARD] copy from share drive to local C: c | Copy .DMP/.DUMP Files From Remote Share Via Cmd.EXE | `rules/windows/process_creation/proc_creation_win_cmd_copy_dmp_from_share.yml` | 0.47 | share, copy |
| `5002701` | [SONICWALL] Intrusion Detection - Probable TCP XMAS sca | OpenCanary - NMAP XMAS Scan | `rules/application/opencanary/opencanary_portscan_nmap_xmas_scan.yml` | 0.47 | xmas, scan |
| `5010863` | [CyberArk] Add Privileged Command | Privileged Account Creation | `rules/cloud/azure/audit_logs/azure_privileged_account_creation.yml` | 0.47 | privileged, add |
| `5002330` | [BASH] SSH tunnel forwarding | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.47 | bash |
| `5008381` | [WINDOWS-CLIPBOARD] bitsadmin file transfer command | Suspicious Download From Direct IP Via Bitsadmin | `rules/windows/process_creation/proc_creation_win_bitsadmin_download_direct_ip.yml` | 0.47 | bitsadmin, transfer |
| `5010559` | [CISCO-SCA] Inbound Port Scanner | PUA - PingCastle Execution From Potentially Suspicious | `rules/windows/process_creation/proc_creation_win_pua_pingcastle_script_parent.yml` | 0.47 | scanner |
| `5010562` | [CISCO-SCA] Internal Port Scanner | PUA - Advanced Port Scanner Execution | `rules/windows/process_creation/proc_creation_win_pua_advanced_port_scanner.yml` | 0.47 | scanner, port |
| `5000385` | [BASH] iptables command access | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.47 | bash |
| `5010516` | [CISCO-SCA] AWS Multifactor Authentication Change | Multifactor Authentication Interrupted | `rules/cloud/azure/signin_logs/azure_mfa_interrupted.yml` | 0.47 | multifactor, authentication |
| `5008651` | [WINDOWS-CLIPBOARD] copy from share drive to local C: c | Copy .DMP/.DUMP Files From Remote Share Via Cmd.EXE | `rules/windows/process_creation/proc_creation_win_cmd_copy_dmp_from_share.yml` | 0.47 | share, copy |
| `5007740` | [WINDOWS-SYSMON] Possible DLL Hijacking of chrome_frame | Potential Chrome Frame Helper DLL Sideloading | `rules/windows/image_load/image_load_side_load_chrome_frame_helper.yml` | 0.47 | chrome_frame_helper.dll, x86, program, dll |
| `5008652` | [WINDOWS-CLIPBOARD] bitsadmin file transfer command | Suspicious Download From Direct IP Via Bitsadmin | `rules/windows/process_creation/proc_creation_win_bitsadmin_download_direct_ip.yml` | 0.47 | bitsadmin, transfer |
| `5009805` | [WINDOWS-SYSMON] Possible DLL Hijacking of chrome_frame | Potential Chrome Frame Helper DLL Sideloading | `rules/windows/image_load/image_load_side_load_chrome_frame_helper.yml` | 0.47 | chrome_frame_helper.dll, x86, program, dll |
| `5014645` | [MSAPI-AZUREAD] Security Operator role assigned to Memb | App Assigned To Azure RBAC/Microsoft Entra Role | `rules/cloud/azure/audit_logs/azure_app_role_added.yml` | 0.47 | assigned, member, role, add |
| `5000003` | [BASH] nmap execution | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.47 | bash |
| `5015968` | [WINDOWS-SYSMON] Process Hacker Kernel Driver Load | PUA - Process Hacker Driver Load | `rules/windows/driver_load/driver_load_win_pua_process_hacker.yml` | 0.47 | kprocesshacker.sys, hacker, driver, load |
| `5015972` | [WINDOWS-SYSMON] Process Hacker Kernel Driver Load | PUA - Process Hacker Driver Load | `rules/windows/driver_load/driver_load_win_pua_process_hacker.yml` | 0.47 | kprocesshacker.sys, hacker, driver, load |
| `5008564` | [WINDOWS-AUTH] User added to Local Administrators group | User Added to Local Administrator Group | `rules/windows/builtin/security/win_security_user_added_to_local_administrators.yml` | 0.47 | s-1-5-32-544, added, local, group |
| `5000008` | [BASH] /bin/sh command line call | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.47 | bash |
| `5000122` | [SYSLOG] Physical root login | AWS Root Credentials | `rules/cloud/aws/cloudtrail/aws_root_account_usage.yml` | 0.47 | root |
| `5003416` | [WINDOWS-SECURITY] The certificate manager denied a pen | Active Directory Certificate Services Denied Certificat | `rules/windows/builtin/system/microsoft_windows_certification_authority/win_system_adcs_enrollment_request_denied.yml` | 0.47 | denied, certificate, request |
| `5013839` | [WINDOWS-SECURITY] PowerTool process started | HackTool - PowerTool Execution | `rules/windows/process_creation/proc_creation_win_hktl_powertool.yml` | 0.47 | powertool, powertool64.exe |
| `5003420` | [WINDOWS-SECURITY] The certificate manager settings for | Certificate Exported From Local Certificate Store | `rules/windows/builtin/certificate_services_client_lifecycle_system/win_certificateservicesclient_lifecycle_system_cert_exported.yml` | 0.47 | certificate |
| `5002331` | [BASH] SSH X11 forwarding | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.47 | bash |
| `5012725` | [MSEXCHANGE-MANAGEMENT] mailboxes Cmdlet Set-Mailbox Su | Suspicious PowerShell Mailbox SMTP Forward Rule | `deprecated/windows/posh_ps_exchange_mailbox_smpt_forwarding_rule.yml` | 0.46 | set-mailbox, cmdlet |
| `5009280` | [WINDOWS-MISC] Windows audit log was cleared | Security Eventlog Cleared | `rules/windows/builtin/security/win_security_audit_log_cleared.yml` | 0.46 | eventlog, cleared, security |
| `5000009` | [BASH] /bin/bash command line call | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.46 | bash |
| `5017577` | [CROWDSTRIKE] Suspicious Execution - Killed: Procdump l | Potential SysInternals ProcDump Evasion | `rules/windows/process_creation/proc_creation_win_sysinternals_procdump_evasion.yml` | 0.46 | procdump, lsass, dump |
| `5003927` | [WINDOWS-AUTH] User added to Local Administrators group | User Added to Local Administrator Group | `rules/windows/builtin/security/win_security_user_added_to_local_administrators.yml` | 0.46 | s-1-5-32-544, added, local, group |
| `5005486` | [CLOUDTRAIL] ElastiCache cloudtrail event detected - (A | AWS ElastiCache Security Group Modified or Deleted | `rules/cloud/aws/cloudtrail/aws_elasticache_security_group_modified_or_deleted.yml` | 0.46 | authorizecachesecuritygroupingress, elasticache, elasticache.amazonaws |
| `5005488` | [CLOUDTRAIL] ElastiCache cloudtrail event detected - (D | AWS ElastiCache Security Group Modified or Deleted | `rules/cloud/aws/cloudtrail/aws_elasticache_security_group_modified_or_deleted.yml` | 0.46 | deletecachesecuritygroup, elasticache, elasticache.amazonaws.com |
| `5005489` | [CLOUDTRAIL] ElastiCache cloudtrail event detected - (R | AWS ElastiCache Security Group Modified or Deleted | `rules/cloud/aws/cloudtrail/aws_elasticache_security_group_modified_or_deleted.yml` | 0.46 | revokecachesecuritygroupingress, elasticache, elasticache.amazonaws.co |
| `5013857` | [WINDOWS-SYSMON] icacls all users deny delete | Use Icacls to Hide File to Everyone | `rules/windows/process_creation/proc_creation_win_icacls_deny.yml` | 0.46 | icacls, deny |
| `5008564` | [WINDOWS-AUTH] User added to Local Administrators group | User Added to Local Administrators Group | `rules/windows/process_creation/proc_creation_win_susp_add_user_local_admin_group.yml` | 0.46 | administrators, added, local, group |
| `5008354` | [WINDOWS-SECURITY] Exfil software rclone detected | Rclone Execution via Command Line or PowerShell | `deprecated/windows/win_susp_rclone_exec.yml` | 0.46 | rclone.exe, rclone, sync, copy, config |
| `5005633` | [LINUX-AUDITD] PHP execution | Php Inline Command Execution | `rules/windows/process_creation/proc_creation_win_php_inline_command_execution.yml` | 0.46 | php, execution |
| `5005663` | [LINUX-AUDITD] chmod +x of something in /tmp | Equation Group Indicators | `rules/linux/builtin/lnx_apt_equationgroup_lnx.yml` | 0.46 | chmod, tmp |
| `5007691` | [WINDOWS-POWERSHELL] Possible Resolve-DnsName IEX comma | Suspicious PowerShell IEX Execution Patterns | `rules/windows/process_creation/proc_creation_win_powershell_iex_patterns.yml` | 0.46 | iex, powershell |
| `5008369` | [WINDOWS-CLIPBOARD] Remoe-exec psexec command | PsExec Service File Creation | `rules/windows/file/file_event/file_event_win_sysinternals_psexec_service.yml` | 0.46 | psexec |
| `5009412` | [WINDOWS-SECURITY] The certificate manager denied a pen | Active Directory Certificate Services Denied Certificat | `rules/windows/builtin/system/microsoft_windows_certification_authority/win_system_adcs_enrollment_request_denied.yml` | 0.46 | denied, certificate, request |
| `5017396` | [WINDOWS-SECURITY] Hidden Scheduled Task Created - Crit | Suspicious PowerShell Invocations - Generic - PowerShel | `rules/windows/powershell/powershell_module/posh_pm_susp_invocation_generic.yml` | 0.46 | hidden |
| `5000385` | [BASH] iptables command access | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.46 | bash |
| `5017599` | [CROWDSTRIKE] Suspicious Execution Detected- PsExec exe | Renamed PsExec | `deprecated/windows/proc_creation_win_renamed_psexec.yml` | 0.46 | psexec, execution |
| `5005279` | [MS-DEFENDER] Real-Time Protection Configuration Change | Windows Defender Real-Time Protection Failure/Restart | `rules/windows/builtin/windefend/win_defender_real_time_protection_errors.yml` | 0.46 | real-time, protection |
| `5005755` | [WINDOWS-POWERSHELL] Powershell Possible Downgrade Atte | PowerShell Downgrade Attack - PowerShell | `rules/windows/powershell/powershell_classic/posh_pc_downgrade_attack.yml` | 0.46 | downgrade, version, powershell |
| `5009416` | [WINDOWS-SECURITY] The certificate manager settings for | Certificate Exported From Local Certificate Store | `rules/windows/builtin/certificate_services_client_lifecycle_system/win_certificateservicesclient_lifecycle_system_cert_exported.yml` | 0.46 | certificate |
| `5002566` | [SU] root password change attempt | AWS Root Credentials | `rules/cloud/aws/cloudtrail/aws_root_account_usage.yml` | 0.46 | root |
| `5009372` | [WINDOWS-POWERSHELL] Possible Resolve-DnsName IEX comma | Suspicious PowerShell IEX Execution Patterns | `rules/windows/process_creation/proc_creation_win_powershell_iex_patterns.yml` | 0.46 | iex, powershell |
| `5008640` | [WINDOWS-CLIPBOARD] Remoe-exec psexec command | PsExec Service File Creation | `rules/windows/file/file_event/file_event_win_sysinternals_psexec_service.yml` | 0.46 | psexec |
| `5003927` | [WINDOWS-AUTH] User added to Local Administrators group | User Added to Local Administrators Group | `rules/windows/process_creation/proc_creation_win_susp_add_user_local_admin_group.yml` | 0.46 | administrators, added, local, group |
| `5010910` | [WINDOWS-SECURITY] Possible Rclone Exfil CommandLine Pa | RClone Execution | `deprecated/windows/sysmon_rclone_execution.yml` | 0.46 | auto-confirm, ignore-existing, multi-thread-streams, transfers, rclone |
| `5013564` | [WINDOWS-SECURITY] WMIC process call create | Process Creation Attempt via Wmic.EXE | `rules/windows/process_creation/proc_creation_win_wmic_process_creation.yml` | 0.46 | wmic, call, create |
| `5003127` | [ZSCALER] known malicious user-agent string - MSIE 7.0 | Malware User Agent | `rules/web/proxy_generic/proxy_ua_malware.yml` | 0.46 | 7.0, mozilla/4.0, msie, compatible |
| `5009280` | [WINDOWS-MISC] Windows audit log was cleared | Security Event Log Cleared | `deprecated/windows/win_security_event_log_cleared.yml` | 0.46 | cleared, security |
| `5003373` | [PASSWORDSTATE] Password Reset Removed from Queue | Password Reset By User Account | `rules/cloud/azure/audit_logs/azure_user_password_change.yml` | 0.46 | reset, password |
| `5008099` | [WINDOWS-SYSMON] Possible DLL Hijacking of wer.dll | Creation of WerFault.exe/Wer.dll in Unusual Folder | `rules/windows/file/file_event/file_event_win_werfault_dll_hijacking.yml` | 0.46 | wer.dll, hijacking, dll |
| `5009313` | [WINDOWS-POWERSHELL] Powershell Possible Downgrade Atte | PowerShell Downgrade Attack - PowerShell | `rules/windows/powershell/powershell_classic/posh_pc_downgrade_attack.yml` | 0.46 | downgrade, version, powershell |
| `5002329` | [BASH] SSH input and output forwarding | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.46 | bash |
| `5017578` | [CROWDSTRIKE] Suspicious Execution Detected - Procdump | Procdump Execution | `rules/windows/process_creation/proc_creation_win_sysinternals_procdump.yml` | 0.46 | procdump, execution |
| `5000097` | [ATTACK] Possible buffer overflow attempt | Buffer Overflow Attempts | `rules/linux/builtin/lnx_buffer_overflows.yml` | 0.46 | buffer, overflow |
| `5002331` | [BASH] SSH X11 forwarding | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.46 | bash |
| `5010164` | [WINDOWS-SYSMON] Possible DLL Hijacking of wer.dll | Creation of WerFault.exe/Wer.dll in Unusual Folder | `rules/windows/file/file_event/file_event_win_werfault_dll_hijacking.yml` | 0.46 | wer.dll, hijacking, dll |
| `5005621` | [LINUX-AUDITD] telnet execution | OpenCanary - Telnet Login Attempt | `rules/application/opencanary/opencanary_telnet_login_attempt.yml` | 0.46 | telnet |
| `5002307` | [BASH] Python socket execution | Python Reverse Shell Execution Via PTY And Socket Modul | `rules/linux/process_creation/proc_creation_lnx_python_reverse_shell.yml` | 0.46 | socket, python, execution |
| `5014556` | [WINDOWS-SECURITY] Possible Rclone Exfil CommandLine Pa | RClone Execution | `deprecated/windows/sysmon_rclone_execution.yml` | 0.46 | auto-confirm, ignore-existing, multi-thread-streams, transfers, rclone |
| `5000009` | [BASH] /bin/bash command line call | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.46 | bash |
| `5002328` | [BASH] SSH remote forwarding | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.46 | bash |
| `5006885` | [WINDOWS-MALWARE] Bart ransomware file extension detect | Potential Perl Reverse Shell Execution | `rules/linux/process_creation/proc_creation_lnx_perl_reverse_shell.yml` | 0.46 | perl |
| `5007092` | [WINDOWS-MALWARE] Bart ransomware file extension detect | Potential Perl Reverse Shell Execution | `rules/linux/process_creation/proc_creation_lnx_perl_reverse_shell.yml` | 0.46 | perl |
| `5013881` | [WINDOWS-SYSMON] Running Processes Enumeration via Task | Taskmgr as LOCAL_SYSTEM | `rules/windows/process_creation/proc_creation_win_taskmgr_localsystem.yml` | 0.46 | taskmgr, taskmgr.exe |
| `5008961` | [WINDOWS-MALWARE] Bart ransomware file extension detect | Potential Perl Reverse Shell Execution | `rules/linux/process_creation/proc_creation_lnx_perl_reverse_shell.yml` | 0.46 | perl |
| `5009168` | [WINDOWS-MALWARE] Bart ransomware file extension detect | Potential Perl Reverse Shell Execution | `rules/linux/process_creation/proc_creation_lnx_perl_reverse_shell.yml` | 0.46 | perl |
| `5013816` | [WINDOWS-SECURITY] AnyDesk Remote management Software S | Remote Access Tool - Anydesk Execution From Suspicious | `rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk_susp_exec.yml` | 0.46 | anydesk.exe, anydesk, software, remote |
| `5100125` | Applocker detected | Possible Applocker Bypass | `deprecated/windows/proc_creation_win_possible_applocker_bypass.yml` | 0.46 | applocker |
| `5000120` | [SYSLOG] Illegal root login | AWS Root Credentials | `rules/cloud/aws/cloudtrail/aws_root_account_usage.yml` | 0.46 | root |
| `5002326` | [BASH] SSH GSSAPI forwarding | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.46 | bash |
| `5015945` | [KEY9] Unauthorized Access Attempted | Okta Unauthorized Access to App | `rules/identity/okta/okta_unauthorized_access_to_app.yml` | 0.45 | unauthorized |
| `5002325` | [BASH] SSH dynamic forwarding | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.45 | bash |
| `5002565` | [BASH] root password change attempt | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.45 | bash |
| `5001833` | [WEB-ATTACKS] Hydra User-Agent | HackTool - Hydra Password Bruteforce Execution | `rules/windows/process_creation/proc_creation_win_hktl_hydra.yml` | 0.45 | hydra |
| `9870009` | [EXPERIMENTAL][WINDOWS-SECURITY] Kerberos - AS-REP Roas | Suspicious Kerberos RC4 Ticket Encryption | `rules/windows/builtin/security/win_security_susp_rc4_kerberos.yml` | 0.45 | 0x17, ticket, encryption, kerberos, type |
| `5013886` | [WINDOWS-SECURITY] whoami command executed | Whoami Utility Execution | `deprecated/windows/proc_creation_win_whoami_execution.yml` | 0.45 | whoami |
| `5002999` | [DYNAMIC] Rsync logs detected via program. | Shell Execution via Rsync - Linux | `rules/linux/process_creation/proc_creation_lnx_rsync_shell_execution.yml` | 0.45 | rsyncd, rsync |
| `5013871` | [WINDOWS-SECURITY] Possible LSASS Dump via ProcDump | Potential SysInternals ProcDump Evasion | `rules/windows/process_creation/proc_creation_win_sysinternals_procdump_evasion.yml` | 0.45 | procdump, lsass.exe, lsass, dump |
| `5002304` | [BASH] History hiding | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.45 | bash |
| `5005442` | [CLOUDTRAIL] cloudtrail event detected - (StopLogging) | AWS CloudTrail Important Change | `rules/cloud/aws/cloudtrail/aws_cloudtrail_disable_logging.yml` | 0.45 | stoplogging, cloudtrail.amazonaws.com, cloudtrail |
| `5000004` | [BASH] /etc/passwd access | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.45 | bash |
| `5002317` | [BASH] /dev/tcp access | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.45 | bash |
| `5002327` | [BASH] SSH local forwarding | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.45 | bash |
| `5010559` | [CISCO-SCA] Inbound Port Scanner | PUA - Advanced Port Scanner Execution | `rules/windows/process_creation/proc_creation_win_pua_advanced_port_scanner.yml` | 0.45 | scanner, port |
| `5000002` | [BASH] telnet execution | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.45 | bash, execution |
| `5013817` | [WINDOWS-SECURITY] Remote Access Software Installed as | Remote Access Tool - AnyDesk Execution | `rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk.yml` | 0.45 | anydesk, software, remote |
| `5007128` | [WINDOWS-POWERSHELL] IEX Command Encoded as Base64 | PowerShell Base64 Encoded IEX Cmdlet | `rules/windows/process_creation/proc_creation_win_powershell_base64_iex.yml` | 0.45 | encoded, iex, base64, powershell |
| `5002329` | [BASH] SSH input and output forwarding | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.45 | bash |
| `5008357` | [WINDOWS-SECURITY] A service was installed in the syste | PowerShell Scripts Run by a Services | `deprecated/windows/driver_load_win_powershell_script_installed_as_service.yml` | 0.45 | installed, powershell |
| `5002324` | [BASH] SSH agent forwarding | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.45 | bash |
| `5013897` | [WINDOWS-SECURITY] List disk information | System Disk And Volume Reconnaissance Via Wmic.EXE | `rules/windows/process_creation/proc_creation_win_wmic_recon_volume.yml` | 0.45 | logicaldisk, disk, wmic.exe, list, information |
| `5005664` | [LINUX-AUDITD] whoami execution | Whoami Utility Execution | `deprecated/windows/proc_creation_win_whoami_execution.yml` | 0.45 | whoami, execution |
| `5100141` | Microsoft IIS server detected | HTTP Logging Disabled On IIS Server | `rules/windows/builtin/iis-configuration/win_iis_logging_http_disabled.yml` | 0.45 | iis, server |
| `5000892` | [JUNIPER] BGP no route to host | New Network Route Added | `rules/cloud/aws/cloudtrail/aws_cloudtrail_new_route_added.yml` | 0.45 | route |
| `5010825` | [CyberArk] Delete Folder (Has Locked Files) | Okta User Account Locked Out | `rules/identity/okta/okta_user_account_locked_out.yml` | 0.45 | locked |
| `5014631` | [LINUX-AUDITD] Immutable File Attr Removed | Remove Immutable File Attribute | `rules/linux/process_creation/proc_creation_lnx_chattr_immutable_removal.yml` | 0.45 | immutable, chattr |
| `5002320` | [BASH] ksh shell execution | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.45 | bash, shell, execution |
| `5002322` | [BASH] zsh shell execution | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.45 | bash, shell, execution |
| `5010487` | [WINDOWS-SECURITY] Comsrvc MiniDump Command | Process Memory Dump Via Comsvcs.DLL | `rules/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs.yml` | 0.45 | comsvcs, minidump, rundll32 |
| `5000005` | [BASH] /etc/shadow access | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.45 | bash |
| `5000011` | [BASH] .bash_history access | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.45 | bash |
| `5003111` | [NXLOG] Missing Windows Log Message | Potential CVE-2023-36884 Exploitation - Share Access | `rules-emerging-threats/2023/Exploits/CVE-2023-36884/win_security_exploit_cve_2023_36884_office_windows_html_rce_share_access_pattern.yml` | 0.45 | 0-9 |
| `5014544` | [WINDOWS-MISC] Potential Metasploit/MS14-068 Activity | Suspicious Kerberos RC4 Ticket Encryption | `rules/windows/builtin/security/win_security_susp_rc4_kerberos.yml` | 0.45 | 0x17, ticket, encryption, type |
| `5002332` | [BASH] SSH X11 trusted forwarding | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.45 | bash |
| `5007330` | [SOPHOS] Sophos Firewall detected malicious traffic | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.45 | endpoint, sophos |
| `5000116` | [SYSLOG] System out of disk space | Space After Filename | `deprecated/linux/lnx_space_after_filename_.yml` | 0.45 | space |
| `5017578` | [CROWDSTRIKE] Suspicious Execution Detected - Procdump | Renamed ProcDump Execution | `rules/windows/process_creation/proc_creation_win_renamed_sysinternals_procdump.yml` | 0.45 | procdump, execution |
| `5001083` | [SONICWALL] Possible TCP Port Scan | OpenCanary - Host Port Scan (SYN Scan) | `rules/application/opencanary/opencanary_portscan_syn_scan.yml` | 0.45 | port, scan |
| `5002326` | [BASH] SSH GSSAPI forwarding | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.45 | bash |
| `5015945` | [KEY9] Unauthorized Access Attempted | Bitbucket Unauthorized Access To A Resource | `rules/application/bitbucket/audit/bitbucket_audit_unauthorized_access_detected.yml` | 0.45 | unauthorized |
| `5002319` | [BASH] csh shell execution | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.45 | bash, shell, execution |
| `5002306` | [BASH] Netcat execution | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.45 | bash, execution |
| `5002565` | [BASH] root password change attempt | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.45 | bash |
| `5100189` | Sophos device detected | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.45 | sophos |
| `5009341` | [WINDOWS-POWERSHELL] IEX Command Encoded as Base64 | PowerShell Base64 Encoded IEX Cmdlet | `rules/windows/process_creation/proc_creation_win_powershell_base64_iex.yml` | 0.45 | encoded, iex, base64, powershell |
| `5001561` | [HUAWEI] ATCKDF - Port scan attack | OpenCanary - Host Port Scan (SYN Scan) | `rules/application/opencanary/opencanary_portscan_syn_scan.yml` | 0.45 | port, scan |
| `5017166` | [CROWDSTRIKE] Network Access In A Detection Summary Eve | Tor Client/Browser Execution | `rules/windows/process_creation/proc_creation_win_browsers_tor_execution.yml` | 0.45 | tor.exe, tor, browser |
| `5002304` | [BASH] History hiding | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.45 | bash |
| `5007664` | [DYNAMIC] windows applocker logs detected via program. | AppLocker Prevented Application or Script from Running | `rules/windows/builtin/applocker/win_applocker_application_was_prevented_from_running.yml` | 0.45 | applocker |
| `5000004` | [BASH] /etc/passwd access | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.45 | bash |
| `5002317` | [BASH] /dev/tcp access | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.45 | bash |
| `5000011` | [BASH] .bash_history access | History File Deletion | `rules/linux/process_creation/proc_creation_lnx_susp_history_delete.yml` | 0.45 | bash_history, history |
| `5002810` | [WINDOWS-SYSMON] Suspicious WMIC call - shadowcopy dele | Potential Maze Ransomware Activity | `rules-emerging-threats/2020/Malware/Maze/proc_creation_win_malware_maze_ransomware.yml` | 0.45 | shadowcopy, delete |
| `5015126` | [DYNAMIC] ScreenConnect logs detected via program. | Remote Access Tool - ScreenConnect Command Execution | `rules/windows/builtin/application/screenconnect/win_app_remote_access_tools_screenconnect_command_exec.yml` | 0.45 | screenconnect |
| `5000003` | [BASH] nmap execution | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.45 | bash, execution |
| `5002330` | [BASH] SSH tunnel forwarding | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.45 | bash |
| `5009400` | [WINDOWS-SECURITY] A security-enabled local group was c | A Security-Enabled Global Group Was Deleted | `rules/windows/builtin/security/account_management/win_security_security_enabled_global_group_deleted.yml` | 0.45 | security-enabled, group |
| `5017581` | [CROWDSTRIKE] Suspicious Execution Detected - comsvcs.d | Process Memory Dump Via Comsvcs.DLL | `rules/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs.yml` | 0.45 | comsvcs.dll, minidump |
| `5002311` | [BASH] Perl socket execution | Potential Perl Reverse Shell Execution | `rules/linux/process_creation/proc_creation_lnx_perl_reverse_shell.yml` | 0.45 | socket, perl, execution |
| `5009782` | [WINDOWS-SYSMON] Suspicious WMIC call - shadowcopy dele | Potential Maze Ransomware Activity | `rules-emerging-threats/2020/Malware/Maze/proc_creation_win_malware_maze_ransomware.yml` | 0.45 | shadowcopy, delete |
| `5010586` | [CISCO-SCA] Permissive Amazon Elastic Kubernetes Servic | Azure Kubernetes Cluster Created or Deleted | `rules/cloud/azure/activity_logs/azure_kubernetes_cluster_created_or_deleted.yml` | 0.44 | cluster, kubernetes, created |
| `5014552` | [WINDOWS-SECURITY] Comsrvc MiniDump Command | Process Memory Dump Via Comsvcs.DLL | `rules/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs.yml` | 0.44 | comsvcs, minidump, rundll32 |
| `5005956` | [WINDOWS-SECURITY] Command to Export Secret Key Detecte | Certificate Exported Via Certutil.EXE | `rules/windows/process_creation/proc_creation_win_certutil_export_pfx.yml` | 0.44 | exportpfx, certutil, export |
| `5013816` | [WINDOWS-SECURITY] AnyDesk Remote management Software S | Remote Access Tool - AnyDesk Execution | `rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk.yml` | 0.44 | anydesk.exe, anydesk, software, remote |
| `5010776` | [CyberArk] Clear User History | Clearing Windows Console History | `rules/windows/powershell/powershell_script/posh_ps_clearing_windows_console_history.yml` | 0.44 | clear, history |
| `5008821` | [WINDOWS-MALWARE] Various ransomware file extension det | Locked Workstation | `rules/windows/builtin/security/win_security_workstation_was_locked.yml` | 0.44 | locked |
| `5009015` | [WINDOWS-MALWARE] Various ransomware file extension det | Locked Workstation | `rules/windows/builtin/security/win_security_workstation_was_locked.yml` | 0.44 | locked |
| `5009773` | [WINDOWS-SECURITY] A service was installed in the syste | PowerShell Scripts Run by a Services | `deprecated/windows/driver_load_win_powershell_script_installed_as_service.yml` | 0.44 | installed, powershell |
| `5015937` | [WINDOWS-SECURITY] Directory Attributes Changed to Hidd | Hiding Files with Attrib.exe | `rules/windows/process_creation/proc_creation_win_attrib_hiding_files.yml` | 0.44 | attrib.exe |
| `5015515` | [WINDOWS-SYSMON] Windows Event Log Cleared | Eventlog Cleared | `rules/windows/builtin/system/microsoft_windows_eventlog/win_system_eventlog_cleared.yml` | 0.44 | wevtutil, cleared |
| `5008354` | [WINDOWS-SECURITY] Exfil software rclone detected | Rclone Config File Creation | `rules/windows/file/file_event/file_event_win_rclone_config_files.yml` | 0.44 | rclone, config |
| `5012651` | [MSEXCHANGE-MANAGEMENT] mailboxes Cmdlet Get-App Succes | Possible Exploitation of Exchange RCE CVE-2021-42321 | `rules-emerging-threats/2021/Exploits/CVE-2021-42321/win_exchange_cve_2021_42321.yml` | 0.44 | get-app, cmdlet |
| `5000005` | [BASH] /etc/shadow access | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.44 | bash |
| `5000011` | [BASH] .bash_history access | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.44 | bash |
| `5002306` | [BASH] Netcat execution | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.44 | bash |
| `5013834` | [WINDOWS-SYSMON] DllRegisterServer Entry Function on db | Potential Renamed Rundll32 Execution | `rules/windows/process_creation/proc_creation_win_renamed_rundll32_dllregisterserver.yml` | 0.44 | dllregisterserver, rundll32.exe |
| `5005622` | [LINUX-AUDITD] nmap execution | OpenCanary - NMAP OS Scan | `rules/application/opencanary/opencanary_portscan_nmap_os_scan.yml` | 0.44 | nmap |
| `5015937` | [WINDOWS-SECURITY] Directory Attributes Changed to Hidd | Set Files as System Files Using Attrib.EXE | `rules-threat-hunting/windows/process_creation/proc_creation_win_attrib_system.yml` | 0.44 | attrib.exe |
| `5006658` | [SentinelOne] New Suspicious threat detected | Potential SentinelOne Shell Context Menu Scan Command T | `rules/windows/registry/registry_set/registry_set_sentinelone_shell_context_tampering.yml` | 0.44 | sentinelone |
| `5002332` | [BASH] SSH X11 trusted forwarding | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.44 | bash |
| `5010509` | [CISCO-SCA] AWS ECS Credential Access | AWS ECS Task Definition That Queries The Credential End | `rules/cloud/aws/cloudtrail/aws_ecs_task_definition_cred_endpoint_query.yml` | 0.44 | ecs, credential, aws |
| `5014405` | [FORTINET] New admin user added | Access To ADMIN$ Network Share | `rules/windows/builtin/security/win_security_admin_share_access.yml` | 0.44 | admin |
| `5000008` | [BASH] /bin/sh command line call | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.44 | bash |
| `5000182` | [FTPD] FTP Login refused | OpenCanary - FTP Login Attempt | `rules/application/opencanary/opencanary_ftp_login_attempt.yml` | 0.44 | ftp, login |
| `5002310` | [BASH] PHP subproces execution | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.44 | bash, execution |
| `5007330` | [SOPHOS] Sophos Firewall detected malicious traffic | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.44 | endpoint, sophos, threat |
| `5008373` | [WINDOWS-CLIPBOARD] net commands | Automated Turla Group Lateral Movement | `unsupported/windows/proc_creation_win_correlation_apt_turla_commands_medium.yml` | 0.44 | net, group |
| `5008374` | [WINDOWS-CLIPBOARD] net commands | Automated Turla Group Lateral Movement | `unsupported/windows/proc_creation_win_correlation_apt_turla_commands_medium.yml` | 0.44 | net, group |
| `5015121` | [SCREENCONNECT] Suspicious Discovery Command (net) | Automated Turla Group Lateral Movement | `unsupported/windows/proc_creation_win_correlation_apt_turla_commands_medium.yml` | 0.44 | view, net, group |
| `5100160` | AWS GuardDuty detected | AWS GuardDuty Important Change | `rules/cloud/aws/cloudtrail/aws_guardduty_disruption.yml` | 0.44 | guardduty.amazonaws.com, guardduty, aws |
| `5010843` | [CyberArk] Add Group Member | Privileged Account Creation | `rules/cloud/azure/audit_logs/azure_privileged_account_creation.yml` | 0.44 | member, add |
| `5007143` | [WINDOWS-POWERSHELL] Suspicious FromBase64String Encode | Obfuscated IP Via CLI | `rules/windows/process_creation/proc_creation_win_susp_obfuscated_ip_via_cli.yml` | 0.44 | 0-9 |
| `5008119` | [WINDOWS-SYSMON] Possible DLL Hijacking of winscard.dll | Possible Process Hollowing Image Loading | `deprecated/windows/image_load_susp_uncommon_image_load.yml` | 0.44 | winscard.dll |
| `5017579` | [CROWDSTRIKE] comsvcs.dll MiniDump usage initiated - Bl | Process Memory Dump Via Comsvcs.DLL | `rules/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs.yml` | 0.44 | comsvcs.dll, minidump |
| `5002318` | [BASH] /dev/udp access | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.44 | bash |
| `5002321` | [BASH] tcsh shell execution | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.44 | bash, shell, execution |
| `5010590` | [CISCO-SCA] Potential Data Exfiltration | Potential Data Exfiltration Via Curl.EXE | `rules-threat-hunting/windows/process_creation/proc_creation_win_curl_fileupload.yml` | 0.44 | exfiltration, data |
| `5017576` | [CROWDSTRIKE] Suspicious Execution - Blocked: Procdump | Procdump Execution | `rules/windows/process_creation/proc_creation_win_sysinternals_procdump.yml` | 0.44 | procdump, execution |
| `5017593` | [CROWDSTRIKE] Suspicious Execution Detected - LaZagne c | Credential Dumping by LaZagne | `deprecated/windows/proc_access_win_lazagne_cred_dump_lsass_access.yml` | 0.44 | lazagne, credential |
| `5017581` | [CROWDSTRIKE] Suspicious Execution Detected - comsvcs.d | Lsass Memory Dump via Comsvcs DLL | `rules/windows/process_access/proc_access_win_lsass_dump_comsvcs_dll.yml` | 0.44 | comsvcs.dll, minidump |
| `5004779` | [WINDOWS-MALWARE] Suspicious Powershell execution | HackTool - Wmiexec Default Powershell Command | `rules/windows/process_creation/proc_creation_win_hktl_wmiexec_default_powershell.yml` | 0.44 | noni, nop, exec, hidden, bypass, powershell |
| `5008644` | [WINDOWS-CLIPBOARD] net commands | Automated Turla Group Lateral Movement | `unsupported/windows/proc_creation_win_correlation_apt_turla_commands_medium.yml` | 0.44 | net, group |
| `5008645` | [WINDOWS-CLIPBOARD] net commands | Automated Turla Group Lateral Movement | `unsupported/windows/proc_creation_win_correlation_apt_turla_commands_medium.yml` | 0.44 | net, group |
| `5009756` | [WINDOWS-SECURITY] Command to Export Secret Key Detecte | Certificate Exported Via Certutil.EXE | `rules/windows/process_creation/proc_creation_win_certutil_export_pfx.yml` | 0.44 | exportpfx, certutil, export |
| `5010184` | [WINDOWS-SYSMON] Possible DLL Hijacking of winscard.dll | Possible Process Hollowing Image Loading | `deprecated/windows/image_load_susp_uncommon_image_load.yml` | 0.44 | winscard.dll |
| `5003134` | [ZSCALER] Win.Trojan.Darkcpn outbound connection | Malware User Agent | `rules/web/proxy_generic/proxy_ua_malware.yml` | 0.44 | 6.0, 5.1, mozilla/4.0, msie, clr, compatible |
| `5008779` | [WINDOWS-MALWARE] Suspicious Powershell execution | HackTool - Wmiexec Default Powershell Command | `rules/windows/process_creation/proc_creation_win_hktl_wmiexec_default_powershell.yml` | 0.44 | noni, nop, exec, hidden, bypass, powershell |
| `5000398` | [NETSCREEN] Port scan! | OpenCanary - Host Port Scan (SYN Scan) | `rules/application/opencanary/opencanary_portscan_syn_scan.yml` | 0.44 | port, scan |
| `5010959` | [GITHUB] Item Added | New Github Organization Member Added | `rules/application/github/audit/github_new_org_member.yml` | 0.44 | github, added |
| `5000932` | [FORTINET] Configuration change | Sysmon Configuration Change | `rules/windows/sysmon/sysmon_config_modification.yml` | 0.44 | change, configuration |
| `5000049` | [SQUID] 'passwd' access attempt | Copy Passwd Or Shadow From TMP Path | `rules/linux/process_creation/proc_creation_lnx_cp_passwd_or_shadow_tmp.yml` | 0.44 | passwd |
| `5003417` | [WINDOWS-SECURITY] Certificate Services revoked a certi | CodeIntegrity - Blocked Image Load With Revoked Certifi | `rules/windows/builtin/code_integrity/win_codeintegrity_revoked_image_blocked.yml` | 0.44 | revoked, certificate |
| `5017593` | [CROWDSTRIKE] Suspicious Execution Detected - LaZagne c | Credentials In Files | `rules/macos/process_creation/proc_creation_macos_find_cred_in_files.yml` | 0.44 | lazagne |
| `5002982` | [DYNAMIC] Linux kernel logs detected via program. | CodeIntegrity - Revoked Kernel Driver Loaded | `rules/windows/builtin/code_integrity/win_codeintegrity_revoked_driver_loaded.yml` | 0.44 | kernel |
| `5002310` | [BASH] PHP subproces execution | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.44 | bash |
| `5002313` | [BASH] Ruby socket execution | Potential Ruby Reverse Shell | `rules/linux/process_creation/proc_creation_lnx_ruby_reverse_shell.yml` | 0.44 | ruby, socket, bash, execution |
| `5015078` | [WINDOWS-SECURITY] Sticky Key Backdoor Execution | Sticky Key Like Backdoor Execution | `rules/windows/process_creation/proc_creation_win_cmd_sticky_key_like_backdoor_execution.yml` | 0.44 | magnify.exe, utilman.exe, sethc.exe, sticky, backdoor, key |
| `5100189` | Sophos device detected | Suspicious Execution of Sc to Delete AV Services | `deprecated/windows/proc_creation_win_sc_delete_av_services.yml` | 0.44 | sophos, device |
| `5009296` | [WINDOWS-MISC] Installation of PSEXEC service via SCM | PsExec Service File Creation | `rules/windows/file/file_event/file_event_win_sysinternals_psexec_service.yml` | 0.44 | psexec, installation |
| `5013747` | [NETWRIX] Logon Activity - Possible Brute Force Attempt | Suspicious Windows ANONYMOUS LOGON Local Account Create | `rules/windows/builtin/security/win_security_susp_local_anon_logon_created.yml` | 0.44 | logon |
| `5005847` | [DARKTRACE] Potential Malicious Device Alert | Azure Device or Configuration Modified or Deleted | `rules/cloud/azure/activity_logs/azure_device_or_configuration_modified_or_deleted.yml` | 0.44 | device |
| `5005912` | [DARKTRACE] A highly privileged credential is being use | MSSQL Server Failed Logon From External Network | `rules/windows/builtin/application/mssqlserver/win_mssql_failed_logon_from_external_network.yml` | 0.44 | client |
| `5008089` | [WINDOWS-SYSMON] Possible DLL Hijacking of vssapi.dll | Suspicious Volume Shadow Copy Vssapi.dll Load | `rules/windows/image_load/image_load_dll_vssapi_susp_load.yml` | 0.43 | vssapi.dll, dll |
| `5017579` | [CROWDSTRIKE] comsvcs.dll MiniDump usage initiated - Bl | Lsass Memory Dump via Comsvcs DLL | `rules/windows/process_access/proc_access_win_lsass_dump_comsvcs_dll.yml` | 0.43 | comsvcs.dll, minidump |
| `5014405` | [FORTINET] New admin user added | User Added To Admin Group Via DseditGroup | `rules/macos/process_creation/proc_creation_macos_dseditgroup_add_to_admin_group.yml` | 0.43 | added, admin |
| `5010154` | [WINDOWS-SYSMON] Possible DLL Hijacking of vssapi.dll | Suspicious Volume Shadow Copy Vssapi.dll Load | `rules/windows/image_load/image_load_dll_vssapi_susp_load.yml` | 0.43 | vssapi.dll, dll |
| `5002662` | [SONICWALL] FTP - Login Failed | OpenCanary - FTP Login Attempt | `rules/application/opencanary/opencanary_ftp_login_attempt.yml` | 0.43 | ftp, login |
| `5100041` | rsync client execution | Shell Execution via Rsync - Linux | `rules/linux/process_creation/proc_creation_lnx_rsync_shell_execution.yml` | 0.43 | rsync, execution |
| `5002331` | [BASH] SSH X11 forwarding | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.43 | bash |
| `5014647` | [MSAPI-AZUREAD] CRITICAL - User Administrator role assi | Privileged Account Creation | `rules/cloud/azure/audit_logs/azure_privileged_account_creation.yml` | 0.43 | member, role, add |
| `5002954` | [WINDOWS-MISC] Event log has been cleared. | Eventlog Cleared | `rules/windows/builtin/system/microsoft_windows_eventlog/win_system_eventlog_cleared.yml` | 0.43 | eventlog, cleared |
| `5003407` | [WINDOWS-SECURITY] A security-enabled universal group w | A Security-Enabled Global Group Was Deleted | `rules/windows/builtin/security/account_management/win_security_security_enabled_global_group_deleted.yml` | 0.43 | security-enabled, group |
| `5010860` | [CyberArk] Add Privileged Command failed | Privileged Account Creation | `rules/cloud/azure/audit_logs/azure_privileged_account_creation.yml` | 0.43 | privileged, add |
| `5010862` | [CyberArk] Add Privileged Command failed | Privileged Account Creation | `rules/cloud/azure/audit_logs/azure_privileged_account_creation.yml` | 0.43 | privileged, add |
| `5017591` | [CROWDSTRIKE] LaZagne credential harvesting binary exec | Credential Dumping by LaZagne | `deprecated/windows/proc_access_win_lazagne_cred_dump_lsass_access.yml` | 0.43 | lazagne, credential |
| `5002318` | [BASH] /dev/udp access | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.43 | bash |
| `5000009` | [BASH] /bin/bash command line call | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.43 | bash |
| `5015078` | [WINDOWS-SECURITY] Sticky Key Backdoor Execution | Read Contents From Stdin Via Cmd.EXE | `rules/windows/process_creation/proc_creation_win_cmd_stdin_redirect.yml` | 0.43 | cmd.exe |
| `5010876` | [CyberArk] Terminate Session Failed | Application Termination Attempt via Wmic.EXE | `rules/windows/process_creation/proc_creation_win_wmic_terminate_application.yml` | 0.43 | terminate |
| `5013886` | [WINDOWS-SECURITY] whoami command executed | Renamed Whoami Execution | `rules/windows/process_creation/proc_creation_win_renamed_whoami.yml` | 0.43 | whoami |
| `5002699` | [SONICWALL] Intrusion Detection - Probable TCP FIN scan | OpenCanary - NMAP FIN Scan | `rules/application/opencanary/opencanary_portscan_nmap_fin_scan.yml` | 0.43 | fin, scan |
| `5008090` | [WINDOWS-SYSMON] Possible DLL Hijacking of vsstrace.dll | Potentially Suspicious Volume Shadow Copy Vsstrace.dll | `rules/windows/image_load/image_load_dll_vsstrace_susp_load.yml` | 0.43 | vsstrace.dll, dll |
| `5007148` | [WINDOWS-POWERSHELL] Schtask Created to Base64 Decode P | Scheduled Task Executing Payload from Registry | `rules/windows/process_creation/proc_creation_win_schtasks_reg_loader.yml` | 0.43 | get-itemproperty, hkcu, frombase64string, payload, registry, powershel |
| `5003420` | [WINDOWS-SECURITY] The certificate manager settings for | Windows Firewall Settings Have Been Changed | `rules/windows/builtin/firewall_as/win_firewall_as_setting_change.yml` | 0.43 | settings, changed |
| `5009413` | [WINDOWS-SECURITY] Certificate Services revoked a certi | CodeIntegrity - Blocked Image Load With Revoked Certifi | `rules/windows/builtin/code_integrity/win_codeintegrity_revoked_image_blocked.yml` | 0.43 | revoked, certificate |
| `5008380` | [WINDOWS-CLIPBOARD] copy from share drive to local C: c | Copy From Or To Admin Share Or Sysvol Folder | `rules/windows/process_creation/proc_creation_win_susp_copy_lateral_movement.yml` | 0.43 | share, copy |
| `5017721` | [SOPHOS_FIREWALL] Firewall Rule Added to Configuration | Windows Defender Firewall Has Been Reset To Its Default | `rules/windows/builtin/firewall_as/win_firewall_as_reset_config.yml` | 0.43 | firewall, configuration |
| `5010155` | [WINDOWS-SYSMON] Possible DLL Hijacking of vsstrace.dll | Potentially Suspicious Volume Shadow Copy Vsstrace.dll | `rules/windows/image_load/image_load_dll_vsstrace_susp_load.yml` | 0.43 | vsstrace.dll, dll |
| `5014405` | [FORTINET] New admin user added | User Added To Admin Group - MacOS | `deprecated/macos/proc_creation_macos_add_to_admin_group.yml` | 0.43 | added, admin |
| `5014402` | [FORTINET] Configuration change | Sysmon Configuration Change | `rules/windows/sysmon/sysmon_config_modification.yml` | 0.43 | change, configuration |
| `5013870` | [WINDOWS-SECURITY] LSASS Dump via ProcDump | Potential SysInternals ProcDump Evasion | `rules/windows/process_creation/proc_creation_win_sysinternals_procdump_evasion.yml` | 0.43 | procdump, lsass.exe, lsass, dump |
| `5017591` | [CROWDSTRIKE] LaZagne credential harvesting binary exec | Credentials In Files | `rules/macos/process_creation/proc_creation_macos_find_cred_in_files.yml` | 0.43 | lazagne |
| `5100030` | Unix 'kernel' messages detected | New Kernel Driver Via SC.EXE | `rules/windows/process_creation/proc_creation_win_sc_new_kernel_driver.yml` | 0.43 | kernel |
| `5013888` | [WINDOWS-SECURITY] net group domain computers command e | Reconnaissance Activity | `rules/windows/builtin/security/win_security_susp_net_recon_activity.yml` | 0.43 | net, domain, group |
| `5017576` | [CROWDSTRIKE] Suspicious Execution - Blocked: Procdump | Renamed ProcDump Execution | `rules/windows/process_creation/proc_creation_win_renamed_sysinternals_procdump.yml` | 0.43 | procdump, execution |
| `5017336` | [DYNAMIC] Azure Eventhub Windows MSSQL Logs Detected | MSSQL XPCmdshell Option Change | `rules/windows/builtin/application/mssqlserver/win_mssql_xp_cmdshell_change.yml` | 0.43 | mssql |
| `5013844` | [WINDOWS-SYSMON] Bumblebee Remote Thread Creation | Wab Execution From Non Default Location | `rules/windows/process_creation/proc_creation_win_wab_execution_from_non_default_location.yml` | 0.43 | wabmig.exe, bumblebee, wab.exe |
| `5000001` | [BASH] gcc execution | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.43 | bash, execution |
| `5002323` | [BASH] stunnel execution | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.43 | bash, execution |
| `5008651` | [WINDOWS-CLIPBOARD] copy from share drive to local C: c | Copy From Or To Admin Share Or Sysvol Folder | `rules/windows/process_creation/proc_creation_win_susp_copy_lateral_movement.yml` | 0.43 | share, copy |
| `5000150` | [MYSQL] Access denied for user | OpenCanary - MySQL Login Attempt | `rules/application/opencanary/opencanary_mysql_login_attempt.yml` | 0.43 | mysql |
| `5005664` | [LINUX-AUDITD] whoami execution | Renamed Whoami Execution | `rules/windows/process_creation/proc_creation_win_renamed_whoami.yml` | 0.43 | whoami, execution |
| `5013834` | [WINDOWS-SYSMON] DllRegisterServer Entry Function on db | IcedID Malware Suspicious Single Digit DLL Execution Vi | `rules-emerging-threats/2023/Malware/IcedID/proc_creation_win_malware_icedid_rundll32_dllregisterserver.yml` | 0.43 | dllregisterserver, function, rundll32.exe |
| `5002001` | [WINDOWS-MALWARE] Incorrect path called for svchost.exe | Suspicious Process Masquerading As SvcHost.EXE | `rules/windows/process_creation/proc_creation_win_svchost_masqueraded_execution.yml` | 0.43 | svchost.exe |
| `5005755` | [WINDOWS-POWERSHELL] Powershell Possible Downgrade Atte | Potential PowerShell Downgrade Attack | `rules/windows/process_creation/proc_creation_win_powershell_downgrade_attack.yml` | 0.43 | downgrade, version, powershell |
| `5003358` | [PASSWORDSTATE] Security Administrator Added | User Added to an Administrator's Azure AD Role | `rules/cloud/azure/audit_logs/azure_ad_user_added_to_admin_role.yml` | 0.43 | administrator, added |
| `5008681` | [WINDOWS-MALWARE] Incorrect path called for svchost.exe | Suspicious Process Masquerading As SvcHost.EXE | `rules/windows/process_creation/proc_creation_win_svchost_masqueraded_execution.yml` | 0.43 | svchost.exe |
| `5011302` | [CARBONBLACK-APP-CONTROL] Multiple failed logins (Warni | Failed Logins with Different Accounts from Single Sourc | `unsupported/windows/win_security_susp_failed_logons_single_source.yml` | 0.43 | logins, failed |
| `5005709` | [CHECKPOINT] Action Quarantine | Win Defender Restored Quarantine File | `rules/windows/builtin/windefend/win_defender_restored_quarantine_file.yml` | 0.43 | quarantine |
| `5002314` | [BASH] Ruby subproces execution | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.43 | bash, execution |
| `5009403` | [WINDOWS-SECURITY] A security-enabled universal group w | A Security-Enabled Global Group Was Deleted | `rules/windows/builtin/security/account_management/win_security_security_enabled_global_group_deleted.yml` | 0.43 | security-enabled, group |
| `5014646` | [MSAPI-AZUREAD] CRITICAL - Security Administrator role | Privileged Account Creation | `rules/cloud/azure/audit_logs/azure_privileged_account_creation.yml` | 0.43 | member, role, add |
| `5000010` | [BASH] HISTORY=/dev/null | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.43 | bash |
| `5003388` | [WINDOWS-SYSMON] SYSMON Possible CMD detected | Read and Execute a File Via Cmd.exe | `deprecated/windows/proc_creation_win_cmd_read_contents.yml` | 0.43 | cmd, cmd.exe |
| `5007143` | [WINDOWS-POWERSHELL] Suspicious FromBase64String Encode | Obfuscated IP Download Activity | `rules/windows/process_creation/proc_creation_win_susp_obfuscated_ip_download.yml` | 0.43 | 0-9 |
| `5009361` | [WINDOWS-POWERSHELL] Schtask Created to Base64 Decode P | Scheduled Task Executing Encoded Payload from Registry | `rules/windows/process_creation/proc_creation_win_schtasks_reg_loader_encoded.yml` | 0.43 | get-itemproperty, schtask, hkcu, frombase64string, payload, base64 |
| `5010518` | [CISCO-SCA] AWS Root Account Used | Root Certificate Installed | `deprecated/windows/proc_creation_win_root_certificate_installed.yml` | 0.43 | root |
| `5009313` | [WINDOWS-POWERSHELL] Powershell Possible Downgrade Atte | Potential PowerShell Downgrade Attack | `rules/windows/process_creation/proc_creation_win_powershell_downgrade_attack.yml` | 0.43 | downgrade, version, powershell |
| `5013889` | [WINDOWS-SECURITY] net group domain controllers command | Reconnaissance Activity | `rules/windows/builtin/security/win_security_susp_net_recon_activity.yml` | 0.43 | net, domain, group |
| `5008384` | [DYNAMIC] windows clipboard logs detected via program. | Clipboard Data Collection Via Pbpaste | `rules-threat-hunting/macos/process_creation/proc_creation_macos_pbpaste_execution.yml` | 0.43 | clipboard |
| `5009416` | [WINDOWS-SECURITY] The certificate manager settings for | Windows Firewall Settings Have Been Changed | `rules/windows/builtin/firewall_as/win_firewall_as_setting_change.yml` | 0.43 | settings, changed |
| `5002309` | [BASH] PHP socket execution | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.43 | bash, execution |
| `5009292` | [WINDOWS-MISC] Event log has been cleared. | Eventlog Cleared | `rules/windows/builtin/system/microsoft_windows_eventlog/win_system_eventlog_cleared.yml` | 0.43 | eventlog, cleared |
| `5009792` | [WINDOWS-SYSMON] SYSMON Possible CMD detected | Read and Execute a File Via Cmd.exe | `deprecated/windows/proc_creation_win_cmd_read_contents.yml` | 0.43 | cmd, cmd.exe |
| `5015178` | [WINDOWS-SECURITY] EDRSilencer block Parameter Detected | HackTool - EDRSilencer Execution | `rules/windows/process_creation/proc_creation_win_hktl_edrsilencer.yml` | 0.43 | edrsilencer, block, security |
| `5000936` | [FORTINET] New user group added | A Member Was Added to a Security-Enabled Global Group | `rules/windows/builtin/security/account_management/win_security_member_added_security_enabled_global_group.yml` | 0.43 | added, group |
| `5008033` | [WINDOWS-SYSMON] Possible DLL Hijacking of samlib.dll | Possible Process Hollowing Image Loading | `deprecated/windows/image_load_susp_uncommon_image_load.yml` | 0.43 | samlib.dll |
| `5001559` | [HUAWEI] ATCKDF - Trace route attack | ETW Trace Evasion Activity | `rules/windows/process_creation/proc_creation_win_susp_etw_trace_evasion.yml` | 0.43 | trace |
| `5003054` | [CISCO-MERAKI] Blocked DHCP server response | DHCP Server Loaded the CallOut DLL | `rules/windows/builtin/system/microsoft_windows_dhcp_server/win_system_susp_dhcp_config.yml` | 0.43 | dhcp, server |
| `5002616` | [SONICWALL] Firewall Rule Modified | Azure Application Credential Modified | `deprecated/cloud/azure_app_credential_modification.yml` | 0.43 | modified |
| `5011302` | [CARBONBLACK-APP-CONTROL] Multiple failed logins (Warni | Multiple Users Failing to Authenticate from Single Proc | `unsupported/windows/win_security_susp_failed_logons_single_process.yml` | 0.42 | logins, multiple, failed |
| `5010098` | [WINDOWS-SYSMON] Possible DLL Hijacking of samlib.dll | Possible Process Hollowing Image Loading | `deprecated/windows/image_load_susp_uncommon_image_load.yml` | 0.42 | samlib.dll |
| `5002326` | [BASH] SSH GSSAPI forwarding | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.42 | bash |
| `5002927` | [CARBONBLACK-APP-CONTROL] Disk configuration change det | Sysmon Configuration Change | `rules/windows/sysmon/sysmon_config_modification.yml` | 0.42 | change, configuration |
| `5007664` | [DYNAMIC] windows applocker logs detected via program. | Possible Applocker Bypass | `deprecated/windows/proc_creation_win_possible_applocker_bypass.yml` | 0.42 | applocker |
| `5000001` | [BASH] gcc execution | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.42 | bash |
| `5002323` | [BASH] stunnel execution | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.42 | bash |
| `5002565` | [BASH] root password change attempt | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.42 | bash |
| `991015` | [AWS] EC2 Create Snapshot | AWS Snapshot Backup Exfiltration | `rules/cloud/aws/cloudtrail/aws_snapshot_backup_exfiltration.yml` | 0.42 | snapshot, ec2, ec2.amazonaws.com, aws |
| `5010910` | [WINDOWS-SECURITY] Possible Rclone Exfil CommandLine Pa | PUA - Rclone Execution | `rules/windows/process_creation/proc_creation_win_pua_rclone_execution.yml` | 0.42 | auto-confirm, ignore-existing, multi-thread-streams, transfers, rclone |
| `5100141` | Microsoft IIS server detected | Suspicious IIS Module Registration | `rules/windows/process_creation/proc_creation_win_iis_susp_module_registration.yml` | 0.42 | iis, microsoft |
| `5017580` | [CROWDSTRIKE] comsvcs.dll MiniDump usage initiated - Ki | Process Memory Dump Via Comsvcs.DLL | `rules/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs.yml` | 0.42 | comsvcs.dll, minidump |
| `5015306` | [NETSKOPE] Quarantine Alert Detected (High) | Win Defender Restored Quarantine File | `rules/windows/builtin/windefend/win_defender_restored_quarantine_file.yml` | 0.42 | quarantine |
| `5001054` | [RSYNC] Authentication failure | Suspicious Invocation of Shell via Rsync | `rules/linux/process_creation/proc_creation_lnx_rsync_shell_spawn.yml` | 0.42 | rsyncd, rsync |
| `5002304` | [BASH] History hiding | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.42 | bash |
| `5002615` | [SONICWALL] Firewall Rule Deleted | Azure Firewall Modified or Deleted | `rules/cloud/azure/activity_logs/azure_firewall_modified_or_deleted.yml` | 0.42 | firewall, deleted |
| `5002314` | [BASH] Ruby subproces execution | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.42 | bash |
| `5002311` | [BASH] Perl socket execution | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.42 | bash, execution |
| `5011321` | [AZURE ACTIVITY] Service Health category Level Critical | Azure Active Directory Hybrid Health AD FS Service Dele | `rules/cloud/azure/activity_logs/azure_aadhybridhealth_adfs_service_delete.yml` | 0.42 | health, category, azure |
| `991017` | [AWS] EC2 Delete Snapshot | AWS Snapshot Backup Exfiltration | `rules/cloud/aws/cloudtrail/aws_snapshot_backup_exfiltration.yml` | 0.42 | snapshot, ec2, ec2.amazonaws.com, aws |
| `5000933` | [FORTINET] Access profile changed | VsCode Powershell Profile Modification | `rules/windows/file/file_event/file_event_win_susp_vscode_powershell_profile.yml` | 0.42 | profile |
| `5017066` | [AWS] EC2 Get Snapshot | AWS Snapshot Backup Exfiltration | `rules/cloud/aws/cloudtrail/aws_snapshot_backup_exfiltration.yml` | 0.42 | snapshot, ec2, ec2.amazonaws.com, aws |
| `5010843` | [CyberArk] Add Group Member | User Added To Group With CA Policy Modification Access | `rules/cloud/azure/audit_logs/azure_group_user_addition_ca_modification.yml` | 0.42 | member, add, group |
| `5000936` | [FORTINET] New user group added | User Added To Group With CA Policy Modification Access | `rules/cloud/azure/audit_logs/azure_group_user_addition_ca_modification.yml` | 0.42 | added, group |
| `5014556` | [WINDOWS-SECURITY] Possible Rclone Exfil CommandLine Pa | PUA - Rclone Execution | `rules/windows/process_creation/proc_creation_win_pua_rclone_execution.yml` | 0.42 | auto-confirm, ignore-existing, multi-thread-streams, transfers, rclone |
| `5005973` | [SYSTEMD] Service Failed to Start | Systemd Service Creation | `rules/linux/auditd/path/lnx_auditd_systemd_service_creation.yml` | 0.42 | systemd |
| `5016063` | [CISCO-MERAKI] Malware Scanning - Option Updated | Windows Defender Malware And PUA Scanning Disabled | `rules/windows/builtin/windefend/win_defender_malware_and_pua_scan_disabled.yml` | 0.42 | scanning, malware |
| `5002309` | [BASH] PHP socket execution | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.42 | bash |
| `5008365` | [WINDOWS-CLIPBOARD] Powershell Policy Bypass Command | Change PowerShell Policies to an Insecure Level | `rules/windows/process_creation/proc_creation_win_powershell_set_policies_to_unsecure_level.yml` | 0.42 | executionpolicy, policy, bypass, powershell |
| `5014600` | [WINDOWS-SYSMON] Installation of PyPyKatz Detected - Cr | Credential Dumping by Pypykatz | `deprecated/windows/proc_access_win_pypykatz_cred_dump_lsass_access.yml` | 0.42 | pypykatz, credential |
| `5000010` | [BASH] HISTORY=/dev/null | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.42 | bash |
| `5001085` | [SONICWALL] Possible UDP Port Scan | OpenCanary - Host Port Scan (SYN Scan) | `rules/application/opencanary/opencanary_portscan_syn_scan.yml` | 0.42 | port, scan |
| `5011322` | [AZURE ACTIVITY] Service Health category Level Error | Azure Active Directory Hybrid Health AD FS Service Dele | `rules/cloud/azure/activity_logs/azure_aadhybridhealth_adfs_service_delete.yml` | 0.42 | health, category, azure |
| `5003127` | [ZSCALER] known malicious user-agent string - MSIE 7.0 | CobaltStrike Malformed UAs in Malleable Profiles | `deprecated/web/proxy_cobalt_malformed_uas.yml` | 0.42 | 7.0, mozilla/4.0, msie, compatible |
| `5016616` | [CROWDSTRIKE] A process attempted to delete a Volume Sh | Delete Volume Shadow Copies via WMI with PowerShell - P | `deprecated/windows/powershell_ps_susp_win32_shadowcopy.yml` | 0.42 | shadow, volume, delete |
| `5010615` | [CISCO-SCA] Suspicious DNS Over HTTPS Activity | BITS Transfer Job Download From Direct IP | `rules/windows/builtin/bits_client/win_bits_client_new_transfer_via_ip_address.yml` | 0.42 | https |
| `5008395` | [WINDOWS-MISC] Pass the Hash Detected | Pass the Hash Activity 2 | `rules/windows/builtin/security/account_management/win_security_pass_the_hash_2.yml` | 0.42 | seclogo, pass, hash, logon, network |
| `5010525` | [CISCO-SCA] Azure Firewall Deleted | All Rules Have Been Deleted From The Windows Firewall C | `rules/windows/builtin/firewall_as/win_firewall_as_delete_all_rules.yml` | 0.42 | firewall, deleted |
| `5013535` | [MYSQL] Update hostpermits in MYSQL database (CVE-2023- | OpenCanary - MySQL Login Attempt | `rules/application/opencanary/opencanary_mysql_login_attempt.yml` | 0.42 | mysql |
| `5013568` | [WINDOWS-SECURITY] Log on using default linux workstati | Locked Workstation | `rules/windows/builtin/security/win_security_workstation_was_locked.yml` | 0.42 | workstation |
| `5016616` | [CROWDSTRIKE] A process attempted to delete a Volume Sh | Delete Volume Shadow Copies Via WMI With PowerShell | `rules/windows/powershell/powershell_classic/posh_pc_delete_volume_shadow_copies.yml` | 0.42 | shadow, volume, delete |
| `5014406` | [FORTINET] New user group added | A Member Was Added to a Security-Enabled Global Group | `rules/windows/builtin/security/account_management/win_security_member_added_security_enabled_global_group.yml` | 0.42 | added, group |
| `5000005` | [BASH] /etc/shadow access | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.42 | bash |
| `5008636` | [WINDOWS-CLIPBOARD] Powershell Policy Bypass Command | Change PowerShell Policies to an Insecure Level | `rules/windows/process_creation/proc_creation_win_powershell_set_policies_to_unsecure_level.yml` | 0.42 | executionpolicy, policy, bypass, powershell |
| `5000000` | [BASH] ./a.out execution attempt | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.42 | bash, execution |
| `5007691` | [WINDOWS-POWERSHELL] Possible Resolve-DnsName IEX comma | PowerShell Base64 Encoded IEX Cmdlet | `rules/windows/process_creation/proc_creation_win_powershell_base64_iex.yml` | 0.42 | iex, powershell |
| `5001010` | [SNORT] Attempt to login by a default username and pass | DiagTrackEoP Default Login Username | `rules/windows/builtin/security/account_management/win_security_diagtrack_eop_default_login_username.yml` | 0.42 | username, default, login |
| `5002332` | [BASH] SSH X11 trusted forwarding | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.42 | bash |
| `5010532` | [CISCO-SCA] Azure Resource Group Deleted | Bitbucket Unauthorized Access To A Resource | `rules/application/bitbucket/audit/bitbucket_audit_unauthorized_access_detected.yml` | 0.42 | resource |
| `5002313` | [BASH] Ruby socket execution | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.42 | bash, execution |
| `5017580` | [CROWDSTRIKE] comsvcs.dll MiniDump usage initiated - Ki | Lsass Memory Dump via Comsvcs DLL | `rules/windows/process_access/proc_access_win_lsass_dump_comsvcs_dll.yml` | 0.42 | comsvcs.dll, minidump |
| `5013559` | [WINDOWS-FIREWALL] Firewall rule added by AnyDesk | Remote Access Tool - AnyDesk Execution With Known Revok | `rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk_revoked_cert.yml` | 0.42 | anydesk |
| `5002312` | [BASH] Perl subproces execution | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.42 | bash, execution |
| `5009404` | [WINDOWS-SECURITY] A security-enabled universal group w | A Security-Enabled Global Group Was Deleted | `rules/windows/builtin/security/account_management/win_security_security_enabled_global_group_deleted.yml` | 0.42 | security-enabled, group |
| `5003105` | [WINDOWS-MISC] CRITICAL - Installation of PSEXEC servic | PsExec Service File Creation | `rules/windows/file/file_event/file_event_win_sysinternals_psexec_service.yml` | 0.42 | psexec, installation |
| `5100135` | Citrix device detected | Registry Persistence via Service in Safe Mode | `rules/windows/registry/registry_set/registry_set_add_load_service_in_safe_mode.yml` | 0.42 | default |
| `5005958` | [WEB-ATTACKS] Log4j exploit attempt - CVE-2021-44228 | Log4j RCE CVE-2021-44228 Generic | `rules-emerging-threats/2021/Exploits/CVE-2021-44228/web_cve_2021_44228_log4j.yml` | 0.42 | cve-2021-44228, jndi, log4j |
| `5007710` | [WINDOWS-POWERSHELL] Possible ProxyShell V2 execution | Chopper Webshell Process Pattern | `rules/windows/process_creation/proc_creation_win_webshell_chopper.yml` | 0.42 | echo |
| `5010759` | [CyberArk] Add/Update Owner | Added Owner To Application | `rules/cloud/azure/audit_logs/azure_app_owner_added.yml` | 0.42 | owner |
| `5002616` | [SONICWALL] Firewall Rule Modified | Azure Firewall Rule Configuration Modified or Deleted | `rules/cloud/azure/activity_logs/azure_network_firewall_rule_modified_or_deleted.yml` | 0.42 | modified, firewall |
| `5002311` | [BASH] Perl socket execution | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.42 | bash |
| `5009372` | [WINDOWS-POWERSHELL] Possible Resolve-DnsName IEX comma | PowerShell Base64 Encoded IEX Cmdlet | `rules/windows/process_creation/proc_creation_win_powershell_base64_iex.yml` | 0.42 | iex, powershell |
| `5009300` | [WINDOWS-MISC] Pass the Hash Detected | Pass the Hash Activity 2 | `rules/windows/builtin/security/account_management/win_security_pass_the_hash_2.yml` | 0.42 | seclogo, pass, hash, logon, network |
| `5017577` | [CROWDSTRIKE] Suspicious Execution - Killed: Procdump l | Procdump Execution | `rules/windows/process_creation/proc_creation_win_sysinternals_procdump.yml` | 0.42 | procdump, execution |
| `5014403` | [FORTINET] Access profile changed | VsCode Powershell Profile Modification | `rules/windows/file/file_event/file_event_win_susp_vscode_powershell_profile.yml` | 0.42 | profile |
| `5002982` | [DYNAMIC] Linux kernel logs detected via program. | CodeIntegrity - Unsigned Kernel Module Loaded | `rules/windows/builtin/code_integrity/win_codeintegrity_unsigned_driver_loaded.yml` | 0.42 | kernel |
| `5009375` | [WINDOWS-POWERSHELL] Possible ProxyShell V2 execution | Chopper Webshell Process Pattern | `rules/windows/process_creation/proc_creation_win_webshell_chopper.yml` | 0.42 | echo |
| `5000012` | [BASH] /tmp/sh access | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.42 | bash |
| `5000013` | [BASH] suidperl access | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.42 | bash |
| `5002305` | [BASH] .mysql_history access | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.42 | bash |
| `5002307` | [BASH] Python socket execution | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.42 | bash, execution |
| `5017456` | [DYNAMIC] Sophos Firewall Logs Detected | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.42 | sophos |
| `5002615` | [SONICWALL] Firewall Rule Deleted | A Rule Has Been Deleted From The Windows Firewall Excep | `rules/windows/builtin/firewall_as/win_firewall_as_delete_rule.yml` | 0.42 | firewall, deleted |
| `5002989` | [DYNAMIC] OpenVPN logs detected via program. | Suspicious Application Installed | `rules/windows/builtin/shell_core/win_shell_core_susp_packages_installed.yml` | 0.42 | openvpn |
| `5017069` | [AWS] EC2 Export Snapshot | AWS Snapshot Backup Exfiltration | `rules/cloud/aws/cloudtrail/aws_snapshot_backup_exfiltration.yml` | 0.42 | snapshot, ec2, ec2.amazonaws.com, aws |
| `991014` | [AWS] EC2 Copy Snapshot | AWS Snapshot Backup Exfiltration | `rules/cloud/aws/cloudtrail/aws_snapshot_backup_exfiltration.yml` | 0.42 | snapshot, ec2, ec2.amazonaws.com, aws |
| `5002310` | [BASH] PHP subproces execution | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.42 | bash, execution |
| `5013729` | Apache PHP device detected | Potential PHP Reverse Shell | `rules/linux/process_creation/proc_creation_lnx_php_reverse_shell.yml` | 0.42 | php |
| `5003186` | [ZSCALER] MSF Meterpreter Default User Agent | Malware User Agent | `rules/web/proxy_generic/proxy_ua_malware.yml` | 0.42 | 6.1, mozilla/4.0, msie, compatible, agent |
| `5014406` | [FORTINET] New user group added | User Added To Group With CA Policy Modification Access | `rules/cloud/azure/audit_logs/azure_group_user_addition_ca_modification.yml` | 0.42 | added, group |
| `5015304` | [NETSKOPE] Quarantine Alert Detected (Low) | Win Defender Restored Quarantine File | `rules/windows/builtin/windefend/win_defender_restored_quarantine_file.yml` | 0.41 | quarantine |
| `5015305` | [NETSKOPE] Quarantine Alert Detected (Medium) | Win Defender Restored Quarantine File | `rules/windows/builtin/windefend/win_defender_restored_quarantine_file.yml` | 0.41 | quarantine |
| `5000377` | [SYSLOG] Information for a user was changed | Windows Firewall Settings Have Been Changed | `rules/windows/builtin/firewall_as/win_firewall_as_setting_change.yml` | 0.41 | changed |
| `5012691` | [MSEXCHANGE-MANAGEMENT] mailboxes Cmdlet New-MailboxExp | Suspicious PowerShell Mailbox Export to Share - PS | `rules/windows/powershell/powershell_script/posh_ps_mailboxexport_share.yml` | 0.41 | new-mailboxexportrequest, cmdlet |
| `5012691` | [MSEXCHANGE-MANAGEMENT] mailboxes Cmdlet New-MailboxExp | Suspicious PowerShell Mailbox Export to Share | `rules/windows/process_creation/proc_creation_win_powershell_mailboxexport_share.yml` | 0.41 | new-mailboxexportrequest, cmdlet |
| `5013536` | [MYSQL] Update hostpermits in MYSQL database (CVE-2023- | OpenCanary - MySQL Login Attempt | `rules/application/opencanary/opencanary_mysql_login_attempt.yml` | 0.41 | mysql |
| `5100016` | csh shell in use | Potentially Suspicious Shell Script Creation in Profile | `rules/linux/file_event/file_event_lnx_susp_shell_script_under_profile_directory.yml` | 0.41 | csh, shell |
| `5015852` | [MICROSOFT_DEFENDER_ENDPOINT] Potentially Unwanted Soft | Windows Defender Malware And PUA Scanning Disabled | `rules/windows/builtin/windefend/win_defender_malware_and_pua_scan_disabled.yml` | 0.41 | unwanted, pua, software, potentially |
| `5000000` | [BASH] ./a.out execution attempt | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.41 | bash |
| `5010954` | [GITHUB] Repository Removed | GitHub Repository Archive Status Changed | `rules/application/github/audit/github_repository_archive_status_changed.yml` | 0.41 | repository, github |
| `5013871` | [WINDOWS-SECURITY] Possible LSASS Dump via ProcDump | LSASS Memory Dump File Creation | `deprecated/windows/file_event_win_lsass_memory_dump_file_creation.yml` | 0.41 | procdump, lsass, dump |
| `5003416` | [WINDOWS-SECURITY] The certificate manager denied a pen | Certificate Exported From Local Certificate Store | `rules/windows/builtin/certificate_services_client_lifecycle_system/win_certificateservicesclient_lifecycle_system_cert_exported.yml` | 0.41 | certificate |
| `5012098` | [WINDOWS-SECURITY] Inbound RDP Tunneling | RDP Login from Localhost | `rules/windows/builtin/security/account_management/win_security_rdp_localhost_login.yml` | 0.41 | localhost, 127.0.0.1, rdp |
| `5100192` | Windows PowerShell device detected | PowerShell Scripts Run by a Services | `deprecated/windows/driver_load_win_powershell_script_installed_as_service.yml` | 0.41 | powershell |
| `5001083` | [SONICWALL] Possible TCP Port Scan | Testing Usage of Uncommonly Used Port | `rules/windows/powershell/powershell_script/posh_ps_test_netconnection.yml` | 0.41 | port |
| `5002313` | [BASH] Ruby socket execution | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.41 | bash |
| `5009299` | [WINDOWS-MISC] Potential Kerberoasting Activity Detecte | Suspicious Kerberos RC4 Ticket Encryption | `rules/windows/builtin/security/win_security_susp_rc4_kerberos.yml` | 0.41 | ticket, encryption, type |
| `5005959` | [WEB-ATTACKS] Log4j exploit attempt via hex encoding - | Log4j RCE CVE-2021-44228 Generic | `rules-emerging-threats/2021/Exploits/CVE-2021-44228/web_cve_2021_44228_log4j.yml` | 0.41 | cve-2021-44228, jndi, log4j |
| `5016616` | [CROWDSTRIKE] A process attempted to delete a Volume Sh | Volume Shadow Copy Mount | `rules/windows/builtin/system/microsoft_windows_ntfs/win_system_volume_shadow_copy_mount.yml` | 0.41 | shadow, volume |
| `5015944` | [WINDOWS-CORRELATED] WmiPrvse Detected After Possible R | WmiPrvSE Spawned A Process | `rules/windows/process_creation/proc_creation_win_wmiprvse_spawning_process.yml` | 0.41 | wmiprvse, wmiprvse.exe |
| `5017336` | [DYNAMIC] Azure Eventhub Windows MSSQL Logs Detected | MSSQL XPCmdshell Suspicious Execution | `rules/windows/builtin/application/mssqlserver/win_mssql_xp_cmdshell_audit_log.yml` | 0.41 | mssql |
| `5002312` | [BASH] Perl subproces execution | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.41 | bash |
| `5007987` | [WINDOWS-SYSMON] Possible DLL Hijacking of oci.dll | Registry Modification for OCI DLL Redirection | `rules/windows/registry/registry_set/registry_set_potential_oci_dll_redirection.yml` | 0.41 | oci.dll, hijacking, dll |
| `5017592` | [CROWDSTRIKE] LaZagne credential harvesting binary exec | Credential Dumping by LaZagne | `deprecated/windows/proc_access_win_lazagne_cred_dump_lsass_access.yml` | 0.41 | lazagne, credential |
| `5003360` | [PASSWORDSTATE] Security Administrator Role Updated | User Added to an Administrator's Azure AD Role | `rules/cloud/azure/audit_logs/azure_ad_user_added_to_admin_role.yml` | 0.41 | role, administrator |
| `5013815` | [WINDOWS-SECURITY] Meshagent Remote Session Interaction | Remote Access Tool - Renamed MeshAgent Execution - Wind | `rules/windows/process_creation/proc_creation_win_remote_access_tools_renamed_meshagent_execution.yml` | 0.41 | meshagent.exe, meshagent, remote |
| `5001559` | [HUAWEI] ATCKDF - Trace route attack | New Network Route Added | `rules/cloud/aws/cloudtrail/aws_cloudtrail_new_route_added.yml` | 0.41 | route |
| `5013876` | [WINDOWS-SECURITY] Credential Access - Copy NTDS file | Copy .DMP/.DUMP Files From Remote Share Via Cmd.EXE | `rules/windows/process_creation/proc_creation_win_cmd_copy_dmp_from_share.yml` | 0.41 | copy, cmd |
| `5010052` | [WINDOWS-SYSMON] Possible DLL Hijacking of oci.dll | Registry Modification for OCI DLL Redirection | `rules/windows/registry/registry_set/registry_set_potential_oci_dll_redirection.yml` | 0.41 | oci.dll, hijacking, dll |
| `5000187` | [FTPD] Remote host connected to FTP server | OpenCanary - FTP Login Attempt | `rules/application/opencanary/opencanary_ftp_login_attempt.yml` | 0.41 | ftp, login |
| `5013576` | [WINDOWS-SYSTEM] The System log file was cleared | Security Eventlog Cleared | `rules/windows/builtin/security/win_security_audit_log_cleared.yml` | 0.41 | cleared |
| `5013577` | [WINDOWS-SYSTEM] The Application log file was cleared | Security Eventlog Cleared | `rules/windows/builtin/security/win_security_audit_log_cleared.yml` | 0.41 | cleared |
| `5002307` | [BASH] Python socket execution | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.41 | bash |
| `5002318` | [BASH] /dev/udp access | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.41 | bash |
| `5012094` | [WINDOWS-SECURITY] RDP Tunnel Detected | Visual Studio Code Tunnel Execution | `rules/windows/process_creation/proc_creation_win_vscode_tunnel_execution.yml` | 0.41 | tunnel |
| `5014561` | [WINDOWS-SECURITY] Inbound RDP Tunneling | RDP Login from Localhost | `rules/windows/builtin/security/account_management/win_security_rdp_localhost_login.yml` | 0.41 | localhost, 127.0.0.1, rdp |
| `5017592` | [CROWDSTRIKE] LaZagne credential harvesting binary exec | Credentials In Files | `rules/macos/process_creation/proc_creation_macos_find_cred_in_files.yml` | 0.41 | lazagne |
| `5000934` | [FORTINET] Access profile deleted | VsCode Powershell Profile Modification | `rules/windows/file/file_event/file_event_win_susp_vscode_powershell_profile.yml` | 0.41 | profile |
| `5009412` | [WINDOWS-SECURITY] The certificate manager denied a pen | Certificate Exported From Local Certificate Store | `rules/windows/builtin/certificate_services_client_lifecycle_system/win_certificateservicesclient_lifecycle_system_cert_exported.yml` | 0.41 | certificate |
| `5015246` | [NETSKOPE] Created new admin Event Detected | Access To ADMIN$ Network Share | `rules/windows/builtin/security/win_security_admin_share_access.yml` | 0.41 | admin |
| `5003127` | [ZSCALER] known malicious user-agent string - MSIE 7.0 | Exploit Framework User Agent | `rules/web/proxy_generic/proxy_ua_frameworks.yml` | 0.41 | 7.0, mozilla/4.0, msie, compatible |
| `5006644` | [SentinelOne] Quarantine failed | Potential SentinelOne Shell Context Menu Scan Command T | `rules/windows/registry/registry_set/registry_set_sentinelone_shell_context_tampering.yml` | 0.41 | sentinelone |
| `5003054` | [CISCO-MERAKI] Blocked DHCP server response | DHCP Server Error Failed Loading the CallOut DLL | `rules/windows/builtin/system/microsoft_windows_dhcp_server/win_system_susp_dhcp_config_failed.yml` | 0.41 | dhcp, server |
| `5013747` | [NETWRIX] Logon Activity - Possible Brute Force Attempt | Outgoing Logon with New Credentials | `rules/windows/builtin/security/account_management/win_security_susp_logon_newcredentials.yml` | 0.41 | logon |
| `5000012` | [BASH] /tmp/sh access | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.41 | bash |
| `5000013` | [BASH] suidperl access | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.41 | bash |
| `5002305` | [BASH] .mysql_history access | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.41 | bash |
| `5014395` | [FORTINET] License about to expired | Invalid PIM License | `rules/cloud/azure/privileged_identity_management/azure_pim_invalid_license.yml` | 0.41 | license |
| `5015850` | [MICROSOFT_DEFENDER_ENDPOINT] Potentially Unwanted Soft | Windows Defender Malware And PUA Scanning Disabled | `rules/windows/builtin/windefend/win_defender_malware_and_pua_scan_disabled.yml` | 0.41 | unwanted, pua, software, potentially |
| `5015851` | [MICROSOFT_DEFENDER_ENDPOINT] Potentially Unwanted Soft | Windows Defender Malware And PUA Scanning Disabled | `rules/windows/builtin/windefend/win_defender_malware_and_pua_scan_disabled.yml` | 0.41 | unwanted, pua, software, potentially |
| `5002092` | [WINDOWS-APPLOCKER] Allowed an MSI or script to execute | AppLocker Prevented Application or Script from Running | `rules/windows/builtin/applocker/win_applocker_application_was_prevented_from_running.yml` | 0.41 | applocker, msi, script |
| `5008412` | [WINDOWS-APPLOCKER] Allowed an MSI or script to execute | AppLocker Prevented Application or Script from Running | `rules/windows/builtin/applocker/win_applocker_application_was_prevented_from_running.yml` | 0.41 | applocker, msi, script |
| `5100161` | AWS IAM detected | AWS IAM Backdoor Users Keys | `rules/cloud/aws/cloudtrail/aws_iam_backdoor_users_keys.yml` | 0.41 | iam.amazonaws.com, iam, aws |
| `5003134` | [ZSCALER] Win.Trojan.Darkcpn outbound connection | Exploit Framework User Agent | `rules/web/proxy_generic/proxy_ua_frameworks.yml` | 0.41 | sv1, 6.0, 5.1, mozilla/4.0, msie, compatible |
| `5008375` | [WINDOWS-CLIPBOARD] query user command | SC.EXE Query Execution | `rules-threat-hunting/windows/process_creation/proc_creation_win_sc_query.yml` | 0.41 | query |
| `5013054` | [MSEXCHANGE-MANAGEMENT] policy-and-compliance-content-s | PST Export Alert Using New-ComplianceSearchAction | `rules/cloud/m365/threat_management/microsoft365_pst_export_alert_using_new_compliancesearchaction.yml` | 0.41 | new-compliancesearchaction |
| `5010473` | [WINDOWS-CLIPBOARD] Local Admin Added | User Added to Local Administrators Group | `rules/windows/process_creation/proc_creation_win_susp_add_user_local_admin_group.yml` | 0.41 | localgroup, administrators, net, added, local |
| `5013874` | [WINDOWS-SYSMON] Password Dumper Remote Thread in LSASS | Potential Credential Dumping Attempt Via PowerShell Rem | `rules/windows/create_remote_thread/create_remote_thread_win_powershell_lsass.yml` | 0.41 | thread, lsass.exe, remote |
| `5010514` | [CISCO-SCA] AWS Lambda Persistence | AWS Lambda Function Created or Invoked | `unsupported/cloud/aws_lambda_function_created_or_invoked.yml` | 0.41 | lambda, aws |
| `5004784` | [WINDOWS-MALWARE] Ryuk ransomware extension detected. | Ryuk Ransomware Command Line Activity | `deprecated/windows/proc_creation_win_mal_ryuk.yml` | 0.41 | ryuk, ransomware |
| `5017577` | [CROWDSTRIKE] Suspicious Execution - Killed: Procdump l | Renamed ProcDump Execution | `rules/windows/process_creation/proc_creation_win_renamed_sysinternals_procdump.yml` | 0.41 | procdump, execution |
| `5008781` | [WINDOWS-MALWARE] Ryuk ransomware extension detected. | Ryuk Ransomware Command Line Activity | `deprecated/windows/proc_creation_win_mal_ryuk.yml` | 0.41 | ryuk, ransomware |
| `5001018` | [KISMET] Detected new data network | Potential Browser Data Stealing | `rules/windows/process_creation/proc_creation_win_susp_copy_browser_data.yml` | 0.41 | data |
| `5010843` | [CyberArk] Add Group Member | A Member Was Added to a Security-Enabled Global Group | `rules/windows/builtin/security/account_management/win_security_member_added_security_enabled_global_group.yml` | 0.41 | member, group |
| `5005550` | [CLOUDTRAIL] RDS cloudtrail event detected - (RestoreDB | Restore Public AWS RDS Instance | `rules/cloud/aws/cloudtrail/aws_rds_public_db_restore.yml` | 0.41 | restoredbinstancefromdbsnapshot, rds.amazonaws.com, rds |
| `5013811` | [WINDOWS-SECURITY] wmic process call create ntdsutil | Ntdsutil Abuse | `rules/windows/builtin/application/esent/win_esent_ntdsutil_abuse.yml` | 0.41 | ntdsutil |
| `5013887` | [WINDOWS-SECURITY] net group /domain command executed | Reconnaissance Activity | `rules/windows/builtin/security/win_security_susp_net_recon_activity.yml` | 0.41 | net, domain, group |
| `5017069` | [AWS] EC2 Export Snapshot | AWS EC2 VM Export Failure | `rules/cloud/aws/cloudtrail/aws_ec2_vm_export_failure.yml` | 0.41 | export, ec2, ec2.amazonaws.com, aws |
| `5000998` | [SNORT] A client was using an unusual port | MSSQL Server Failed Logon From External Network | `rules/windows/builtin/application/mssqlserver/win_mssql_failed_logon_from_external_network.yml` | 0.41 | client |
| `5001041` | [HOSTAPD] Possible downgrade attack | PowerShell Downgrade Attack - PowerShell | `rules/windows/powershell/powershell_classic/posh_pc_downgrade_attack.yml` | 0.41 | downgrade, attack |
| `5007148` | [WINDOWS-POWERSHELL] Schtask Created to Base64 Decode P | Base64 Encoded PowerShell Command Detected | `rules/windows/process_creation/proc_creation_win_powershell_frombase64string.yml` | 0.41 | decode, frombase64string, base64, powershell |
| `5008646` | [WINDOWS-CLIPBOARD] query user command | SC.EXE Query Execution | `rules-threat-hunting/windows/process_creation/proc_creation_win_sc_query.yml` | 0.41 | query |
| `5014404` | [FORTINET] Access profile deleted | VsCode Powershell Profile Modification | `rules/windows/file/file_event/file_event_win_susp_vscode_powershell_profile.yml` | 0.41 | profile |
| `5008041` | [WINDOWS-SYSMON] Possible DLL Hijacking of shell32.dll | Shell32 DLL Execution in Suspicious Directory | `rules/windows/process_creation/proc_creation_win_rundll32_shell32_susp_execution.yml` | 0.40 | shell32.dll, dll |
| `5014326` | [WINDOWS-POWERSHELL] PowerShell Script to find all Comp | Active Directory Computers Enumeration With Get-AdCompu | `rules/windows/powershell/powershell_script/posh_ps_get_adcomputer.yml` | 0.40 | get-adcomputer, computers |
| `5015968` | [WINDOWS-SYSMON] Process Hacker Kernel Driver Load | CodeIntegrity - Revoked Kernel Driver Loaded | `rules/windows/builtin/code_integrity/win_codeintegrity_revoked_driver_loaded.yml` | 0.40 | kernel, driver, load |
| `5015972` | [WINDOWS-SYSMON] Process Hacker Kernel Driver Load | CodeIntegrity - Revoked Kernel Driver Loaded | `rules/windows/builtin/code_integrity/win_codeintegrity_revoked_driver_loaded.yml` | 0.40 | kernel, driver, load |
| `5002323` | [BASH] stunnel execution | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.40 | bash, execution |
| `5005539` | [CLOUDTRAIL] RDS cloudtrail event detected - (ModifyDBI | AWS RDS Master Password Change | `rules/cloud/aws/cloudtrail/aws_rds_change_master_password.yml` | 0.40 | modifydbinstance, rds.amazonaws.com, rds |
| `5008442` | [WINDOWS-AUTH] A member was added to a security-enabled | A Security-Enabled Global Group Was Deleted | `rules/windows/builtin/security/account_management/win_security_security_enabled_global_group_deleted.yml` | 0.40 | security-enabled, group |
| `5008368` | [WINDOWS-CLIPBOARD] Uninstall Windows Defender Command | Suspicious Uninstall of Windows Defender Feature via Po | `rules/windows/process_creation/proc_creation_win_powershell_uninstall_defender_feature.yml` | 0.40 | uninstall-windowsfeature, windows-defender, uninstall, defender |
| `5009760` | [WINDOWS-SECURITY] A security-enabled local group membe | User Removed From Group With CA Policy Modification Acc | `rules/cloud/azure/audit_logs/azure_group_user_removal_ca_modification.yml` | 0.40 | membership, group |
| `5007154` | [WINDOWS-POWERSHELL] Local User Created | PowerShell Create Local User | `rules/windows/powershell/powershell_script/posh_ps_create_local_user.yml` | 0.40 | new-localuser, local, powershell |
| `5003111` | [NXLOG] Missing Windows Log Message | Obfuscated IP Via CLI | `rules/windows/process_creation/proc_creation_win_susp_obfuscated_ip_via_cli.yml` | 0.40 | 0-9 |
| `5006643` | [SentinelOne] Kill failed | Potential SentinelOne Shell Context Menu Scan Command T | `rules/windows/registry/registry_set/registry_set_sentinelone_shell_context_tampering.yml` | 0.40 | sentinelone |
| `5013890` | [WINDOWS-SECURITY] net group domain admins command exec | Potential Exploitation of CVE-2024-37085 - Suspicious E | `rules-emerging-threats/2024/Exploits/CVE-2024-37085/win_security_exploit_cve_2024_37085_esxi_admins_group.yml` | 0.40 | admins, domain, group |
| `5008372` | [WINDOWS-CLIPBOARD] rundll32 command with DllRegisterSe | IcedID Malware Suspicious Single Digit DLL Execution Vi | `rules-emerging-threats/2023/Malware/IcedID/proc_creation_win_malware_icedid_rundll32_dllregisterserver.yml` | 0.40 | dllregisterserver, rundll32, rundll32.exe |
| `5010106` | [WINDOWS-SYSMON] Possible DLL Hijacking of shell32.dll | Shell32 DLL Execution in Suspicious Directory | `rules/windows/process_creation/proc_creation_win_rundll32_shell32_susp_execution.yml` | 0.40 | shell32.dll, dll |
| `5007370` | [SOPHOS] Detected malware | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.40 | endpoint, sophos |
| `5007388` | [SOPHOS] Malware detected | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.40 | endpoint, sophos |
| `5010627` | [CISCO-SCA] Vulnerable Transport Security Protocol | MSExchange Transport Agent Installation | `rules/windows/process_creation/proc_creation_win_powershell_msexchange_transport_agent.yml` | 0.40 | transport |
| `5013835` | [WINDOWS-SYSMON] CMD set in Registry Key | Windows Webshell Strings | `rules/web/webserver_generic/web_win_webshells_in_access_logs.yml` | 0.40 | cmd |
| `5002698` | [SONICWALL] Intrusion Detection - Probable port scan de | OpenCanary - Host Port Scan (SYN Scan) | `rules/application/opencanary/opencanary_portscan_syn_scan.yml` | 0.40 | port, scan |
| `5002314` | [BASH] Ruby subproces execution | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.40 | bash, execution |
| `5015078` | [WINDOWS-SECURITY] Sticky Key Backdoor Execution | Suspicious Debugger Registration Cmdline | `rules/windows/process_creation/proc_creation_win_registry_install_reg_debugger_backdoor.yml` | 0.40 | helppane.exe, magnify.exe, utilman.exe, sethc.exe, sticky, backdoor |
| `5010514` | [CISCO-SCA] AWS Lambda Persistence | New AWS Lambda Function URL Configuration Created | `rules/cloud/aws/cloudtrail/aws_lambda_function_url.yml` | 0.40 | lambda, aws |
| `5016599` | [CROWDSTRIKE] This file is classified as Adware/PUP bas | Renamed Cloudflared.EXE Execution | `rules/windows/process_creation/proc_creation_win_renamed_cloudflared.yml` | 0.40 | sha256 |
| `5100189` | Sophos device detected | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.40 | sophos |
| `5008639` | [WINDOWS-CLIPBOARD] Uninstall Windows Defender Command | Suspicious Uninstall of Windows Defender Feature via Po | `rules/windows/process_creation/proc_creation_win_powershell_uninstall_defender_feature.yml` | 0.40 | uninstall-windowsfeature, windows-defender, uninstall, defender |
| `5010844` | [CyberArk] Delete Group Member | A Member Was Added to a Security-Enabled Global Group | `rules/windows/builtin/security/account_management/win_security_member_added_security_enabled_global_group.yml` | 0.40 | member, group |
| `5008643` | [WINDOWS-CLIPBOARD] rundll32 command with DllRegisterSe | IcedID Malware Suspicious Single Digit DLL Execution Vi | `rules-emerging-threats/2023/Malware/IcedID/proc_creation_win_malware_icedid_rundll32_dllregisterserver.yml` | 0.40 | dllregisterserver, rundll32, rundll32.exe |
| `5015242` | [NETSKOPE] Login Successful After Brute Force Event Det | Successful Account Login Via WMI | `rules/windows/builtin/security/account_management/win_security_susp_wmi_login.yml` | 0.40 | successful, login |
| `5100057` | Generic syslog service detected | ESXi Syslog Configuration Change Via ESXCLI | `rules/linux/process_creation/proc_creation_lnx_esxcli_syslog_config_change.yml` | 0.40 | syslog |
| `5002309` | [BASH] PHP socket execution | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.40 | bash, execution |
| `5010572` | [CISCO-SCA] New AWS Lambda Invoke Permission Added | AWS Lambda Function Created or Invoked | `unsupported/cloud/aws_lambda_function_created_or_invoked.yml` | 0.40 | lambda, invoke, aws |
| `5015941` | [WINDOWS-SYSMON] Cobalt Strike Beacon Detected | Default Cobalt Strike Certificate | `rules/network/zeek/zeek_default_cobalt_strike_certificate.yml` | 0.40 | strike, cobalt |
| `5003186` | [ZSCALER] MSF Meterpreter Default User Agent | Exploit Framework User Agent | `rules/web/proxy_generic/proxy_ua_frameworks.yml` | 0.40 | 6.1, mozilla/4.0, msie, compatible, agent |
| `5007329` | [SOPHOS] Malicious traffic detected | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.40 | endpoint, sophos, threat |
| `5007331` | [SOPHOS] Malicious traffic detected | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.40 | endpoint, sophos, threat |
| `5003388` | [WINDOWS-SYSMON] SYSMON Possible CMD detected | Suspicious Service Path Modification | `rules/windows/process_creation/proc_creation_win_sc_service_path_modification.yml` | 0.40 | cmd, cmd.exe |
| `5000056` | [SYSLOG] Kernel TCP/IP redirect attempt | CMD Shell Output Redirect | `rules-threat-hunting/windows/process_creation/proc_creation_win_cmd_redirect.yml` | 0.40 | redirect |
| `5014557` | [WINDOWS-SECURITY] RDP Tunnel Detected | Visual Studio Code Tunnel Execution | `rules/windows/process_creation/proc_creation_win_vscode_tunnel_execution.yml` | 0.40 | tunnel |
| `5014583` | [WINDOWS-SYSMON] GitHub Cloning Of BloodHoundAD Detecte | OpenCanary - GIT Clone Request | `rules/application/opencanary/opencanary_git_clone_request.yml` | 0.40 | clone, git |
| `5002667` | [SONICWALL] Guest account deleted | User State Changed From Guest To Member | `rules/cloud/azure/audit_logs/azure_guest_to_member.yml` | 0.40 | guest |
| `5009792` | [WINDOWS-SYSMON] SYSMON Possible CMD detected | Suspicious Service Path Modification | `rules/windows/process_creation/proc_creation_win_sc_service_path_modification.yml` | 0.40 | cmd, cmd.exe |
| `5002666` | [SONICWALL] Guest account created | User State Changed From Guest To Member | `rules/cloud/azure/audit_logs/azure_guest_to_member.yml` | 0.40 | guest |
| `5007370` | [SOPHOS] Detected malware | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.40 | endpoint, sophos, malware |
| `5007388` | [SOPHOS] Malware detected | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.40 | endpoint, sophos, malware |
| `5013890` | [WINDOWS-SECURITY] net group domain admins command exec | Potential Exploitation of CVE-2024-37085 - Suspicious C | `rules-emerging-threats/2024/Exploits/CVE-2024-37085/proc_creation_win_exploit_cve_2024_37085_esxi_admins_group_creation.yml` | 0.40 | admins, domain, group |
| `5008406` | [WINDOWS-MISC] Potential AS-REP Roasting Activity Detec | Suspicious Kerberos RC4 Ticket Encryption | `rules/windows/builtin/security/win_security_susp_rc4_kerberos.yml` | 0.40 | 0x17, ticket, encryption, type |
| `5000010` | [BASH] HISTORY=/dev/null | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.40 | bash |
| `5017068` | [AWS] EC2 Delete Disk Snapshot | AWS Snapshot Backup Exfiltration | `rules/cloud/aws/cloudtrail/aws_snapshot_backup_exfiltration.yml` | 0.40 | snapshot, ec2, ec2.amazonaws.com, aws |
| `5005906` | [DARKTRACE] A device has deleted an anomalous volume of | Microsoft 365 - Unusual Volume of File Deletion | `rules/cloud/m365/threat_management/microsoft365_unusual_volume_of_file_deletion.yml` | 0.40 | volume, unusual, deleted |
| `5005762` | [WINDOWS-POWERSHELL] HostVersion and EngineVersion MixM | PowerShell Called from an Executable Version Mismatch | `rules/windows/powershell/powershell_classic/posh_pc_exe_calling_ps.yml` | 0.40 | hostversion, engineversion, powershell |
| `5007902` | [WINDOWS-SYSMON] Possible DLL Hijacking of iphlpapi.dll | Malicious DLL File Dropped in the Teams or OneDrive Fol | `rules/windows/file/file_event/file_event_win_iphlpapi_dll_sideloading.yml` | 0.40 | iphlpapi.dll, dll |
| `5005651` | [LINUX-AUDITD] base64 execution | Decode Base64 Encoded Text | `rules/linux/process_creation/proc_creation_lnx_base64_decode.yml` | 0.40 | base64 |
| `5000149` | [MYSQL] Access denied for user | OpenCanary - MySQL Login Attempt | `rules/application/opencanary/opencanary_mysql_login_attempt.yml` | 0.40 | mysql |
| `5009320` | [WINDOWS-POWERSHELL] HostVersion and EngineVersion MixM | PowerShell Called from an Executable Version Mismatch | `rules/windows/powershell/powershell_classic/posh_pc_exe_calling_ps.yml` | 0.40 | hostversion, engineversion, powershell |
| `5015084` | [WINDOWS-POWERSHELL] Windows Defender Uninstalled via P | Uncommon PowerShell Hosts | `rules-threat-hunting/windows/powershell/powershell_classic/posh_pc_alternate_powershell_hosts.yml` | 0.40 | hostapplication, powershell |
| `5005758` | [WINDOWS-POWERSHELL] HostVersion and EngineVersion MixM | PowerShell Called from an Executable Version Mismatch | `rules/windows/powershell/powershell_classic/posh_pc_exe_calling_ps.yml` | 0.40 | hostversion, engineversion, powershell |
| `5005759` | [WINDOWS-POWERSHELL] HostVersion and EngineVersion MixM | PowerShell Called from an Executable Version Mismatch | `rules/windows/powershell/powershell_classic/posh_pc_exe_calling_ps.yml` | 0.40 | hostversion, engineversion, powershell |
| `5005760` | [WINDOWS-POWERSHELL] HostVersion and EngineVersion MixM | PowerShell Called from an Executable Version Mismatch | `rules/windows/powershell/powershell_classic/posh_pc_exe_calling_ps.yml` | 0.40 | hostversion, engineversion, powershell |
| `5005763` | [WINDOWS-POWERSHELL] HostVersion and EngineVersion MixM | PowerShell Called from an Executable Version Mismatch | `rules/windows/powershell/powershell_classic/posh_pc_exe_calling_ps.yml` | 0.40 | hostversion, engineversion, powershell |
| `5005764` | [WINDOWS-POWERSHELL] HostVersion and EngineVersion MixM | PowerShell Called from an Executable Version Mismatch | `rules/windows/powershell/powershell_classic/posh_pc_exe_calling_ps.yml` | 0.40 | hostversion, engineversion, powershell |
| `5009316` | [WINDOWS-POWERSHELL] HostVersion and EngineVersion MixM | PowerShell Called from an Executable Version Mismatch | `rules/windows/powershell/powershell_classic/posh_pc_exe_calling_ps.yml` | 0.40 | hostversion, engineversion, powershell |
| `5009317` | [WINDOWS-POWERSHELL] HostVersion and EngineVersion MixM | PowerShell Called from an Executable Version Mismatch | `rules/windows/powershell/powershell_classic/posh_pc_exe_calling_ps.yml` | 0.40 | hostversion, engineversion, powershell |
| `5009318` | [WINDOWS-POWERSHELL] HostVersion and EngineVersion MixM | PowerShell Called from an Executable Version Mismatch | `rules/windows/powershell/powershell_classic/posh_pc_exe_calling_ps.yml` | 0.40 | hostversion, engineversion, powershell |
| `5009321` | [WINDOWS-POWERSHELL] HostVersion and EngineVersion MixM | PowerShell Called from an Executable Version Mismatch | `rules/windows/powershell/powershell_classic/posh_pc_exe_calling_ps.yml` | 0.40 | hostversion, engineversion, powershell |
| `5009322` | [WINDOWS-POWERSHELL] HostVersion and EngineVersion MixM | PowerShell Called from an Executable Version Mismatch | `rules/windows/powershell/powershell_classic/posh_pc_exe_calling_ps.yml` | 0.40 | hostversion, engineversion, powershell |
| `5009967` | [WINDOWS-SYSMON] Possible DLL Hijacking of iphlpapi.dll | Malicious DLL File Dropped in the Teams or OneDrive Fol | `rules/windows/file/file_event/file_event_win_iphlpapi_dll_sideloading.yml` | 0.40 | iphlpapi.dll, dll |
| `5013932` | [WINDOWS-SECURITY] Possible Ransomware - vssadmin creat | Conti Volume Shadow Listing | `rules-emerging-threats/2021/Malware/Conti/proc_creation_win_malware_conti.yml` | 0.40 | vssadmin, shadow |
| `5002303` | [BASH] History hiding | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.40 | bash |
| `5009760` | [WINDOWS-SECURITY] A security-enabled local group membe | User Added To Group With CA Policy Modification Access | `rules/cloud/azure/audit_logs/azure_group_user_addition_ca_modification.yml` | 0.40 | membership, group |
| `5014645` | [MSAPI-AZUREAD] Security Operator role assigned to Memb | Privileged Account Creation | `rules/cloud/azure/audit_logs/azure_privileged_account_creation.yml` | 0.40 | member, role, add |
| `5000056` | [SYSLOG] Kernel TCP/IP redirect attempt | Suspicious RDP Redirect Using TSCON | `rules/windows/process_creation/proc_creation_win_tscon_rdp_redirect.yml` | 0.40 | redirect |
| `5005876` | [DARKTRACE] A device is communicating with the Tor netw | Tor Client/Browser Execution | `rules/windows/process_creation/proc_creation_win_browsers_tor_execution.yml` | 0.40 | tor |
| `5009301` | [WINDOWS-MISC] Potential AS-REP Roasting Activity Detec | Suspicious Kerberos RC4 Ticket Encryption | `rules/windows/builtin/security/win_security_susp_rc4_kerberos.yml` | 0.40 | 0x17, ticket, encryption, type |
| `5007147` | [WINDOWS-POWERSHELL] Suspicious Invoke-RestMethod Comma | Potential DLL File Download Via PowerShell Invoke-WebRe | `rules/windows/process_creation/proc_creation_win_powershell_download_dll.yml` | 0.40 | invoke-restmethod, irm, http, powershell |
| `5006807` | [WINDOWS-MALWARE] Locky ransomware file extension detec | Suspicious Unsigned Thor Scanner Execution | `rules/windows/image_load/image_load_thor_unsigned_execution.yml` | 0.40 | thor |
| `5007008` | [WINDOWS-MALWARE] Locky ransomware file extension detec | Suspicious Unsigned Thor Scanner Execution | `rules/windows/image_load/image_load_thor_unsigned_execution.yml` | 0.40 | thor |
| `5007289` | [SOPHOS] Unknown violation | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.40 | endpoint, sophos |
| `5005766` | [DYNAMIC] PowerShell logs detect via program | PowerShell Scripts Run by a Services | `deprecated/windows/driver_load_win_powershell_script_installed_as_service.yml` | 0.40 | powershell |
| `5007290` | [SOPHOS] Application was blocked by an endpoint firewal | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.40 | endpoint, sophos |
| `5013887` | [WINDOWS-SECURITY] net group /domain command executed | Automated Turla Group Lateral Movement | `unsupported/windows/proc_creation_win_correlation_apt_turla_commands_medium.yml` | 0.40 | net, domain, group |
| `5008883` | [WINDOWS-MALWARE] Locky ransomware file extension detec | Suspicious Unsigned Thor Scanner Execution | `rules/windows/image_load/image_load_thor_unsigned_execution.yml` | 0.40 | thor |
| `5009084` | [WINDOWS-MALWARE] Locky ransomware file extension detec | Suspicious Unsigned Thor Scanner Execution | `rules/windows/image_load/image_load_thor_unsigned_execution.yml` | 0.40 | thor |
| `5013569` | [WINDOWS-SECURITY] Log on using Non-Standard Workstatio | Locked Workstation | `rules/windows/builtin/security/win_security_workstation_was_locked.yml` | 0.40 | workstation |
| `5000931` | [FORTINET] New access profile added | VsCode Powershell Profile Modification | `rules/windows/file/file_event/file_event_win_susp_vscode_powershell_profile.yml` | 0.40 | profile |
| `5017569` | [CROWDSTRIKE] Suspicious Execution Detected - PsExec ex | PsExec Service File Creation | `rules/windows/file/file_event/file_event_win_sysinternals_psexec_service.yml` | 0.40 | psexec, execution |
| `5000122` | [SYSLOG] Physical root login | Root Certificate Installed | `deprecated/windows/proc_creation_win_root_certificate_installed.yml` | 0.40 | root |
| `5007384` | [SOPHOS] AMSI Protection blocked a threat | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.40 | protection, endpoint, sophos, threat |
| `5007385` | [SOPHOS] AMSI Protection blocked a threat | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.40 | protection, endpoint, sophos, threat |
| `5010458` | [WINDOWS-SECURITY] Fax service installed - Possible Bla | Change User Account Associated with the FAX Service | `rules/windows/registry/registry_set/registry_set_fax_change_service_user.yml` | 0.40 | fax |
| `5010949` | [GITHUB] Member Removed | New Github Organization Member Added | `rules/application/github/audit/github_new_org_member.yml` | 0.40 | member, github |
| `5010759` | [CyberArk] Add/Update Owner | Azure Owner Removed From Application or Service Princip | `rules/cloud/azure/audit_logs/azure_owner_removed_from_application_or_service_principal.yml` | 0.40 | owner |
| `5011302` | [CARBONBLACK-APP-CONTROL] Multiple failed logins (Warni | Failed NTLM Logins with Different Accounts from Single | `unsupported/windows/win_security_susp_failed_logons_single_source2.yml` | 0.40 | logins, failed |
| `5010617` | [CISCO-SCA] Suspicious SMB Activity | External Remote SMB Logon from Public IP | `rules/windows/builtin/security/account_management/win_security_successful_external_remote_smb_login.yml` | 0.40 | smb |
| `5007259` | [SOPHOS] New protected | CodeIntegrity - Disallowed File For Protected Processes | `rules/windows/builtin/code_integrity/win_codeintegrity_blocked_protected_process_file.yml` | 0.40 | protected |
| `5007141` | [WINDOWS-POWERSHELL] Suspicious XOR Command | Potential Xor Encoded PowerShell Command | `deprecated/windows/proc_creation_win_powershell_xor_encoded_command.yml` | 0.39 | xor, bxor, powershell |
| `5013876` | [WINDOWS-SECURITY] Credential Access - Copy NTDS file | Suspicious Process Patterns NTDS.DIT Exfil | `rules/windows/process_creation/proc_creation_win_susp_ntds.yml` | 0.39 | ntds, ntds.dit, copy |
| `5007138` | [WINDOWS-POWERSHELL] .NET Assembly Loaded | Assembly DLL Creation Via AspNetCompiler | `rules/windows/file/file_event/file_event_win_aspnet_temp_files.yml` | 0.39 | aspnet_compiler.exe, assembly |
| `5009296` | [WINDOWS-MISC] Installation of PSEXEC service via SCM | PsExec Service Installation | `rules/windows/builtin/system/service_control_manager/win_system_service_install_sysinternals_psexec.yml` | 0.39 | psexec, installation |
| `5003388` | [WINDOWS-SYSMON] SYSMON Possible CMD detected | Schtasks From Suspicious Folders | `rules/windows/process_creation/proc_creation_win_schtasks_folder_combos.yml` | 0.39 | cmd, cmd.exe |
| `5010596` | [CISCO-SCA] Public Amazon Route 53 Hosted Zone Created | Potentially Suspicious File Download From ZIP TLD | `rules/windows/create_stream_hash/create_stream_hash_zip_tld_download.yml` | 0.39 | zone |
| `5005278` | [MS-DEFENDER] Real-Time Protection Is Disabled | Microsoft Defender Tamper Protection Trigger | `rules/windows/builtin/windefend/win_defender_tamper_protection_trigger.yml` | 0.39 | real-time, protection |
| `5007141` | [WINDOWS-POWERSHELL] Suspicious XOR Command | bXOR Operator Usage In PowerShell Command Line - PowerS | `rules-threat-hunting/windows/powershell/powershell_classic/posh_pc_bxor_operator_usage.yml` | 0.39 | xor, bxor, powershell |
| `5000000` | [BASH] ./a.out execution attempt | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.39 | bash, execution |
| `5007329` | [SOPHOS] Malicious traffic detected | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.39 | endpoint, sophos |
| `5007331` | [SOPHOS] Malicious traffic detected | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.39 | endpoint, sophos |
| `5009360` | [WINDOWS-POWERSHELL] Suspicious Invoke-RestMethod Comma | Potential DLL File Download Via PowerShell Invoke-WebRe | `rules/windows/process_creation/proc_creation_win_powershell_download_dll.yml` | 0.39 | invoke-restmethod, irm, http, powershell |
| `5010844` | [CyberArk] Delete Group Member | A Member Was Removed From a Security-Enabled Global Gro | `rules/windows/builtin/security/account_management/win_security_member_removed_security_enabled_global_group.yml` | 0.39 | member, group |
| `5004767` | [AZURE-EVENTHUB-AD] Risk Event Detected - investigation | Azure AD Threat Intelligence | `rules/cloud/azure/identity_protection/azure_identity_protection_threat_intel.yml` | 0.39 | investigationsthreatintelligence |
| `5007290` | [SOPHOS] Application was blocked by an endpoint firewal | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.39 | endpoint, sophos |
| `5014548` | [WINDOWS-SECURITY] Fax service installed - Possible Bla | Change User Account Associated with the FAX Service | `rules/windows/registry/registry_set/registry_set_fax_change_service_user.yml` | 0.39 | fax |
| `5002312` | [BASH] Perl subproces execution | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.39 | bash, execution |
| `5009792` | [WINDOWS-SYSMON] SYSMON Possible CMD detected | Schtasks From Suspicious Folders | `rules/windows/process_creation/proc_creation_win_schtasks_folder_combos.yml` | 0.39 | cmd, cmd.exe |
| `5016599` | [CROWDSTRIKE] This file is classified as Adware/PUP bas | Cloudflared Quick Tunnel Execution | `rules/windows/process_creation/proc_creation_win_cloudflared_quicktunnel_execution.yml` | 0.39 | sha256 |
| `5005527` | [CLOUDTRAIL] RDS cloudtrail event detected - (DeleteDBC | Modification or Deletion of an AWS RDS Cluster | `rules/cloud/aws/cloudtrail/aws_rds_dbcluster_actions.yml` | 0.39 | deletedbcluster, rds.amazonaws.com, rds |
| `5005537` | [CLOUDTRAIL] RDS cloudtrail event detected - (ModifyDBC | Modification or Deletion of an AWS RDS Cluster | `rules/cloud/aws/cloudtrail/aws_rds_dbcluster_actions.yml` | 0.39 | modifydbcluster, rds.amazonaws.com, rds |
| `5006637` | [SentinelOne] Agent disabled | Potential SentinelOne Shell Context Menu Scan Command T | `rules/windows/registry/registry_set/registry_set_sentinelone_shell_context_tampering.yml` | 0.39 | sentinelone, agent |
| `5007645` | [DYNAMIC] ntp logs detected via program. | OpenCanary - NTP Monlist Request | `rules/application/opencanary/opencanary_ntp_monlist.yml` | 0.39 | ntp |
| `5013870` | [WINDOWS-SECURITY] LSASS Dump via ProcDump | LSASS Memory Dump File Creation | `deprecated/windows/file_event_win_lsass_memory_dump_file_creation.yml` | 0.39 | procdump, lsass, dump |
| `5015935` | [WINDOWS-SYSMON] Reg Add Executed by Batch File | Potential Persistence Attempt Via Existing Service Tamp | `rules/windows/process_creation/proc_creation_win_sc_service_tamper_for_persistence.yml` | 0.39 | reg, bat, cmd, add |
| `` | Aggregate of rules setting Sagan bit recon | Curl Web Request With Potential Custom User-Agent | `rules/windows/process_creation/proc_creation_win_curl_custom_user_agent.yml` | 0.39 | user-agent |
| `5001605` | [MONGODB] Admin command received from client | MSSQL Server Failed Logon From External Network | `rules/windows/builtin/application/mssqlserver/win_mssql_failed_logon_from_external_network.yml` | 0.39 | client |
| `5005622` | [LINUX-AUDITD] nmap execution | OpenCanary - NMAP NULL Scan | `rules/application/opencanary/opencanary_portscan_nmap_null_scan.yml` | 0.39 | nmap |
| `5100053` | sshd detected | Potential Exploitation of CVE-2024-3094 - Suspicious SS | `rules-emerging-threats/2024/Exploits/CVE-2024-3094/proc_creation_lnx_exploit_cve_2024_3094_sshd_child_process.yml` | 0.39 | sshd |
| `5009354` | [WINDOWS-POWERSHELL] Suspicious XOR Command | Potential Xor Encoded PowerShell Command | `deprecated/windows/proc_creation_win_powershell_xor_encoded_command.yml` | 0.39 | xor, bxor, powershell |
| `5014327` | [WINDOWS-SECURITY] PowerShell Invoke Web-Request Detect | Potential DLL File Download Via PowerShell Invoke-WebRe | `rules/windows/process_creation/proc_creation_win_powershell_download_dll.yml` | 0.39 | iwr, invoke-webrequest, powershell |
| `5008369` | [WINDOWS-CLIPBOARD] Remoe-exec psexec command | PsExec Service Start | `deprecated/windows/proc_creation_win_sysinternals_psexesvc_start.yml` | 0.39 | psexec |
| `5015071` | [WINDOWS-SECURITY] Impacket PsExec Named PIPE | PsExec Default Named Pipe | `rules-threat-hunting/windows/pipe_created/pipe_created_sysinternals_psexec_default_pipe.yml` | 0.39 | psexec, pipe, named |
| `5010586` | [CISCO-SCA] Permissive Amazon Elastic Kubernetes Servic | New Kubernetes Service Account Created | `rules/application/kubernetes/audit/kubernetes_audit_serviceaccount_creation.yml` | 0.39 | cluster, kubernetes, created |
| `5005761` | [WINDOWS-POWERSHELL] HostVersion and EngineVersion MixM | PowerShell Called from an Executable Version Mismatch | `rules/windows/powershell/powershell_classic/posh_pc_exe_calling_ps.yml` | 0.39 | hostversion, engineversion, powershell |
| `5009351` | [WINDOWS-POWERSHELL] .NET Assembly Loaded | Assembly DLL Creation Via AspNetCompiler | `rules/windows/file/file_event/file_event_win_aspnet_temp_files.yml` | 0.39 | aspnet_compiler.exe, assembly |
| `5009354` | [WINDOWS-POWERSHELL] Suspicious XOR Command | bXOR Operator Usage In PowerShell Command Line - PowerS | `rules-threat-hunting/windows/powershell/powershell_classic/posh_pc_bxor_operator_usage.yml` | 0.39 | xor, bxor, powershell |
| `5002308` | [BASH] Python subproces execution | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.39 | bash, execution |
| `5003111` | [NXLOG] Missing Windows Log Message | Obfuscated IP Download Activity | `rules/windows/process_creation/proc_creation_win_susp_obfuscated_ip_download.yml` | 0.39 | 0-9 |
| `5004314` | [ZINGBOX] Username same as password in FTP login | OpenCanary - FTP Login Attempt | `rules/application/opencanary/opencanary_ftp_login_attempt.yml` | 0.39 | ftp, login |
| `5007738` | [WINDOWS-SYSMON] Possible DLL Hijacking of log.dll | Potential Antivirus Software DLL Sideloading | `rules/windows/image_load/image_load_side_load_antivirus.yml` | 0.39 | log.dll, bitdefender, free, antivirus, x86, program |
| `5015084` | [WINDOWS-POWERSHELL] Windows Defender Uninstalled via P | Renamed Powershell Under Powershell Channel | `rules/windows/powershell/powershell_classic/posh_pc_renamed_powershell.yml` | 0.39 | hostapplication, powershell |
| `5009319` | [WINDOWS-POWERSHELL] HostVersion and EngineVersion MixM | PowerShell Called from an Executable Version Mismatch | `rules/windows/powershell/powershell_classic/posh_pc_exe_calling_ps.yml` | 0.39 | hostversion, engineversion, powershell |
| `5009803` | [WINDOWS-SYSMON] Possible DLL Hijacking of log.dll | Potential Antivirus Software DLL Sideloading | `rules/windows/image_load/image_load_side_load_antivirus.yml` | 0.39 | log.dll, bitdefender, free, antivirus, x86, program |
| `5009772` | [WINDOWS-SECURITY] Exfil software rclone detected | Rclone Execution via Command Line or PowerShell | `deprecated/windows/win_susp_rclone_exec.yml` | 0.39 | rclone |
| `5014401` | [FORTINET] New access profile added | VsCode Powershell Profile Modification | `rules/windows/file/file_event/file_event_win_susp_vscode_powershell_profile.yml` | 0.39 | profile |
| `5007374` | [SOPHOS] Detected PUA | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.39 | endpoint, sophos |
| `5007390` | [SOPHOS] PUA detected | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.39 | endpoint, sophos |
| `5005295` | [CLOUDTRAIL] IAM cloudtrail event detected - (ConsoleLo | AWS ConsoleLogin Failed Authentication | `rules/cloud/aws/cloudtrail/aws_cloudtrail_console_login_failed_authentication.yml` | 0.39 | consolelogin |
| `5002303` | [BASH] History hiding | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.39 | bash |
| `5008640` | [WINDOWS-CLIPBOARD] Remoe-exec psexec command | PsExec Service Start | `deprecated/windows/proc_creation_win_sysinternals_psexesvc_start.yml` | 0.39 | psexec |
| `5010525` | [CISCO-SCA] Azure Firewall Deleted | Azure Firewall Rule Configuration Modified or Deleted | `rules/cloud/azure/activity_logs/azure_network_firewall_rule_modified_or_deleted.yml` | 0.39 | firewall, azure, deleted |
| `5002566` | [SU] root password change attempt | Root Certificate Installed | `deprecated/windows/proc_creation_win_root_certificate_installed.yml` | 0.39 | root |
| `5015082` | [WINDOWS-POWERSHELL] Windows Defender Restarted via Pow | Uncommon PowerShell Hosts | `rules-threat-hunting/windows/powershell/powershell_classic/posh_pc_alternate_powershell_hosts.yml` | 0.39 | hostapplication, powershell |
| `5002693` | [SONICWALL] Intrusion Detection - Possible FIN Flood | OpenCanary - NMAP FIN Scan | `rules/application/opencanary/opencanary_portscan_nmap_fin_scan.yml` | 0.39 | fin |
| `5007126` | [WINDOWS-POWERSHELL] Microsoft Defender Security Regist | Windows Defender Threat Detection Disabled | `deprecated/windows/win_defender_disabled.yml` | 0.39 | protection, defender, threat |
| `5010878` | [CyberArk] Monitor Session End Failed | End User Consent | `rules/cloud/azure/audit_logs/azure_app_end_user_consent.yml` | 0.39 | end |
| `5001552` | [HUAWEI] ATCKDF - Ip option source route attack | New Network Route Added | `rules/cloud/aws/cloudtrail/aws_cloudtrail_new_route_added.yml` | 0.39 | route |
| `5017456` | [DYNAMIC] Sophos Firewall Logs Detected | Suspicious Execution of Sc to Delete AV Services | `deprecated/windows/proc_creation_win_sc_delete_av_services.yml` | 0.39 | sophos |
| `5006642` | [SentinelOne] Quarantine performed successfully | Potential SentinelOne Shell Context Menu Scan Command T | `rules/windows/registry/registry_set/registry_set_sentinelone_shell_context_tampering.yml` | 0.39 | sentinelone |
| `5017641` | [CROWDSTRIKE] File classified as Adware or PUP based on | Renamed Cloudflared.EXE Execution | `rules/windows/process_creation/proc_creation_win_renamed_cloudflared.yml` | 0.39 | sha256 |
| `5017060` | [AWS] S3 Enumeration (Multiple ListBuckets Events) | Potential Storage Enumeration on AWS | `unsupported/cloud/aws_enum_storage.yml` | 0.39 | listbuckets, s3.amazonaws.com, enumeration, aws |
| `5008369` | [WINDOWS-CLIPBOARD] Remoe-exec psexec command | Renamed PsExec | `deprecated/windows/proc_creation_win_renamed_psexec.yml` | 0.39 | psexec |
| `5017332` | [DYNAMIC] Azure Eventhub Windows Applocker Logs Detecte | AppLocker Application Would Have Been Blocked | `rules/windows/builtin/applocker/win_applocker_application_would_have_been_blocked.yml` | 0.39 | applocker |
| `5007371` | [SOPHOS] Deleted malware | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.39 | endpoint, sophos |
| `5009339` | [WINDOWS-POWERSHELL] Microsoft Defender Security Regist | Windows Defender Threat Detection Disabled | `deprecated/windows/win_defender_disabled.yml` | 0.39 | protection, defender, threat |
| `5010614` | [CISCO-SCA] Suspected Zerologon RPC Exploit Attempt | Zerologon Exploitation Using Well-known Tools | `rules/windows/builtin/system/netlogon/win_system_possible_zerologon_exploitation_using_wellknown_tools.yml` | 0.39 | zerologon, exploit |
| `5007203` | [MCAS] Activity from Infrequent Country | Activity from Infrequent Country | `rules/cloud/m365/threat_management/microsoft365_activity_from_infrequent_country.yml` | 0.39 | infrequent, country |
| `5010502` | [CISCO-SCA] Anomalous Windows Workstation | Locked Workstation | `rules/windows/builtin/security/win_security_workstation_was_locked.yml` | 0.39 | workstation |
| `5010958` | [GITHUB] Item Added To Repository | GitHub Repository Archive Status Changed | `rules/application/github/audit/github_repository_archive_status_changed.yml` | 0.39 | repository, github |
| `5013871` | [WINDOWS-SECURITY] Possible LSASS Dump via ProcDump | WerFault LSASS Process Memory Dump | `rules/windows/file/file_event/file_event_win_lsass_werfault_dump.yml` | 0.39 | lsass.exe, lsass, dump |
| `5000012` | [BASH] /tmp/sh access | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.39 | bash |
| `5000013` | [BASH] suidperl access | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.39 | bash |
| `5002305` | [BASH] .mysql_history access | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.39 | bash |
| `5014451` | [FORTINET] IPv6 firewall inbound policy added | FortiGate - New Firewall Policy Added | `rules/network/fortinet/fortigate/fortinet_fortigate_new_firewall_policy_added.yml` | 0.39 | firewall, added, policy, fortinet |
| `5015574` | [Barracuda] Email Gateway Suspicious Event Detected | HackTool - SharpMove Tool Execution | `rules/windows/process_creation/proc_creation_win_hktl_sharpmove.yml` | 0.39 | action |
| `5013550` | [WINDOWS-SYSMON] Possible Hoaxshell attempt (Batch Scri | Potential File Override/Append Via SET Command | `rules-threat-hunting/windows/process_creation/proc_creation_win_cmd_set_prompt_abuse.yml` | 0.39 | set |
| `5008640` | [WINDOWS-CLIPBOARD] Remoe-exec psexec command | Renamed PsExec | `deprecated/windows/proc_creation_win_renamed_psexec.yml` | 0.39 | psexec |
| `5014631` | [LINUX-AUDITD] Immutable File Attr Removed | Remove Immutable File Attribute - Auditd | `rules/linux/auditd/execve/lnx_auditd_chattr_immutable_removal.yml` | 0.39 | immutable, chattr |
| `5005277` | [MS-DEFENDER] Real-Time Protection Is Enabled | Microsoft Defender Tamper Protection Trigger | `rules/windows/builtin/windefend/win_defender_tamper_protection_trigger.yml` | 0.39 | real-time, protection |
| `5005842` | [DARKTRACE] Potential Malicious Anomalous File Alert | Anomalous User Activity | `rules/cloud/azure/identity_protection/azure_identity_protection_anomalous_user.yml` | 0.39 | anomalous |
| `5007344` | [SOPHOS] PUA detected | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.39 | endpoint, sophos, threat |
| `5001085` | [SONICWALL] Possible UDP Port Scan | Testing Usage of Uncommonly Used Port | `rules/windows/powershell/powershell_script/posh_ps_test_netconnection.yml` | 0.39 | port |
| `5007339` | [SOPHOS] Running malware detected | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.39 | endpoint, sophos, threat, malware |
| `5012103` | [SONICWALL] Admin Login Disabled | Access To ADMIN$ Network Share | `rules/windows/builtin/security/win_security_admin_share_access.yml` | 0.39 | admin |
| `5013565` | [WINDOWS-SECURITY] RDP session reconnected to loopback | RDP over Reverse SSH Tunnel WFP | `rules/windows/builtin/security/win_security_rdp_reverse_tunnel.yml` | 0.39 | loopback, rdp, address |
| `5010627` | [CISCO-SCA] Vulnerable Transport Security Protocol | MSExchange Transport Agent Installation - Builtin | `rules/windows/builtin/msexchange/win_exchange_transportagent.yml` | 0.39 | transport |
| `5002308` | [BASH] Python subproces execution | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.39 | bash |
| `5003367` | [PASSWORDSTATE] Password Copied Between Password Lists | Notepad Password Files Discovery | `rules/windows/process_creation/proc_creation_win_notepad_local_passwd_discovery.yml` | 0.39 | password |
| `5015075` | [WINDOWS-SECURITY] Atera Registry Key Deleted | Atera Agent Installation | `rules/windows/builtin/application/msiinstaller/win_software_atera_rmm_agent_install.yml` | 0.39 | atera |
| `5011310` | [FORTISANDBOX] Event Application Subtype Playbook | RedMimicry Winnti Playbook Registry Manipulation | `rules/windows/registry/registry_event/registry_event_redmimicry_winnti_reg.yml` | 0.39 | playbook |
| `5000120` | [SYSLOG] Illegal root login | Root Certificate Installed | `deprecated/windows/proc_creation_win_root_certificate_installed.yml` | 0.39 | root |
| `5007126` | [WINDOWS-POWERSHELL] Microsoft Defender Security Regist | Disable Windows Defender Functionalities Via Registry K | `rules/windows/registry/registry_set/registry_set_windows_defender_tamper.yml` | 0.39 | disableioavprotection, disablebehaviormonitoring, disableintrusionprev |
| `5013571` | [WINDOWS-SECURITY] Log on using Non-Standard Workstatio | Locked Workstation | `rules/windows/builtin/security/win_security_workstation_was_locked.yml` | 0.39 | workstation |
| `5007691` | [WINDOWS-POWERSHELL] Possible Resolve-DnsName IEX comma | PowerShell Download and Execution Cradles | `rules/windows/process_creation/proc_creation_win_powershell_download_iex.yml` | 0.39 | iex, powershell |
| `5015126` | [DYNAMIC] ScreenConnect logs detected via program. | Remote Access Tool - ScreenConnect Installation Executi | `rules/windows/process_creation/proc_creation_win_remote_access_tools_screenconnect_installation_cli_param.yml` | 0.39 | screenconnect, program |
| `5000124` | [SYSLOG] Interface entered promiscuous mode | Suspicious Log Entries | `rules/linux/builtin/lnx_shell_susp_log_entries.yml` | 0.39 | promiscuous, entered, mode |
| `5010458` | [WINDOWS-SECURITY] Fax service installed - Possible Bla | Change the Fax Dll | `rules/windows/registry/registry_set/registry_set_fax_dll_persistance.yml` | 0.39 | fax |
| `5002690` | [SONICWALL] No firewall rule exists for VPN policy | FortiGate - New Firewall Policy Added | `rules/network/fortinet/fortigate/fortinet_fortigate_new_firewall_policy_added.yml` | 0.39 | firewall, policy |
| `5100141` | Microsoft IIS server detected | IIS WebServer Log Deletion via CommandLine Utilities | `rules/windows/process_creation/proc_creation_win_iis_logs_deletion.yml` | 0.39 | iis |
| `5013914` | [WINDOWS-SECURITY] Suspicious netsh PortProxy Command D | New PortProxy Registry Entry Added | `rules/windows/registry/registry_event/registry_event_portproxy_registry_key.yml` | 0.39 | portproxy |
| `5009400` | [WINDOWS-SECURITY] A security-enabled local group was c | A Member Was Added to a Security-Enabled Global Group | `rules/windows/builtin/security/account_management/win_security_member_added_security_enabled_global_group.yml` | 0.39 | security-enabled, group |
| `5013815` | [WINDOWS-SECURITY] Meshagent Remote Session Interaction | Remote Access Tool - Potential MeshAgent Execution - Wi | `rules/windows/process_creation/proc_creation_win_remote_access_tools_meshagent_arguments.yml` | 0.39 | meshagent, remote |
| `5005629` | [LINUX-AUDITD] iptables command access | Flush Iptables Ufw Chain | `rules/linux/process_creation/proc_creation_lnx_iptables_flush_ufw.yml` | 0.39 | iptables |
| `5007371` | [SOPHOS] Deleted malware | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.39 | endpoint, sophos, malware |
| `5000116` | [SYSLOG] System out of disk space | Space After Filename - macOS | `rules/macos/process_creation/proc_creation_macos_space_after_filename.yml` | 0.39 | space |
| `5009339` | [WINDOWS-POWERSHELL] Microsoft Defender Security Regist | Disable Windows Defender Functionalities Via Registry K | `rules/windows/registry/registry_set/registry_set_windows_defender_tamper.yml` | 0.39 | disableioavprotection, disablebehaviormonitoring, disableintrusionprev |
| `5002095` | [WINDOWS-APPLOCKER] Package application allowed | Deployment AppX Package Was Blocked By AppLocker | `rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_applocker_block.yml` | 0.39 | applocker, package |
| `5005860` | [DARKTRACE] A device is connecting directly to an IP ad | Suspicious Execution of Hostname | `rules/windows/process_creation/proc_creation_win_hostname_execution.yml` | 0.39 | hostname |
| `5008415` | [WINDOWS-APPLOCKER] Package application allowed | Deployment AppX Package Was Blocked By AppLocker | `rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_applocker_block.yml` | 0.39 | applocker, package |
| `5008358` | [WINDOWS-SECURITY] A service was installed in the syste | IcedID Malware Suspicious Single Digit DLL Execution Vi | `rules-emerging-threats/2023/Malware/IcedID/proc_creation_win_malware_icedid_rundll32_dllregisterserver.yml` | 0.38 | dllregisterserver, rundll32 |
| `5009372` | [WINDOWS-POWERSHELL] Possible Resolve-DnsName IEX comma | PowerShell Download and Execution Cradles | `rules/windows/process_creation/proc_creation_win_powershell_download_iex.yml` | 0.38 | iex, powershell |
| `5010961` | [GITHUB] Item Removed From Repository | GitHub Repository Archive Status Changed | `rules/application/github/audit/github_repository_archive_status_changed.yml` | 0.38 | repository, github |
| `5015082` | [WINDOWS-POWERSHELL] Windows Defender Restarted via Pow | Renamed Powershell Under Powershell Channel | `rules/windows/powershell/powershell_classic/posh_pc_renamed_powershell.yml` | 0.38 | hostapplication, powershell |
| `5015508` | [WINDOWS-SECURITY] Suspicious Tasklist Command Detected | HackTool - CrackMapExec Process Patterns | `rules/windows/process_creation/proc_creation_win_hktl_crackmapexec_patterns.yml` | 0.38 | tasklist, findstr |
| `5014548` | [WINDOWS-SECURITY] Fax service installed - Possible Bla | Change the Fax Dll | `rules/windows/registry/registry_set/registry_set_fax_dll_persistance.yml` | 0.38 | fax |
| `5002668` | [SONICWALL] Guest account disabled | User State Changed From Guest To Member | `rules/cloud/azure/audit_logs/azure_guest_to_member.yml` | 0.38 | guest |
| `5007157` | [WINDOWS-POWERSHELL] Create Volume Shadow Copy | Volume Shadow Copy Mount | `rules/windows/builtin/system/microsoft_windows_ntfs/win_system_volume_shadow_copy_mount.yml` | 0.38 | shadow, volume, copy |
| `5011144` | [CARBONBLACK-APP-CONTROL] Device Rule deleted (Info) | Azure Device or Configuration Modified or Deleted | `rules/cloud/azure/activity_logs/azure_device_or_configuration_modified_or_deleted.yml` | 0.38 | device, deleted |
| `5007699` | [WINDOWS-SYSMON] Attack on Sysmon - SysmonEnte Detected | HackTool - SysmonEnte Execution | `rules/windows/process_access/proc_access_win_hktl_sysmonente.yml` | 0.38 | ente, sysmonente, attack, sysmon |
| `5005649` | [LINUX-AUDITD] wget execution | Wget Creating Files in Tmp Directory | `rules/linux/file_event/file_event_lnx_wget_download_file_in_tmp_dir.yml` | 0.38 | wget |
| `5009801` | [WINDOWS-SYSMON] Attack on Sysmon - SysmonEnte Detected | HackTool - SysmonEnte Execution | `rules/windows/process_access/proc_access_win_hktl_sysmonente.yml` | 0.38 | ente, sysmonente, attack, sysmon |
| `5007341` | [SOPHOS] Malware detected | Suspicious Execution of Sc to Delete AV Services | `deprecated/windows/proc_creation_win_sc_delete_av_services.yml` | 0.38 | endpoint, sophos |
| `5013559` | [WINDOWS-FIREWALL] Firewall rule added by AnyDesk | Remote Access Tool - AnyDesk Incoming Connection | `rules/windows/network_connection/net_connection_win_remote_access_tools_anydesk_incoming_connection.yml` | 0.38 | anydesk |
| `5006639` | [SentinelOne] Network quarantine performed successfully | Potential SentinelOne Shell Context Menu Scan Command T | `rules/windows/registry/registry_set/registry_set_sentinelone_shell_context_tampering.yml` | 0.38 | sentinelone |
| `5010627` | [CISCO-SCA] Vulnerable Transport Security Protocol | Failed MSExchange Transport Agent Installation | `rules/windows/builtin/msexchange/win_exchange_transportagent_failed.yml` | 0.38 | transport |
| `5002097` | [WINDOWS-APPLOCKER] Package application disabled | Deployment AppX Package Was Blocked By AppLocker | `rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_applocker_block.yml` | 0.38 | applocker, package |
| `5008417` | [WINDOWS-APPLOCKER] Package application disabled | Deployment AppX Package Was Blocked By AppLocker | `rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_applocker_block.yml` | 0.38 | applocker, package |
| `5013815` | [WINDOWS-SECURITY] Meshagent Remote Session Interaction | Remote Access Tool - Potential MeshAgent Execution - Ma | `rules/macos/process_creation/proc_creation_macos_remote_access_tools_meshagent_arguments.yml` | 0.38 | meshagent, remote |
| `5017639` | [CROWDSTRIKE] File classified as Adware or PUP based on | Renamed Cloudflared.EXE Execution | `rules/windows/process_creation/proc_creation_win_renamed_cloudflared.yml` | 0.38 | sha256 |
| `5007289` | [SOPHOS] Unknown violation | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.38 | endpoint, sophos |
| `5014640` | [LINUX-SECURITY] User Added to SUDO Group Command Detec | User Added To Root/Sudoers Group Using Usermod | `rules/linux/process_creation/proc_creation_lnx_usermod_susp_group.yml` | 0.38 | usermod, added, group |
| `5015043` | [VEEAM] Multi-Factor Authentication Token Revoked | Okta API Token Revoked | `rules/identity/okta/okta_api_token_revoked.yml` | 0.38 | revoked, token |
| `5008567` | [WINDOWS-AUTH] Suspicious Account Lockout | Process Launched Without Image Name | `rules/windows/process_creation/proc_creation_win_susp_no_image_name.yml` | 0.38 | name |
| `5009370` | [WINDOWS-POWERSHELL] Create Volume Shadow Copy | Volume Shadow Copy Mount | `rules/windows/builtin/system/microsoft_windows_ntfs/win_system_volume_shadow_copy_mount.yml` | 0.38 | shadow, volume, copy |
| `5009774` | [WINDOWS-SECURITY] A service was installed in the syste | IcedID Malware Suspicious Single Digit DLL Execution Vi | `rules-emerging-threats/2023/Malware/IcedID/proc_creation_win_malware_icedid_rundll32_dllregisterserver.yml` | 0.38 | dllregisterserver, rundll32 |
| `5017783` | [CROWDSTRIKE] Machine Learning Analysis Blocked - AnyDe | Anydesk Remote Access Software Service Installation | `rules/windows/builtin/system/service_control_manager/win_system_service_install_anydesk.yml` | 0.38 | anydesk |
| `5003982` | [WINDOWS-AUTH] Suspicious Account Lockout | Process Launched Without Image Name | `rules/windows/process_creation/proc_creation_win_susp_no_image_name.yml` | 0.38 | name |
| `5005882` | [DARKTRACE] A device has been observed receiving a numb | OpenCanary - SIP Request | `rules/application/opencanary/opencanary_sip_request.yml` | 0.38 | sip |
| `5015262` | [NETSKOPE] Reset password Event Detected | Windows Defender Firewall Has Been Reset To Its Default | `rules/windows/builtin/firewall_as/win_firewall_as_reset_config.yml` | 0.38 | reset |
| `5002151` | [CISCO-PRIME] MESH authentication failure | Mesh Agent Service Installation | `rules/windows/builtin/system/service_control_manager/win_system_service_install_mesh_agent.yml` | 0.38 | mesh |
| `5003363` | [PASSWORDSTATE] Security Group Deleted | Azure Application Security Group Modified or Deleted | `rules/cloud/azure/activity_logs/azure_application_security_group_modified_or_deleted.yml` | 0.38 | group, deleted, security |
| `5017721` | [SOPHOS_FIREWALL] Firewall Rule Added to Configuration | Sysmon Configuration Change | `rules/windows/sysmon/sysmon_config_modification.yml` | 0.38 | change, configuration |
| `5007344` | [SOPHOS] PUA detected | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.38 | endpoint, sophos |
| `5013877` | [WINDOWS-SECURITY] Possible Impacket Command | HackTool - Impacket File Indicators | `rules/windows/file/file_event/file_event_win_impacket_file_indicators.yml` | 0.38 | impacket |
| `5017641` | [CROWDSTRIKE] File classified as Adware or PUP based on | Cloudflared Quick Tunnel Execution | `rules/windows/process_creation/proc_creation_win_cloudflared_quicktunnel_execution.yml` | 0.38 | sha256 |
| `5013558` | [WINDOWS-POWERSHELL] ShadowCopy Deleted | Delete Volume Shadow Copies Via WMI With PowerShell | `rules/windows/powershell/powershell_classic/posh_pc_delete_volume_shadow_copies.yml` | 0.38 | remove-wmiobject, get-wmiobject, win32_shadowcopy, powershell |
| `5000935` | [FORTINET] New admin user added | FortiGate - New Administrator Account Created | `rules/network/fortinet/fortigate/fortinet_fortigate_new_admin_account_created.yml` | 0.38 | system.admin, add, fortinet |
| `5013864` | [WINDOWS-SECURITY] False CMD Parameters /I /SI | Read and Execute a File Via Cmd.exe | `deprecated/windows/proc_creation_win_cmd_read_contents.yml` | 0.38 | cmd, cmd.exe |
| `5013865` | [WINDOWS-SECURITY] False CMD Parameters /O /SO | Read and Execute a File Via Cmd.exe | `deprecated/windows/proc_creation_win_cmd_read_contents.yml` | 0.38 | cmd, cmd.exe |
| `5005867` | [DARKTRACE] A device is transferring an abnormally larg | Microsoft 365 - Unusual Volume of File Deletion | `rules/cloud/m365/threat_management/microsoft365_unusual_volume_of_file_deletion.yml` | 0.38 | large, volume, unusual |
| `5008363` | [WINDOWS-CLIPBOARD] Get-ADUser Command | Get-ADUser Enumeration Using UserAccountControl Flags | `rules/windows/powershell/powershell_script/posh_ps_as_rep_roasting.yml` | 0.38 | get-aduser |
| `5008381` | [WINDOWS-CLIPBOARD] bitsadmin file transfer command | File Download Via Bitsadmin To An Uncommon Target Folde | `deprecated/windows/proc_creation_win_bitsadmin_download_uncommon_targetfolder.yml` | 0.38 | bitsadmin, transfer |
| `5007128` | [WINDOWS-POWERSHELL] IEX Command Encoded as Base64 | Base64 Encoded PowerShell Command Detected | `rules/windows/process_creation/proc_creation_win_powershell_frombase64string.yml` | 0.38 | encoded, base64, powershell |
| `5008497` | [WINDOWS-AUTH] Windows DC Logon Failure - Brute force 0 | MSSQL Server Failed Logon From External Network | `rules/windows/builtin/application/mssqlserver/win_mssql_failed_logon_from_external_network.yml` | 0.38 | logon, client |
| `5015252` | [NETSKOPE] Enabled admin Event Detected | Access To ADMIN$ Network Share | `rules/windows/builtin/security/win_security_admin_share_access.yml` | 0.38 | admin |
| `5000376` | [SYSLOG] User or group was deleted from the system | A Security-Enabled Global Group Was Deleted | `rules/windows/builtin/security/account_management/win_security_security_enabled_global_group_deleted.yml` | 0.38 | group, deleted |
| `5000971` | [FORTINET] Admin changed another admin's password | User Added To Admin Group Via DseditGroup | `rules/macos/process_creation/proc_creation_macos_dseditgroup_add_to_admin_group.yml` | 0.38 | admin |
| `5008488` | [WINDOWS-AUTH] Windows Brute force - User Account Disab | COM Object Execution via Xwizard.EXE | `rules/windows/process_creation/proc_creation_win_xwizard_runwizard_com_object_exec.yml` | 0.38 | a-fa-f0-9 |
| `5007709` | [WINDOWS-POWERSHELL] Possible ProxyShell V2 execution | Chopper Webshell Process Pattern | `rules/windows/process_creation/proc_creation_win_webshell_chopper.yml` | 0.38 | echo |
| `5100192` | Windows PowerShell device detected | Azure Device or Configuration Modified or Deleted | `rules/cloud/azure/activity_logs/azure_device_or_configuration_modified_or_deleted.yml` | 0.38 | device |
| `5008541` | [WINDOWS-AUTH] Account locked out (ADMINISTRATOR) | OneLogin User Account Locked | `rules/identity/onelogin/onelogin_user_account_locked.yml` | 0.38 | locked |
| `5010513` | [CISCO-SCA] AWS Lambda Invocation Spike | AWS New Lambda Layer Attached | `rules/cloud/aws/cloudtrail/aws_new_lambda_layer_attached.yml` | 0.38 | lambda, aws |
| `5010621` | [CISCO-SCA] Unused AWS Resource | Bitbucket Unauthorized Access To A Resource | `rules/application/bitbucket/audit/bitbucket_audit_unauthorized_access_detected.yml` | 0.38 | resource |
| `5014640` | [LINUX-SECURITY] User Added to SUDO Group Command Detec | Linux Sudo Chroot Execution | `rules/linux/process_creation/proc_creation_lnx_chroot_execution.yml` | 0.38 | sudo |
| `5008652` | [WINDOWS-CLIPBOARD] bitsadmin file transfer command | File Download Via Bitsadmin To An Uncommon Target Folde | `deprecated/windows/proc_creation_win_bitsadmin_download_uncommon_targetfolder.yml` | 0.38 | bitsadmin, transfer |
| `5010596` | [CISCO-SCA] Public Amazon Route 53 Hosted Zone Created | Unusual File Download from Direct IP Address | `rules/windows/create_stream_hash/create_stream_hash_susp_ip_domains.yml` | 0.38 | zone, type |
| `5015849` | [MICROSOFT_DEFENDER_ENDPOINT] Potentially Unwanted Soft | Windows Defender Malware And PUA Scanning Disabled | `rules/windows/builtin/windefend/win_defender_malware_and_pua_scan_disabled.yml` | 0.38 | unwanted, pua, software, potentially |
| `5008634` | [WINDOWS-CLIPBOARD] Get-ADUser Command | Get-ADUser Enumeration Using UserAccountControl Flags | `rules/windows/powershell/powershell_script/posh_ps_as_rep_roasting.yml` | 0.38 | get-aduser |
| `5100129` | Google updater detected | Suspicious Login Activity Classified By Google | `rules/cloud/gcp/gworkspace/login/gcp_gworkspace_suspicious_login.yml` | 0.38 | google |
| `5001695` | [WINDOWS-AUTH] CRITICAL - User added to Domain Administ | Reconnaissance Activity | `rules/windows/builtin/security/win_security_susp_net_recon_activity.yml` | 0.38 | admins, domain, group |
| `5009400` | [WINDOWS-SECURITY] A security-enabled local group was c | A Member Was Removed From a Security-Enabled Global Gro | `rules/windows/builtin/security/account_management/win_security_member_removed_security_enabled_global_group.yml` | 0.38 | security-enabled, group |
| `5014587` | [WINDOWS-SYSMON] GitHub Cloning of ADRecon Detected - A | OpenCanary - GIT Clone Request | `rules/application/opencanary/opencanary_git_clone_request.yml` | 0.38 | clone, git |
| `5002333` | [BASH] LD_PRELOAD environment variable access | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.38 | bash |
| `5002334` | [BASH] LD_LIBRARY_PATH environment variable access | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.38 | bash |
| `5009374` | [WINDOWS-POWERSHELL] Possible ProxyShell V2 execution | Chopper Webshell Process Pattern | `rules/windows/process_creation/proc_creation_win_webshell_chopper.yml` | 0.38 | echo |
| `5002815` | [WINDOWS-SYSMON] Suspicious WMIC call - csproduct Get N | Hardware Model Reconnaissance Via Wmic.EXE | `rules/windows/process_creation/proc_creation_win_wmic_recon_csproduct.yml` | 0.38 | csproduct, wmic |
| `5010753` | [CyberArk] Add Safe | Add SafeBoot Keys Via Reg Utility | `rules/windows/process_creation/proc_creation_win_reg_add_safeboot.yml` | 0.38 | safe, add |
| `5010792` | [CyberArk] Add Safe Event | Add SafeBoot Keys Via Reg Utility | `rules/windows/process_creation/proc_creation_win_reg_add_safeboot.yml` | 0.38 | safe, add |
| `5007374` | [SOPHOS] Detected PUA | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.38 | endpoint, sophos |
| `5007390` | [SOPHOS] PUA detected | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.38 | endpoint, sophos |
| `5009787` | [WINDOWS-SYSMON] Suspicious WMIC call - csproduct Get N | Hardware Model Reconnaissance Via Wmic.EXE | `rules/windows/process_creation/proc_creation_win_wmic_recon_csproduct.yml` | 0.38 | csproduct, wmic |
| `5007128` | [WINDOWS-POWERSHELL] IEX Command Encoded as Base64 | Suspicious PowerShell IEX Execution Patterns | `rules/windows/process_creation/proc_creation_win_powershell_iex_patterns.yml` | 0.38 | iex, powershell |
| `5013575` | [WINDOWS-SYSTEM] The Setup Log was cleared | Security Event Log Cleared | `deprecated/windows/win_security_event_log_cleared.yml` | 0.38 | cleared |
| `5000376` | [SYSLOG] User or group was deleted from the system | Azure Application Security Group Modified or Deleted | `rules/cloud/azure/activity_logs/azure_application_security_group_modified_or_deleted.yml` | 0.38 | group, deleted |
| `5015073` | [WINDOWS-SECURITY] Atera Stop/Delete Service | Atera Agent Installation | `rules/windows/builtin/application/msiinstaller/win_software_atera_rmm_agent_install.yml` | 0.38 | ateraagent, atera |
| `5015074` | [WINDOWS-SECURITY] Atera Stop/Delete Service | Atera Agent Installation | `rules/windows/builtin/application/msiinstaller/win_software_atera_rmm_agent_install.yml` | 0.38 | ateraagent, atera |
| `5008482` | [WINDOWS-AUTH] User added to Group Policy Creator Owner | Added Owner To Application | `rules/cloud/azure/audit_logs/azure_app_owner_added.yml` | 0.38 | owner, added |
| `5010818` | [CyberArk] Get User's Details | Bitbucket User Permissions Export Attempt | `rules/application/bitbucket/audit/bitbucket_audit_user_permissions_export_attempt_detected.yml` | 0.38 | details |
| `5010819` | [CyberArk] Get Your User's Details | Bitbucket User Permissions Export Attempt | `rules/application/bitbucket/audit/bitbucket_audit_user_permissions_export_attempt_detected.yml` | 0.38 | details |
| `5012094` | [WINDOWS-SECURITY] RDP Tunnel Detected | Renamed Visual Studio Code Tunnel Execution | `rules/windows/process_creation/proc_creation_win_vscode_tunnel_renamed_execution.yml` | 0.38 | tunnel |
| `5014312` | [DYNAMIC] JAMF Protect logs detected via program. | JAMF MDM Execution | `rules/macos/process_creation/proc_creation_macos_jamf_usage.yml` | 0.38 | jamf |
| `5014407` | [FORTINET] Admin changed another admin's password | User Added To Admin Group Via DseditGroup | `rules/macos/process_creation/proc_creation_macos_dseditgroup_add_to_admin_group.yml` | 0.38 | admin |
| `5000971` | [FORTINET] Admin changed another admin's password | User Added To Admin Group - MacOS | `deprecated/macos/proc_creation_macos_add_to_admin_group.yml` | 0.38 | admin |
| `5013926` | [WINDOWS-SECURITY] Ransomware command line parameters | Rundll32 Execution Without CommandLine Parameters | `rules/windows/process_creation/proc_creation_win_rundll32_no_params.yml` | 0.38 | parameters, rundll32.exe |
| `5015083` | [WINDOWS-POWERSHELL] Windows Firewall Restarted via Pow | Uncommon PowerShell Hosts | `rules-threat-hunting/windows/powershell/powershell_classic/posh_pc_alternate_powershell_hosts.yml` | 0.38 | hostapplication, powershell |
| `5013805` | [WINDOWS-SYSMON] PowerShell Rundll32 Remote Thread Crea | Potential Bumblebee Remote Thread Creation | `rules-emerging-threats/2022/Malware/Bumblebee/create_remote_thread_win_malware_bumblebee.yml` | 0.38 | thread, rundll32.exe, remote, creation |
| `5017563` | [CROWDSTRIKE] Possible Defense Evasion Attempt Detected | Potential Defense Evasion Activity Via Emoji Usage In C | `rules/windows/process_creation/proc_creation_win_susp_emoji_usage_in_cli_1.yml` | 0.38 | defense, evasion |
| `5017563` | [CROWDSTRIKE] Possible Defense Evasion Attempt Detected | Potential Defense Evasion Activity Via Emoji Usage In C | `rules/windows/process_creation/proc_creation_win_susp_emoji_usage_in_cli_2.yml` | 0.38 | defense, evasion |
| `5017563` | [CROWDSTRIKE] Possible Defense Evasion Attempt Detected | Potential Defense Evasion Activity Via Emoji Usage In C | `rules/windows/process_creation/proc_creation_win_susp_emoji_usage_in_cli_3.yml` | 0.38 | defense, evasion |
| `5009341` | [WINDOWS-POWERSHELL] IEX Command Encoded as Base64 | Base64 Encoded PowerShell Command Detected | `rules/windows/process_creation/proc_creation_win_powershell_frombase64string.yml` | 0.38 | encoded, base64, powershell |
| `5010315` | [NETWRIX] Windows Server - Scheduled Task Added | Scheduled Task Created - FileCreation | `rules-threat-hunting/windows/file/file_event/file_event_win_scheduled_task_creation.yml` | 0.38 | scheduled, task |
| `5009781` | [WINDOWS-SYSMON] vssadmin.exe Delete Shadows execution. | Shadow Copies Deletion Using Operating Systems Utilitie | `rules/windows/process_creation/proc_creation_win_susp_shadow_copies_deletion.yml` | 0.38 | vssadmin.exe, delete |
| `5013877` | [WINDOWS-SECURITY] Possible Impacket Command | HackTool - Potential Impacket Lateral Movement Activity | `rules/windows/process_creation/proc_creation_win_hktl_impacket_lateral_movement.yml` | 0.38 | impacket, 127.0.0.1 |
| `5017352` | [DYNAMIC] PHP Logs Detected | Php Inline Command Execution | `rules/windows/process_creation/proc_creation_win_php_inline_command_execution.yml` | 0.38 | php |
| `5003407` | [WINDOWS-SECURITY] A security-enabled universal group w | A Member Was Added to a Security-Enabled Global Group | `rules/windows/builtin/security/account_management/win_security_member_added_security_enabled_global_group.yml` | 0.38 | security-enabled, group |
| `5003186` | [ZSCALER] MSF Meterpreter Default User Agent | APT User Agent | `rules/web/proxy_generic/proxy_ua_apt.yml` | 0.38 | 6.1, mozilla/4.0, msie, compatible, agent |
| `5007328` | [SOPHOS] Malware cleaned up | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.38 | endpoint, sophos, threat, malware |
| `5001978` | [WINDOWS-AUTH] Account locked out (ADMINISTRATOR) | OneLogin User Account Locked | `rules/identity/onelogin/onelogin_user_account_locked.yml` | 0.38 | locked |
| `5008541` | [WINDOWS-AUTH] Account locked out (ADMINISTRATOR) | User Added to an Administrator's Azure AD Role | `rules/cloud/azure/audit_logs/azure_ad_user_added_to_admin_role.yml` | 0.37 | administrator |
| `5010601` | [CISCO-SCA] Role Violation | User Added to an Administrator's Azure AD Role | `rules/cloud/azure/audit_logs/azure_ad_user_added_to_admin_role.yml` | 0.37 | role |
| `5013804` | [WINDOWS-SYSMON] Accessing WinAPI in PowerShell. Code I | Accessing WinAPI in PowerShell for Credentials Dumping | `deprecated/windows/sysmon_accessing_winapi_in_powershell_credentials_dumping.yml` | 0.37 | winapi, pwsh.exe, powershell |
| `5010885` | [CyberArk] Privileged group modification blocked. | Standard User In High Privileged Group | `rules/windows/builtin/lsa_server/win_lsa_server_normal_user_admin.yml` | 0.37 | privileged, group |
| `5008487` | [WINDOWS-AUTH] Windows Brute force - User Is Locked Out | COM Object Execution via Xwizard.EXE | `rules/windows/process_creation/proc_creation_win_xwizard_runwizard_com_object_exec.yml` | 0.37 | a-fa-f0-9 |
| `5015508` | [WINDOWS-SECURITY] Suspicious Tasklist Command Detected | Suspicious Tasklist Discovery Command | `rules-threat-hunting/windows/process_creation/proc_creation_win_tasklist_basic_execution.yml` | 0.37 | tasklist |
| `5000933` | [FORTINET] Access profile changed | PowerShell Profile Modification | `rules/windows/file/file_event/file_event_win_susp_powershell_profile.yml` | 0.37 | profile |
| `5001697` | [WINDOWS-AUTH] User added to Group Policy Creator Owner | Added Owner To Application | `rules/cloud/azure/audit_logs/azure_app_owner_added.yml` | 0.37 | owner, added |
| `5017456` | [DYNAMIC] Sophos Firewall Logs Detected | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.37 | sophos |
| `5100121` | MS-SQL service detected | MSSQL Server Failed Logon | `rules/windows/builtin/application/mssqlserver/win_mssql_failed_logon.yml` | 0.37 | mssql |
| `5017590` | [CROWDSTRIKE] Suspicious Execution Detected - CrackMapE | HackTool - Potential Remote Credential Dumping Activity | `rules/windows/file/file_event/file_event_win_hktl_remote_cred_dump.yml` | 0.37 | crackmapexec, execution |
| `5100038` | OpenVPN services detected | Suspicious Application Installed | `rules/windows/builtin/shell_core/win_shell_core_susp_packages_installed.yml` | 0.37 | openvpn |
| `5014645` | [MSAPI-AZUREAD] Security Operator role assigned to Memb | User Added to an Administrator's Azure AD Role | `rules/cloud/azure/audit_logs/azure_ad_user_added_to_admin_role.yml` | 0.37 | member, role, add |
| `5017639` | [CROWDSTRIKE] File classified as Adware or PUP based on | Cloudflared Quick Tunnel Execution | `rules/windows/process_creation/proc_creation_win_cloudflared_quicktunnel_execution.yml` | 0.37 | sha256 |
| `5007702` | [WINDOWS-SECURITY] Attack on Sysmon - Process Injection | HackTool - HandleKatz Duplicating LSASS Handle | `rules/windows/process_access/proc_access_win_hktl_handlekatz_lsass_access.yml` | 0.37 | duplicate, handle |
| `5000936` | [FORTINET] New user group added | Group Modification Logging | `deprecated/windows/win_security_group_modification_logging.yml` | 0.37 | added, group |
| `5005282` | [MS-DEFENDER] Scanning For Malware is Enabled | Windows Defender Malware And PUA Scanning Disabled | `rules/windows/builtin/windefend/win_defender_malware_and_pua_scan_disabled.yml` | 0.37 | scanning, malware |
| `5009280` | [WINDOWS-MISC] Windows audit log was cleared | Eventlog Cleared | `rules/windows/builtin/system/microsoft_windows_eventlog/win_system_eventlog_cleared.yml` | 0.37 | eventlog, cleared, security |
| `5014407` | [FORTINET] Admin changed another admin's password | User Added To Admin Group - MacOS | `deprecated/macos/proc_creation_macos_add_to_admin_group.yml` | 0.37 | admin |
| `5100030` | Unix 'kernel' messages detected | CodeIntegrity - Revoked Kernel Driver Loaded | `rules/windows/builtin/code_integrity/win_codeintegrity_revoked_driver_loaded.yml` | 0.37 | kernel |
| `5011325` | [AZURE ACTIVITY] Resource Health category Level Critica | Azure Active Directory Hybrid Health AD FS Service Dele | `rules/cloud/azure/activity_logs/azure_aadhybridhealth_adfs_service_delete.yml` | 0.37 | health, category, azure |
| `5005679` | [NETSKOPE] Policy alert | PowerShell Script Execution Policy Enabled | `rules/windows/registry/registry_set/registry_set_powershell_enablescripts_enabled.yml` | 0.37 | policy |
| `5009341` | [WINDOWS-POWERSHELL] IEX Command Encoded as Base64 | Suspicious PowerShell IEX Execution Patterns | `rules/windows/process_creation/proc_creation_win_powershell_iex_patterns.yml` | 0.37 | iex, powershell |
| `5005955` | [WINDOWS-POWERSHELL] Powershell Command to Export Secre | Certificate Exported Via Certutil.EXE | `rules/windows/process_creation/proc_creation_win_certutil_export_pfx.yml` | 0.37 | exportpfx, certutil, export |
| `5005283` | [MS-DEFENDER] Scanning For Malware is Disabled | Login to Disabled Account | `rules/cloud/azure/signin_logs/azure_login_to_disabled_account.yml` | 0.37 | disabled |
| `5001083` | [SONICWALL] Possible TCP Port Scan | Bpfdoor TCP Ports Redirect | `rules/linux/auditd/execve/lnx_auditd_bpfdoor_port_redirect.yml` | 0.37 | tcp, port |
| `5002930` | [CARBONBLACK-APP-CONTROL] Permission change was blocked | Bitbucket Global Permission Changed | `rules/application/bitbucket/audit/bitbucket_audit_global_permissions_change_detected.yml` | 0.37 | permission, change |
| `5015509` | [WINDOWS-SECURITY] PsExec Executed from Suspicious Dire | Renamed PsExec | `deprecated/windows/proc_creation_win_renamed_psexec.yml` | 0.37 | psexec.exe, psexec |
| `5017640` | [CROWDSTRIKE] File classified as Adware or PUP based on | Renamed Cloudflared.EXE Execution | `rules/windows/process_creation/proc_creation_win_renamed_cloudflared.yml` | 0.37 | sha256 |
| `5000157` | [APACHE] Attempt to access forbidden directory index | Removal Of Index Value to Hide Schedule Task - Registry | `rules/windows/registry/registry_delete/registry_delete_schtasks_hide_task_via_index_value_removal.yml` | 0.37 | index |
| `5000244` | [TELNET] Remote host established a telnet connection | OpenCanary - Telnet Login Attempt | `rules/application/opencanary/opencanary_telnet_login_attempt.yml` | 0.37 | telnet |
| `5002333` | [BASH] LD_PRELOAD environment variable access | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.37 | bash |
| `5002334` | [BASH] LD_LIBRARY_PATH environment variable access | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.37 | bash |
| `5011326` | [AZURE ACTIVITY] Resource Health category Level Error | Azure Active Directory Hybrid Health AD FS Service Dele | `rules/cloud/azure/activity_logs/azure_aadhybridhealth_adfs_service_delete.yml` | 0.37 | health, category, azure |
| `5005622` | [LINUX-AUDITD] nmap execution | OpenCanary - NMAP FIN Scan | `rules/application/opencanary/opencanary_portscan_nmap_fin_scan.yml` | 0.37 | nmap |
| `5003420` | [WINDOWS-SECURITY] The certificate manager settings for | Active Directory Certificate Services Denied Certificat | `rules/windows/builtin/system/microsoft_windows_certification_authority/win_system_adcs_enrollment_request_denied.yml` | 0.37 | certificate |
| `5005626` | [LINUX-AUDITD] .bash_history access | History File Deletion | `rules/linux/process_creation/proc_creation_lnx_susp_history_delete.yml` | 0.37 | bash_history |
| `5015952` | [KEY9] Authentication - Multiple Console Login Failed A | AWS ConsoleLogin Failed Authentication | `rules/cloud/aws/cloudtrail/aws_cloudtrail_console_login_failed_authentication.yml` | 0.37 | console, authentication, login, failed |
| `5014188` | [IMPERVA] Illegal Resource Access Detected and Not Bloc | Bitbucket Unauthorized Access To A Resource | `rules/application/bitbucket/audit/bitbucket_audit_unauthorized_access_detected.yml` | 0.37 | resource |
| `5001805` | [WEB-ATTACKS] Nmap Scripting Engine User-Agent Detected | OpenCanary - NMAP OS Scan | `rules/application/opencanary/opencanary_portscan_nmap_os_scan.yml` | 0.37 | nmap |
| `5005633` | [LINUX-AUDITD] PHP execution | Potential PHP Reverse Shell | `rules/linux/process_creation/proc_creation_lnx_php_reverse_shell.yml` | 0.37 | php |
| `5010481` | [WINDOWS-POWERSHELL] Mimikatz Command Line Parameters ( | Anomalous Token | `rules/cloud/azure/identity_protection/azure_identity_protection_anomalous_token.yml` | 0.37 | token |
| `5010572` | [CISCO-SCA] New AWS Lambda Invoke Permission Added | AWS New Lambda Layer Attached | `rules/cloud/aws/cloudtrail/aws_new_lambda_layer_attached.yml` | 0.37 | lambda, aws |
| `5007339` | [SOPHOS] Running malware detected | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.37 | endpoint, sophos |
| `5001978` | [WINDOWS-AUTH] Account locked out (ADMINISTRATOR) | User Added to an Administrator's Azure AD Role | `rules/cloud/azure/audit_logs/azure_ad_user_added_to_admin_role.yml` | 0.37 | administrator |
| `5008395` | [WINDOWS-MISC] Pass the Hash Detected | Successful Overpass the Hash Attempt | `rules/windows/builtin/security/account_management/win_security_overpass_the_hash.yml` | 0.37 | seclogo, negotiate, hash, logon, type |
| `5002658` | [SONICWALL] Intrusion Detection - Possible FIN Flood | OpenCanary - NMAP FIN Scan | `rules/application/opencanary/opencanary_portscan_nmap_fin_scan.yml` | 0.37 | fin |
| `5003204` | [WINDOWS-MALWARE] Bad Rabbit Malware scheduled task det | Scheduled Task Created - FileCreation | `rules-threat-hunting/windows/file/file_event/file_event_win_scheduled_task_creation.yml` | 0.37 | scheduled, task |
| `5017781` | [CROWDSTRIKE] Machine Learning Analysis Blocked - Scree | Remote Access Tool - ScreenConnect Command Execution | `rules/windows/builtin/application/screenconnect/win_app_remote_access_tools_screenconnect_command_exec.yml` | 0.37 | screenconnect |
| `5010488` | [WINDOWS-SECURITY] Comsrvc MiniDump Command via Service | New Service Creation Using Sc.EXE | `rules/windows/process_creation/proc_creation_win_sc_create_service.yml` | 0.37 | binpath, sc.exe, create |
| `5008753` | [WINDOWS-MALWARE] Bad Rabbit Malware scheduled task det | Scheduled Task Created - FileCreation | `rules-threat-hunting/windows/file/file_event/file_event_win_scheduled_task_creation.yml` | 0.37 | scheduled, task |
| `5017152` | [AWS] EC2 Shared Snapshot Volume Created | AWS Snapshot Backup Exfiltration | `rules/cloud/aws/cloudtrail/aws_snapshot_backup_exfiltration.yml` | 0.37 | snapshot, ec2, ec2.amazonaws.com, aws |
| `5002638` | [SONICWALL] VPN PKI - Bad CRL format | XSL Script Execution Via WMIC.EXE | `rules/windows/process_creation/proc_creation_win_wmic_xsl_script_processing.yml` | 0.37 | format |
| `5002303` | [BASH] History hiding | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.37 | bash |
| `5009329` | [WINDOWS-POWERSHELL] Powershell Command to Export Secre | Certificate Exported Via Certutil.EXE | `rules/windows/process_creation/proc_creation_win_certutil_export_pfx.yml` | 0.37 | exportpfx, certutil, export |
| `5015510` | [WINDOWS-SECURITY] PsExec AcceptEULA Detected | Potential Execution of Sysinternals Tools | `rules/windows/process_creation/proc_creation_win_sysinternals_eula_accepted.yml` | 0.37 | accepteula |
| `5010576` | [CISCO-SCA] New Internal Device | Azure Device or Configuration Modified or Deleted | `rules/cloud/azure/activity_logs/azure_device_or_configuration_modified_or_deleted.yml` | 0.37 | device |
| `5009403` | [WINDOWS-SECURITY] A security-enabled universal group w | A Member Was Added to a Security-Enabled Global Group | `rules/windows/builtin/security/account_management/win_security_member_added_security_enabled_global_group.yml` | 0.37 | security-enabled, group |
| `5015083` | [WINDOWS-POWERSHELL] Windows Firewall Restarted via Pow | Renamed Powershell Under Powershell Channel | `rules/windows/powershell/powershell_classic/posh_pc_renamed_powershell.yml` | 0.37 | hostapplication, powershell |
| `5005643` | [LINUX-AUDITD] SSH tunnel forwarding | Potential Remote Desktop Tunneling | `rules/windows/process_creation/proc_creation_win_susp_remote_desktop_tunneling.yml` | 0.37 | tunnel, ssh |
| `5010505` | [CISCO-SCA] AWS Config Rule Violation | AWS Config Disabling Channel/Recorder | `rules/cloud/aws/cloudtrail/aws_config_disable_recording.yml` | 0.37 | config, aws |
| `5010532` | [CISCO-SCA] Azure Resource Group Deleted | Azure Application Security Group Modified or Deleted | `rules/cloud/azure/activity_logs/azure_application_security_group_modified_or_deleted.yml` | 0.37 | azure, group, deleted |
| `5010809` | [CyberArk] Clear Expired History | Clearing Windows Console History | `rules/windows/powershell/powershell_script/posh_ps_clearing_windows_console_history.yml` | 0.37 | clear, history |
| `5005753` | [WINDOWS-POWERSHELL] Powershell created local user [3/3 | User Added to Local Administrators Group | `rules/windows/process_creation/proc_creation_win_susp_add_user_local_admin_group.yml` | 0.37 | localgroup, administrators, net, local, add |
| `5005852` | [DARKTRACE] Potential Malicious Remote Desktop Tunnel | Visual Studio Code Tunnel Execution | `rules/windows/process_creation/proc_creation_win_vscode_tunnel_execution.yml` | 0.37 | tunnel |
| `5014403` | [FORTINET] Access profile changed | PowerShell Profile Modification | `rules/windows/file/file_event/file_event_win_susp_powershell_profile.yml` | 0.37 | profile |
| `5002803` | [WINDOWS-SYSMON] vssadmin.exe Delete Shadows execution. | Shadow Copies Deletion Using Operating Systems Utilitie | `rules/windows/process_creation/proc_creation_win_susp_shadow_copies_deletion.yml` | 0.37 | vssadmin.exe, delete |
| `5010482` | [WINDOWS-POWERSHELL] Net.WebClient DownloadString | Suspicious PowerShell Invocations - Specific | `deprecated/windows/powershell_suspicious_invocation_specific.yml` | 0.37 | net.webclient, new-object, downloadstring, powershell |
| `5008449` | [WINDOWS-AUTH] A member was added to a security-enabled | A Security-Enabled Global Group Was Deleted | `rules/windows/builtin/security/account_management/win_security_security_enabled_global_group_deleted.yml` | 0.37 | security-enabled, group |
| `5013870` | [WINDOWS-SECURITY] LSASS Dump via ProcDump | WerFault LSASS Process Memory Dump | `rules/windows/file/file_event/file_event_win_lsass_werfault_dump.yml` | 0.37 | lsass.exe, lsass, dump |
| `5001830` | [WEB-ATTACKS] WITOOL SQL Injection Scan | Malware User Agent | `rules/web/proxy_generic/proxy_ua_malware.yml` | 0.37 | 5.0, 6.0, mozilla/4.0, msie, compatible |
| `5002308` | [BASH] Python subproces execution | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.37 | bash, execution |
| `5014337` | [WINDOWS-SECURITY] CRITICAL - Suspicious TGT Request wi | Potential AS-REP Roasting via Kerberos TGT Requests | `rules/windows/builtin/security/win_security_kerberos_asrep_roasting.yml` | 0.37 | pre-authentication, tgt, ticket, request, type |
| `5009300` | [WINDOWS-MISC] Pass the Hash Detected | Successful Overpass the Hash Attempt | `rules/windows/builtin/security/account_management/win_security_overpass_the_hash.yml` | 0.37 | seclogo, negotiate, hash, logon, type |
| `5100192` | Windows PowerShell device detected | PowerShell as a Service in Registry | `rules/windows/registry/registry_set/registry_set_powershell_as_service.yml` | 0.37 | powershell |
| `5001560` | [HUAWEI] ATCKDF - Ip options route record attack | New Network Route Added | `rules/cloud/aws/cloudtrail/aws_cloudtrail_new_route_added.yml` | 0.37 | route |
| `5014553` | [WINDOWS-SECURITY] Comsrvc MiniDump Command via Service | New Service Creation Using Sc.EXE | `rules/windows/process_creation/proc_creation_win_sc_create_service.yml` | 0.37 | binpath, sc.exe, create |
| `5005651` | [LINUX-AUDITD] base64 execution | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.37 | base64, execution |
| `5007336` | [SOPHOS] Network Traffic Protection cleaned up a threat | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.37 | protection, endpoint, sophos, threat |
| `5007392` | [SOPHOS] Malware cleaned up | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.37 | endpoint, sophos |
| `5007398` | [SOPHOS] Malware cleaned up | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.37 | endpoint, sophos |
| `5014406` | [FORTINET] New user group added | Group Modification Logging | `deprecated/windows/win_security_group_modification_logging.yml` | 0.37 | added, group |
| `5001054` | [RSYNC] Authentication failure | Shell Execution via Rsync - Linux | `rules/linux/process_creation/proc_creation_lnx_rsync_shell_execution.yml` | 0.37 | rsyncd, rsync |
| `5003407` | [WINDOWS-SECURITY] A security-enabled universal group w | A Member Was Removed From a Security-Enabled Global Gro | `rules/windows/builtin/security/account_management/win_security_member_removed_security_enabled_global_group.yml` | 0.37 | security-enabled, group |
| `5009361` | [WINDOWS-POWERSHELL] Schtask Created to Base64 Decode P | Base64 Encoded PowerShell Command Detected | `rules/windows/process_creation/proc_creation_win_powershell_frombase64string.yml` | 0.37 | decode, frombase64string, base64, powershell |
| `5015515` | [WINDOWS-SYSMON] Windows Event Log Cleared | Security Event Log Cleared | `deprecated/windows/win_security_event_log_cleared.yml` | 0.37 | cleared |
| `5010885` | [CyberArk] Privileged group modification blocked. | User Removed From Group With CA Policy Modification Acc | `rules/cloud/azure/audit_logs/azure_group_user_removal_ca_modification.yml` | 0.37 | modification, group |
| `5013877` | [WINDOWS-SECURITY] Possible Impacket Command | Possible Impacket SecretDump Remote Activity | `rules/windows/builtin/security/win_security_impacket_secretdump.yml` | 0.37 | impacket, admin |
| `5009416` | [WINDOWS-SECURITY] The certificate manager settings for | Active Directory Certificate Services Denied Certificat | `rules/windows/builtin/system/microsoft_windows_certification_authority/win_system_adcs_enrollment_request_denied.yml` | 0.37 | certificate |
| `5002107` | [CISCO-WLC] Assoc Flood | Change Default File Association Via Assoc | `rules/windows/process_creation/proc_creation_win_cmd_assoc_execution.yml` | 0.37 | assoc |
| `5014557` | [WINDOWS-SECURITY] RDP Tunnel Detected | Renamed Visual Studio Code Tunnel Execution | `rules/windows/process_creation/proc_creation_win_vscode_tunnel_renamed_execution.yml` | 0.37 | tunnel |
| `5005279` | [MS-DEFENDER] Real-Time Protection Configuration Change | Microsoft Defender Tamper Protection Trigger | `rules/windows/builtin/windefend/win_defender_tamper_protection_trigger.yml` | 0.37 | real-time, protection |
| `5007258` | [SOPHOS] Failed to protect | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.37 | endpoint, sophos |
| `5007410` | [SOPHOS] System Clean failed | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.37 | endpoint, sophos |
| `5005668` | [LINUX-AUDITD] python -m SimpleHTTPServer execution | Python WebServer Execution - Linux | `rules/linux/process_creation/proc_creation_lnx_python_http_server_execution.yml` | 0.37 | simplehttpserver, python, execution |
| `5009311` | [WINDOWS-POWERSHELL] Powershell created local user [3/3 | User Added to Local Administrators Group | `rules/windows/process_creation/proc_creation_win_susp_add_user_local_admin_group.yml` | 0.37 | localgroup, administrators, net, local, add |
| `5013833` | [WINDOWS-SYSMON] MSHTA executing powershell | Suspicious Mshta.EXE Execution Patterns | `rules/windows/process_creation/proc_creation_win_mshta_susp_pattern.yml` | 0.37 | mshta, mshta.exe, powershell.exe |
| `5000365` | [ATTACK] Possible buffer overflow attempt [yppasswd?] | Buffer Overflow Attempts | `rules/linux/builtin/lnx_buffer_overflows.yml` | 0.37 | buffer, overflow |
| `5014479` | [FORTINET] VPN Login After Brute Force | Brute Force | `deprecated/other/generic_brute_force.yml` | 0.37 | brute, force |
| `5002623` | [SONICWALL] Administrator Access not allowed on this in | Login to Disabled Account | `rules/cloud/azure/signin_logs/azure_login_to_disabled_account.yml` | 0.37 | administrator, disabled, login |
| `5000888` | [JUNIPER] AS group missing | Juniper BGP Missing MD5 | `rules/network/juniper/bgp/juniper_bgp_missing_md5.yml` | 0.37 | missing, juniper |
| `5002147` | [CISCO-PRIME] MESH Console login | Mesh Agent Service Installation | `rules/windows/builtin/system/service_control_manager/win_system_service_install_mesh_agent.yml` | 0.37 | mesh |
| `5010601` | [CISCO-SCA] Role Violation | Roles Are Not Being Used | `rules/cloud/azure/privileged_identity_management/azure_pim_role_not_used.yml` | 0.37 | role |
| `5009776` | [WINDOWS-SECURITY] A service was installed in the syste | Invoke-Obfuscation Via Use Rundll32 | `deprecated/windows/proc_creation_win_invoke_obfuscation_via_use_rundll32.yml` | 0.37 | rundll32 |
| `5009776` | [WINDOWS-SECURITY] A service was installed in the syste | Invoke-Obfuscation Via Use Rundll32 | `unsupported/windows/driver_load_invoke_obfuscation_via_use_rundll32_services.yml` | 0.37 | rundll32 |
| `5007330` | [SOPHOS] Sophos Firewall detected malicious traffic | Suspicious Execution of Sc to Delete AV Services | `deprecated/windows/proc_creation_win_sc_delete_av_services.yml` | 0.37 | endpoint, sophos |
| `5003105` | [WINDOWS-MISC] CRITICAL - Installation of PSEXEC servic | PsExec Default Named Pipe | `rules-threat-hunting/windows/pipe_created/pipe_created_sysinternals_psexec_default_pipe.yml` | 0.37 | psexesvc, psexec |
| `5010816` | [CyberArk] Delete User | Azure Application Deleted | `rules/cloud/azure/audit_logs/azure_application_deleted.yml` | 0.37 | delete |
| `5010817` | [CyberArk] Delete Your User | Azure Application Deleted | `rules/cloud/azure/audit_logs/azure_application_deleted.yml` | 0.37 | delete |
| `5010849` | [CyberArk] Delete Rule | Azure Application Deleted | `rules/cloud/azure/audit_logs/azure_application_deleted.yml` | 0.37 | delete |
| `5013802` | [WINDOWS-SYSMON] WinWord created ps1 file | Windows Binaries Write Suspicious Extensions | `rules/windows/file/file_event/file_event_win_shell_write_susp_files_extensions.yml` | 0.37 | ps1 |
| `5002700` | [SONICWALL] Intrusion Detection - Probable TCP NULL sca | OpenCanary - NMAP NULL Scan | `rules/application/opencanary/opencanary_portscan_nmap_null_scan.yml` | 0.37 | null, scan |
| `5008482` | [WINDOWS-AUTH] User added to Group Policy Creator Owner | User Added To Group With CA Policy Modification Access | `rules/cloud/azure/audit_logs/azure_group_user_addition_ca_modification.yml` | 0.37 | added, policy, group |
| `5016599` | [CROWDSTRIKE] This file is classified as Adware/PUP bas | PUA - System Informer Driver Load | `rules/windows/driver_load/driver_load_win_pua_system_informer.yml` | 0.37 | sha256 |
| `5007053` | [WINDOWS-MALWARE] TeslaCrypt ransomware file extension | Cisco Disabling Logging | `rules/network/cisco/aaa/cisco_cli_disable_logging.yml` | 0.37 | aaa |
| `5005917` | [WINDOWS-POWERSHELL] Powershell MAPSReporting Disabled | Login to Disabled Account | `rules/cloud/azure/signin_logs/azure_login_to_disabled_account.yml` | 0.37 | disabled |
| `` | Aggregate of rules setting Sagan bit nxlog_problem | Potential CVE-2023-36884 Exploitation - Share Access | `rules-emerging-threats/2023/Exploits/CVE-2023-36884/win_security_exploit_cve_2023_36884_office_windows_html_rce_share_access_pattern.yml` | 0.36 | 0-9 |
| `5003368` | [PASSWORDSTATE] Password Deleted | Notepad Password Files Discovery | `rules/windows/process_creation/proc_creation_win_notepad_local_passwd_discovery.yml` | 0.36 | password |
| `5015510` | [WINDOWS-SECURITY] PsExec AcceptEULA Detected | Psexec Execution | `rules/windows/process_creation/proc_creation_win_sysinternals_psexec_execution.yml` | 0.36 | psexec.exe, psexec |
| `5002690` | [SONICWALL] No firewall rule exists for VPN policy | The Windows Defender Firewall Service Failed To Load Gr | `rules/windows/builtin/firewall_as/win_firewall_as_failed_load_gpo.yml` | 0.36 | firewall, policy |
| `5005750` | [WINDOWS-POWERSHELL] Powershell History Cleared Detecte | Potential PowerShell Console History Access Attempt via | `rules/windows/process_creation/proc_creation_win_powershell_console_history_file_access.yml` | 0.36 | get-psreadlineoption, historysavepath, history, powershell |
| `5007392` | [SOPHOS] Malware cleaned up | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.36 | endpoint, sophos, malware |
| `5007398` | [SOPHOS] Malware cleaned up | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.36 | endpoint, sophos, malware |
| `5009776` | [WINDOWS-SECURITY] A service was installed in the syste | Invoke-Obfuscation Via Use Rundll32 - Security | `rules/windows/builtin/security/win_security_invoke_obfuscation_via_use_rundll32_services_security.yml` | 0.36 | rundll32 |
| `5013888` | [WINDOWS-SECURITY] net group domain computers command e | Automated Turla Group Lateral Movement | `unsupported/windows/proc_creation_win_correlation_apt_turla_commands_medium.yml` | 0.36 | net, domain, group |
| `5013578` | [WINDOWS-POWERSHELL] OpenSSH.Server Installed via Add-W | Add Windows Capability Via PowerShell Script | `rules/windows/powershell/powershell_script/posh_ps_add_windows_capability.yml` | 0.36 | add-windowscapability, name, powershell |
| `5015126` | [DYNAMIC] ScreenConnect logs detected via program. | Remote Access Tool - ScreenConnect File Transfer | `rules/windows/builtin/application/screenconnect/win_app_remote_access_tools_screenconnect_file_transfer.yml` | 0.36 | screenconnect |
| `5017561` | [CROWDSTRIKE] Possible Defense Evasion Attempt Blocked | Potential Defense Evasion Activity Via Emoji Usage In C | `rules/windows/process_creation/proc_creation_win_susp_emoji_usage_in_cli_1.yml` | 0.36 | defense, evasion |
| `5017561` | [CROWDSTRIKE] Possible Defense Evasion Attempt Blocked | Potential Defense Evasion Activity Via Emoji Usage In C | `rules/windows/process_creation/proc_creation_win_susp_emoji_usage_in_cli_2.yml` | 0.36 | defense, evasion |
| `5017561` | [CROWDSTRIKE] Possible Defense Evasion Attempt Blocked | Potential Defense Evasion Activity Via Emoji Usage In C | `rules/windows/process_creation/proc_creation_win_susp_emoji_usage_in_cli_3.yml` | 0.36 | defense, evasion |
| `5010857` | [CyberArk] Reset Password User | Windows Defender Firewall Has Been Reset To Its Default | `rules/windows/builtin/firewall_as/win_firewall_as_reset_config.yml` | 0.36 | reset |
| `5010858` | [CyberArk] Reset Password Your User | Windows Defender Firewall Has Been Reset To Its Default | `rules/windows/builtin/firewall_as/win_firewall_as_reset_config.yml` | 0.36 | reset |
| `5017640` | [CROWDSTRIKE] File classified as Adware or PUP based on | Cloudflared Quick Tunnel Execution | `rules/windows/process_creation/proc_creation_win_cloudflared_quicktunnel_execution.yml` | 0.36 | sha256 |
| `5000014` | [BASH] histfile=/dev/null | Linux Shell Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_susp_pipe_shell.yml` | 0.36 | bash |
| `5010315` | [NETWRIX] Windows Server - Scheduled Task Added | Scheduled Task Executed From A Suspicious Location | `rules/windows/builtin/taskscheduler/win_taskscheduler_execution_from_susp_locations.yml` | 0.36 | scheduled, task |
| `5017587` | [CROWDSTRIKE] Suspicious Execution Detected - Invoke-Mi | Potential Invoke-Mimikatz PowerShell Script | `rules/windows/powershell/powershell_script/posh_ps_potential_invoke_mimikatz.yml` | 0.36 | invoke-mimikatz, powershell |
| `5006641` | [SentinelOne] Remediate performed successfully | Potential SentinelOne Shell Context Menu Scan Command T | `rules/windows/registry/registry_set/registry_set_sentinelone_shell_context_tampering.yml` | 0.36 | sentinelone |
| `5009327` | [WINDOWS-POWERSHELL] Powershell MAPSReporting Disabled | Login to Disabled Account | `rules/cloud/azure/signin_logs/azure_login_to_disabled_account.yml` | 0.36 | disabled |
| `5014577` | [WINDOWS-SECURITY] Possible Active Directory User Enume | Potential AD User Enumeration From Non-Machine Account | `rules/windows/builtin/security/win_security_ad_user_enumeration.yml` | 0.36 | bf967aba-0de6-11d0-a285-00aa003049e2, read, enumeration, domain |
| `5000934` | [FORTINET] Access profile deleted | PowerShell Profile Modification | `rules/windows/file/file_event/file_event_win_susp_powershell_profile.yml` | 0.36 | profile |
| `5002098` | [WINDOWS-APPLOCKER] Package application installation al | Deployment AppX Package Was Blocked By AppLocker | `rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_applocker_block.yml` | 0.36 | applocker, package |
| `5008418` | [WINDOWS-APPLOCKER] Package application installation al | Deployment AppX Package Was Blocked By AppLocker | `rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_applocker_block.yml` | 0.36 | applocker, package |
| `5005960` | [APACHE] Log4j exploit attempt - CVE-2021-44228 | Log4j RCE CVE-2021-44228 Generic | `rules-emerging-threats/2021/Exploits/CVE-2021-44228/web_cve_2021_44228_log4j.yml` | 0.36 | cve-2021-44228, jndi, log4j |
| `5014557` | [WINDOWS-SECURITY] RDP Tunnel Detected | Mstsc.EXE Execution With Local RDP File | `rules/windows/process_creation/proc_creation_win_mstsc_run_local_rdp_file.yml` | 0.36 | rdp |
| `5013564` | [WINDOWS-SECURITY] WMIC process call create | Potential Process Reconnaissance via Wmic.EXE | `rules/windows/process_creation/proc_creation_win_wmic_recon_process.yml` | 0.36 | wmic, call, create |
| `5001697` | [WINDOWS-AUTH] User added to Group Policy Creator Owner | User Added To Group With CA Policy Modification Access | `rules/cloud/azure/audit_logs/azure_group_user_addition_ca_modification.yml` | 0.36 | added, policy, group |
| `5003764` | [WINDOWS-SECURITY] An attempt was made to set the Direc | Directory Service Restore Mode(DSRM) Registry Value Tam | `rules/windows/registry/registry_set/registry_set_dsrm_tampering.yml` | 0.36 | restore, mode, administrator, password, set, directory |
| `5009403` | [WINDOWS-SECURITY] A security-enabled universal group w | A Member Was Removed From a Security-Enabled Global Gro | `rules/windows/builtin/security/account_management/win_security_member_removed_security_enabled_global_group.yml` | 0.36 | security-enabled, group |
| `5007694` | [WINDOWS-SECURITY] Possible Microsoft Teams token acces | Renamed Microsoft Teams Execution | `rules/windows/process_creation/proc_creation_win_renamed_msteams.yml` | 0.36 | teams.exe, teams, microsoft |
| `5008556` | [WINDOWS-AUTH] Suspicious network login from non-RFC191 | Activity From Anonymous IP Address | `rules/cloud/azure/identity_protection/azure_identity_protection_anonymous_ip_activity.yml` | 0.36 | address |
| `5010506` | [CISCO-SCA] AWS Console Login Failures | AWS ConsoleLogin Failed Authentication | `rules/cloud/aws/cloudtrail/aws_cloudtrail_console_login_failed_authentication.yml` | 0.36 | failures, console, login, aws |
| `5003377` | [WINDOWS-AUTH] Suspicious network login from non-RFC191 | Activity From Anonymous IP Address | `rules/cloud/azure/identity_protection/azure_identity_protection_anonymous_ip_activity.yml` | 0.36 | address |
| `5012098` | [WINDOWS-SECURITY] Inbound RDP Tunneling | Port Forwarding Activity Via SSH.EXE | `rules/windows/process_creation/proc_creation_win_ssh_port_forward.yml` | 0.36 | ssh.exe |
| `5017500` | [CROWDSTRIKE] Possible Defense Evasion Detected - Proce | Windows Defender AMSI Trigger Detected | `rules/windows/builtin/windefend/win_defender_malware_detected_amsi_source.yml` | 0.36 | amsi |
| `5006650` | [SentinelOne] Exclusion was added/modified by user | Potential SentinelOne Shell Context Menu Scan Command T | `rules/windows/registry/registry_set/registry_set_sentinelone_shell_context_tampering.yml` | 0.36 | sentinelone |
| `5009308` | [WINDOWS-POWERSHELL] Powershell History Cleared Detecte | Potential PowerShell Console History Access Attempt via | `rules/windows/process_creation/proc_creation_win_powershell_console_history_file_access.yml` | 0.36 | get-psreadlineoption, historysavepath, history, powershell |
| `5002006` | [WINDOWS-MALWARE] Suspicious Tool Event | Suspicious Kerberos Ticket Request via CLI | `rules/windows/process_creation/proc_creation_win_powershell_kerberos_kerberos_ticket_request_via_cli.yml` | 0.36 | ticket, kerberos |
| `5005253` | [MS-DEFENDER] Microsoft Defender Antivirus Has Deduced | Windows Defender Threat Detection Service Disabled | `rules/windows/builtin/system/service_control_manager/win_system_defender_disabled.yml` | 0.36 | antivirus, defender, microsoft, threat |
| `5003342` | [PASSWORDSTATE] Access was Granted | Google Workspace Granted Domain API Access | `rules/cloud/gcp/gworkspace/admin/gcp_gworkspace_granted_domain_api_access.yml` | 0.36 | granted |
| `5009404` | [WINDOWS-SECURITY] A security-enabled universal group w | A Member Was Added to a Security-Enabled Global Group | `rules/windows/builtin/security/account_management/win_security_member_added_security_enabled_global_group.yml` | 0.36 | security-enabled, group |
| `5000992` | [SNORT] A suspicious filename was detected | Space After Filename | `deprecated/linux/lnx_space_after_filename_.yml` | 0.36 | filename |
| `5002100` | [WINDOWS-APPLOCKER] Package application installation di | Deployment AppX Package Was Blocked By AppLocker | `rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_applocker_block.yml` | 0.36 | applocker, package |
| `5007337` | [SOPHOS] Network Traffic Protection could not clean up | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.36 | protection, endpoint, sophos, threat |
| `5008420` | [WINDOWS-APPLOCKER] Package application installation di | Deployment AppX Package Was Blocked By AppLocker | `rules/windows/builtin/appxdeployment_server/win_appxdeployment_server_applocker_block.yml` | 0.36 | applocker, package |
| `5010885` | [CyberArk] Privileged group modification blocked. | User Added To Group With CA Policy Modification Access | `rules/cloud/azure/audit_logs/azure_group_user_addition_ca_modification.yml` | 0.36 | modification, group |
| `5010489` | [WINDOWS-SECURITY] Possible Obfuscation - CMD with Care | Cmd Stream Redirection | `deprecated/windows/proc_creation_win_cmd_redirect_to_stream.yml` | 0.36 | redirection, cmd, cmd.exe |
| `9870007` | [EXPERIMENTAL][WINDOWS-SECURITY] Kerberos - Service Tic | Suspicious Kerberos Ticket Request via CLI | `rules/windows/process_creation/proc_creation_win_powershell_kerberos_kerberos_ticket_request_via_cli.yml` | 0.36 | kerberoasting, ticket, kerberos, request |
| `5000392` | [TELNET] Attempt to login with an option | OpenCanary - Telnet Login Attempt | `rules/application/opencanary/opencanary_telnet_login_attempt.yml` | 0.36 | telnet, login |
| `5013889` | [WINDOWS-SECURITY] net group domain controllers command | Automated Turla Group Lateral Movement | `unsupported/windows/proc_creation_win_correlation_apt_turla_commands_medium.yml` | 0.36 | net, domain, group |
| `5100033` | MySQL services detected | Uncommon File Creation By Mysql Daemon Process | `rules/windows/file/file_event/file_event_win_mysqld_uncommon_file_creation.yml` | 0.36 | mysql |
| `5000102` | [BIND] Denied zone transfer attempt | Failed DNS Zone Transfer | `rules/windows/builtin/dns_server/win_dns_server_failed_dns_zone_transfer.yml` | 0.36 | zone, transfer |
| `5009762` | [WINDOWS-SECURITY] Possible Microsoft Teams token acces | Renamed Microsoft Teams Execution | `rules/windows/process_creation/proc_creation_win_renamed_msteams.yml` | 0.36 | teams.exe, teams, microsoft |
| `5005961` | [APACHE] Log4j exploit attempt via hex encoding - CVE-2 | Log4j RCE CVE-2021-44228 Generic | `rules-emerging-threats/2021/Exploits/CVE-2021-44228/web_cve_2021_44228_log4j.yml` | 0.36 | cve-2021-44228, jndi, log4j |
| `5015244` | [NETSKOPE] Password Change Failed Attempt Event Detecte | AWS RDS Master Password Change | `rules/cloud/aws/cloudtrail/aws_rds_change_master_password.yml` | 0.36 | change, password |
| `5014593` | [WINDOWS-SYSMON] GitHub Cloning of Group3R Detected - A | OpenCanary - GIT Clone Request | `rules/application/opencanary/opencanary_git_clone_request.yml` | 0.36 | clone, git |
| `5100163` | Azure Eventhub device detected | Azure Device or Configuration Modified or Deleted | `rules/cloud/azure/activity_logs/azure_device_or_configuration_modified_or_deleted.yml` | 0.36 | azure, device |
| `5015244` | [NETSKOPE] Password Change Failed Attempt Event Detecte | Notepad Password Files Discovery | `rules/windows/process_creation/proc_creation_win_notepad_local_passwd_discovery.yml` | 0.36 | password |
| `5013567` | [WINDOWS-TERMINAL-SERVICES] RDP connection to loopback | RDP over Reverse SSH Tunnel WFP | `rules/windows/builtin/security/win_security_rdp_reverse_tunnel.yml` | 0.36 | loopback, rdp, address |
| `5017500` | [CROWDSTRIKE] Possible Defense Evasion Detected - Proce | Removal Of AMSI Provider Registry Keys | `rules/windows/registry/registry_delete/registry_delete_removal_amsi_registry_key.yml` | 0.36 | amsi, provider |
| `5007126` | [WINDOWS-POWERSHELL] Microsoft Defender Security Regist | Windows Defender Threat Detection Service Disabled | `rules/windows/builtin/system/service_control_manager/win_system_defender_disabled.yml` | 0.36 | protection, defender, microsoft, threat |
| `5007364` | [SOPHOS] CryptoGuard detected ransomware | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.36 | endpoint, sophos |
| `5014561` | [WINDOWS-SECURITY] Inbound RDP Tunneling | Port Forwarding Activity Via SSH.EXE | `rules/windows/process_creation/proc_creation_win_ssh_port_forward.yml` | 0.36 | ssh.exe |
| `5002148` | [CISCO-PRIME] MESH authorization failure | Mesh Agent Service Installation | `rules/windows/builtin/system/service_control_manager/win_system_service_install_mesh_agent.yml` | 0.36 | mesh |
| `5007259` | [SOPHOS] New protected | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.36 | endpoint, sophos |
| `5008384` | [DYNAMIC] windows clipboard logs detected via program. | Clipboard Collection with Xclip Tool - Auditd | `rules/linux/auditd/execve/lnx_auditd_clipboard_collection.yml` | 0.36 | clipboard |
| `5100160` | AWS GuardDuty detected | AWS GuardDuty Detector Deleted Or Updated | `rules/cloud/aws/cloudtrail/aws_cloudtrail_guardduty_detector_deleted_or_updated.yml` | 0.36 | guardduty.amazonaws.com, guardduty, aws |
| `5005277` | [MS-DEFENDER] Real-Time Protection Is Enabled | Windows Defender Real-time Protection Disabled | `rules/windows/builtin/windefend/win_defender_real_time_protection_disabled.yml` | 0.36 | real-time, protection |
| `5007328` | [SOPHOS] Malware cleaned up | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.36 | endpoint, sophos |
| `5007417` | [SOPHOS] Outbreak detected | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.36 | endpoint, sophos |
| `5010881` | [CyberArk] Changes to the Master Policy failed | AWS RDS Master Password Change | `rules/cloud/aws/cloudtrail/aws_rds_change_master_password.yml` | 0.36 | master |
| `5005296` | [CLOUDTRAIL] IAM cloudtrail event detected - (CreateAcc | AWS IAM S3Browser User or AccessKey Creation | `rules/cloud/aws/cloudtrail/aws_iam_s3browser_user_or_accesskey_creation.yml` | 0.36 | createaccesskey, iam.amazonaws.com, iam |
| `5012103` | [SONICWALL] Admin Login Disabled | Admin User Remote Logon | `rules/windows/builtin/security/account_management/win_security_admin_rdp_login.yml` | 0.36 | admin, login |
| `5000247` | [XINETD] Telnet connection from remote host | OpenCanary - Telnet Login Attempt | `rules/application/opencanary/opencanary_telnet_login_attempt.yml` | 0.36 | telnet |
| `5014327` | [WINDOWS-SECURITY] PowerShell Invoke Web-Request Detect | PowerShell Web Download | `deprecated/windows/proc_creation_win_powershell_download_cradles.yml` | 0.36 | iwr, invoke-webrequest, powershell |
| `5014404` | [FORTINET] Access profile deleted | PowerShell Profile Modification | `rules/windows/file/file_event/file_event_win_susp_powershell_profile.yml` | 0.36 | profile |
| `5003204` | [WINDOWS-MALWARE] Bad Rabbit Malware scheduled task det | Scheduled Task Executed From A Suspicious Location | `rules/windows/builtin/taskscheduler/win_taskscheduler_execution_from_susp_locations.yml` | 0.36 | scheduled, task |
| `5009383` | [WINDOWS-SECURITY] An attempt was made to set the Direc | Directory Service Restore Mode(DSRM) Registry Value Tam | `rules/windows/registry/registry_set/registry_set_dsrm_tampering.yml` | 0.36 | restore, mode, administrator, password, set, directory |
| `5008753` | [WINDOWS-MALWARE] Bad Rabbit Malware scheduled task det | Scheduled Task Executed From A Suspicious Location | `rules/windows/builtin/taskscheduler/win_taskscheduler_execution_from_susp_locations.yml` | 0.36 | scheduled, task |
| `5011194` | [CARBONBLACK-APP-CONTROL] Updater disabled (Info) | Login to Disabled Account | `rules/cloud/azure/signin_logs/azure_login_to_disabled_account.yml` | 0.36 | disabled |
| `5015071` | [WINDOWS-SECURITY] Impacket PsExec Named PIPE | RemCom Service File Creation | `rules/windows/file/file_event/file_event_win_remcom_service.yml` | 0.36 | remcom |
| `5007375` | [SOPHOS] Pua has been cleaned up | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.36 | endpoint, sophos |
| `5009339` | [WINDOWS-POWERSHELL] Microsoft Defender Security Regist | Windows Defender Threat Detection Service Disabled | `rules/windows/builtin/system/service_control_manager/win_system_defender_disabled.yml` | 0.36 | protection, defender, microsoft, threat |
| `5010772` | [CyberArk] Update Location | Flash Player Update from Suspicious Location | `rules/web/proxy_generic/proxy_susp_flash_download_loc.yml` | 0.36 | update, location |
| `5007334` | [SOPHOS] Malicious outbound network traffic blocked | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.36 | endpoint, sophos, threat |
| `5007335` | [SOPHOS] Malicious outbound network traffic blocked | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.36 | endpoint, sophos, threat |
| `5010315` | [NETWRIX] Windows Server - Scheduled Task Added | Scheduled Task Executed Uncommon LOLBIN | `rules/windows/builtin/taskscheduler/win_taskscheduler_lolbin_execution_via_task_scheduler.yml` | 0.36 | scheduled, task |
| `5013841` | [WINDOWS-SECURITY] OneNote executing CMD | OneNote.EXE Execution of Malicious Embedded Scripts | `rules/windows/process_creation/proc_creation_win_office_onenote_embedded_script_execution.yml` | 0.36 | onenote, onenote.exe, cmd.exe |
| `5013856` | [WINDOWS-SYSMON] netsh firewall add allowedprogram | Suspicious Program Location Whitelisted In Firewall Via | `rules/windows/process_creation/proc_creation_win_netsh_fw_allow_program_in_susp_location.yml` | 0.36 | allowedprogram, netsh, firewall, add |
| `5014554` | [WINDOWS-SECURITY] Possible Obfuscation - CMD with Care | Cmd Stream Redirection | `deprecated/windows/proc_creation_win_cmd_redirect_to_stream.yml` | 0.36 | redirection, cmd, cmd.exe |
| `5000014` | [BASH] histfile=/dev/null | Bash Interactive Shell | `rules/linux/process_creation/proc_creation_lnx_bash_interactive_shell.yml` | 0.36 | bash |
| `5006649` | [SentinelOne] Quarantine pending to reboot | Potential SentinelOne Shell Context Menu Scan Command T | `rules/windows/registry/registry_set/registry_set_sentinelone_shell_context_tampering.yml` | 0.36 | sentinelone |
| `5008373` | [WINDOWS-CLIPBOARD] net commands | Reconnaissance Activity | `rules/windows/builtin/security/win_security_susp_net_recon_activity.yml` | 0.36 | net, group |
| `5008374` | [WINDOWS-CLIPBOARD] net commands | Reconnaissance Activity | `rules/windows/builtin/security/win_security_susp_net_recon_activity.yml` | 0.36 | net, group |
| `5007338` | [SOPHOS] Running malware cleaned up | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.36 | endpoint, sophos, threat, malware |
| `5014591` | [WINDOWS-SYSMON] Use Of ADExplorer Detected - Active Di | Suspicious Active Directory Database Snapshot Via ADExp | `rules/windows/process_creation/proc_creation_win_sysinternals_adexplorer_susp_execution.yml` | 0.36 | adexplorer, adexplorer64.exe, adexplorer.exe, active, directory |
| `5015510` | [WINDOWS-SECURITY] PsExec AcceptEULA Detected | Renamed PsExec | `deprecated/windows/proc_creation_win_renamed_psexec.yml` | 0.36 | psexec.exe, psexec |
| `5001830` | [WEB-ATTACKS] WITOOL SQL Injection Scan | Exploit Framework User Agent | `rules/web/proxy_generic/proxy_ua_frameworks.yml` | 0.36 | 6.0, mozilla/4.0, msie, compatible |
| `5017585` | [CROWDSTRIKE] Invoke-Mimikatz executed via PowerShell - | Potential Invoke-Mimikatz PowerShell Script | `rules/windows/powershell/powershell_script/posh_ps_potential_invoke_mimikatz.yml` | 0.36 | invoke-mimikatz, powershell |
| `5017619` | [CROWDSTRIKE] Possible Impact Detected - Process Attemp | Volume Shadow Copy Mount | `rules/windows/builtin/system/microsoft_windows_ntfs/win_system_volume_shadow_copy_mount.yml` | 0.36 | shadow, volume |
| `5100099` | Telnet service detected | OpenCanary - Telnet Login Attempt | `rules/application/opencanary/opencanary_telnet_login_attempt.yml` | 0.36 | telnet |
| `5003366` | [PASSWORDSTATE] User Removed From Security Group | A Member Was Removed From a Security-Enabled Global Gro | `rules/windows/builtin/security/account_management/win_security_member_removed_security_enabled_global_group.yml` | 0.36 | removed, group |
| `5014330` | [WINDOWS-SECURITY] User Created with Net User Command | Automated Turla Group Lateral Movement | `unsupported/windows/proc_creation_win_correlation_apt_turla_commands_medium.yml` | 0.36 | net |
| `5005667` | [LINUX-AUDITD] getent passwd execution | Copy Passwd Or Shadow From TMP Path | `rules/linux/process_creation/proc_creation_lnx_cp_passwd_or_shadow_tmp.yml` | 0.36 | passwd |
| `5007343` | [SOPHOS] PUA cleaned up | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.36 | endpoint, sophos, threat |
| `5008360` | [WINDOWS-SECURITY] A service was installed in the syste | Invoke-Obfuscation Via Use Rundll32 | `deprecated/windows/proc_creation_win_invoke_obfuscation_via_use_rundll32.yml` | 0.36 | rundll32 |
| `5008360` | [WINDOWS-SECURITY] A service was installed in the syste | Invoke-Obfuscation Via Use Rundll32 | `unsupported/windows/driver_load_invoke_obfuscation_via_use_rundll32_services.yml` | 0.36 | rundll32 |
| `5008644` | [WINDOWS-CLIPBOARD] net commands | Reconnaissance Activity | `rules/windows/builtin/security/win_security_susp_net_recon_activity.yml` | 0.36 | net, group |
| `5008645` | [WINDOWS-CLIPBOARD] net commands | Reconnaissance Activity | `rules/windows/builtin/security/win_security_susp_net_recon_activity.yml` | 0.36 | net, group |
| `5015084` | [WINDOWS-POWERSHELL] Windows Defender Uninstalled via P | Suspicious Uninstall of Windows Defender Feature via Po | `rules/windows/process_creation/proc_creation_win_powershell_uninstall_defender_feature.yml` | 0.36 | uninstall-windowsfeature, windows-defender, defender, powershell |
| `5017782` | [CROWDSTRIKE] Machine Learning Analysis Blocked - Scree | Remote Access Tool - ScreenConnect Command Execution | `rules/windows/builtin/application/screenconnect/win_app_remote_access_tools_screenconnect_command_exec.yml` | 0.36 | screenconnect |
| `5015262` | [NETSKOPE] Reset password Event Detected | Notepad Password Files Discovery | `rules/windows/process_creation/proc_creation_win_notepad_local_passwd_discovery.yml` | 0.36 | password |
| `5013843` | [WINDOWS-SECURITY] OneNote executing MSHTA | OneNote.EXE Execution of Malicious Embedded Scripts | `rules/windows/process_creation/proc_creation_win_office_onenote_embedded_script_execution.yml` | 0.36 | onenote, onenote.exe, mshta.exe |
| `5002571` | [CYLANCE] Device - Action Taken | Device Installation Blocked | `rules/windows/builtin/security/win_security_device_installation_blocked.yml` | 0.36 | device |
| `5017498` | [CROWDSTRIKE] Possible Defense Evasion Blocked - Proces | Windows Defender AMSI Trigger Detected | `rules/windows/builtin/windefend/win_defender_malware_detected_amsi_source.yml` | 0.36 | amsi |
| `5000101` | [BIND] Invalid DNS packet. Possible attack | Suspicious Named Error | `rules/linux/builtin/syslog/lnx_syslog_susp_named.yml` | 0.36 | dropping, zero, packet, source, port, named |
| `5005670` | [LINUX-AUDITD] /etc/sudoers access | Access of Sudoers File Content | `rules/linux/process_creation/proc_creation_lnx_susp_process_reading_sudoers.yml` | 0.36 | etc/sudoers |
| `5010803` | [CyberArk] Get License Information | Invalid PIM License | `rules/cloud/azure/privileged_identity_management/azure_pim_invalid_license.yml` | 0.36 | license |
| `5017588` | [CROWDSTRIKE] CrackMapExec executed on host - Blocked | HackTool - Potential Remote Credential Dumping Activity | `rules/windows/file/file_event/file_event_win_hktl_remote_cred_dump.yml` | 0.36 | crackmapexec, execution |
| `5100180` | Github device detected | New Github Organization Member Added | `rules/application/github/audit/github_new_org_member.yml` | 0.36 | github |
| `5100019` | Generic crond detected | Masquerading as Linux Crond Process | `rules/linux/auditd/execve/lnx_auditd_masquerading_crond.yml` | 0.36 | crond |
| `5100137` | Fortigate device detected | Potential CVE-2023-36884 Exploitation - Share Access | `rules-emerging-threats/2023/Exploits/CVE-2023-36884/win_security_exploit_cve_2023_36884_office_windows_html_rce_share_access_pattern.yml` | 0.36 | 0-9 |
| `5002988` | [DYNAMIC] Nginx logs detected via program. | Nginx Core Dump | `rules/web/product/nginx/web_nginx_core_dump.yml` | 0.36 | nginx |
| `5100030` | Unix 'kernel' messages detected | CodeIntegrity - Unsigned Kernel Module Loaded | `rules/windows/builtin/code_integrity/win_codeintegrity_unsigned_driver_loaded.yml` | 0.36 | kernel |
| `5007750` | [WINDOWS-SYSMON] Possible DLL Hijacking of aclui.dll | Potential Raspberry Robin Aclui Dll SideLoading | `rules-emerging-threats/2024/Malware/Raspberry-Robin/image_load_malware_raspberry_robin_side_load_aclui_oleview.yml` | 0.36 | aclui.dll, dll |
| `5008148` | [WINDOWS-SYSMON] Possible DLL Hijacking of aclui.dll | Potential Raspberry Robin Aclui Dll SideLoading | `rules-emerging-threats/2024/Malware/Raspberry-Robin/image_load_malware_raspberry_robin_side_load_aclui_oleview.yml` | 0.36 | aclui.dll, dll |
| `5010983` | [CARBONBLACK-APP-CONTROL] Agent uninstalled (Notice) | Application Uninstalled | `rules/windows/builtin/application/msiinstaller/win_builtin_remove_application.yml` | 0.36 | uninstalled |
| `5001002` | [SNORT] Generic Protocol Command Decode | File Decoded From Base64/Hex Via Certutil.EXE | `rules/windows/process_creation/proc_creation_win_certutil_decode.yml` | 0.36 | decode |
| `5013568` | [WINDOWS-SECURITY] Log on using default linux workstati | Suspicious Workstation Locking via Rundll32 | `rules/windows/process_creation/proc_creation_win_rundll32_user32_dll.yml` | 0.36 | workstation |
| `5013801` | [WINDOWS-SYSMON] Powershell converting Base64 and execu | Suspicious PowerShell IEX Execution Patterns | `rules/windows/process_creation/proc_creation_win_powershell_iex_patterns.yml` | 0.36 | system.convert, iex, powershell.exe, powershell, execution |
| `5014591` | [WINDOWS-SYSMON] Use Of ADExplorer Detected - Active Di | Active Directory Database Snapshot Via ADExplorer | `rules/windows/process_creation/proc_creation_win_sysinternals_adexplorer_execution.yml` | 0.36 | adexplorer, adexplorer64.exe, adexplorer.exe, active, directory |
| `5010520` | [CISCO-SCA] AWS Temporary Token Persistence | Anomalous Token | `rules/cloud/azure/identity_protection/azure_identity_protection_anomalous_token.yml` | 0.36 | token |
| `5008360` | [WINDOWS-SECURITY] A service was installed in the syste | Invoke-Obfuscation Via Use Rundll32 - Security | `rules/windows/builtin/security/win_security_invoke_obfuscation_via_use_rundll32_services_security.yml` | 0.36 | rundll32 |
| `5100133` | Cisco Meraki device detected | Potential CVE-2023-36884 Exploitation - Share Access | `rules-emerging-threats/2023/Exploits/CVE-2023-36884/win_security_exploit_cve_2023_36884_office_windows_html_rce_share_access_pattern.yml` | 0.36 | 0-9 |
| `5009815` | [WINDOWS-SYSMON] Possible DLL Hijacking of aclui.dll | Potential Raspberry Robin Aclui Dll SideLoading | `rules-emerging-threats/2024/Malware/Raspberry-Robin/image_load_malware_raspberry_robin_side_load_aclui_oleview.yml` | 0.36 | aclui.dll, dll |
| `5010213` | [WINDOWS-SYSMON] Possible DLL Hijacking of aclui.dll | Potential Raspberry Robin Aclui Dll SideLoading | `rules-emerging-threats/2024/Malware/Raspberry-Robin/image_load_malware_raspberry_robin_side_load_aclui_oleview.yml` | 0.36 | aclui.dll, dll |
| `5017334` | [DYNAMIC] Azure Eventhub Windows Clipboard Logs Detecte | Clipboard Access Via OSAScript | `rules/macos/process_creation/proc_creation_macos_clipboard_access_via_osascript.yml` | 0.35 | clipboard |
| `5015047` | [VEEAM] Global VM Exclusions Added | Windows Defender Exclusions Added | `rules/windows/builtin/windefend/win_defender_config_change_exclusion_added.yml` | 0.35 | exclusions, added |
| `5010507` | [CISCO-SCA] AWS Detector Modified | AWS GuardDuty Detector Deleted Or Updated | `rules/cloud/aws/cloudtrail/aws_cloudtrail_guardduty_detector_deleted_or_updated.yml` | 0.35 | detector, aws |
| `5009404` | [WINDOWS-SECURITY] A security-enabled universal group w | A Member Was Removed From a Security-Enabled Global Gro | `rules/windows/builtin/security/account_management/win_security_member_removed_security_enabled_global_group.yml` | 0.35 | security-enabled, group |
| `5002924` | [CARBONBLACK-APP-CONTROL] File was executed for the fir | Discovery of a System Time | `rules/windows/process_creation/proc_creation_win_remote_time_discovery.yml` | 0.35 | time |
| `5011211` | [CARBONBLACK-APP-CONTROL] Database error (Error) | Sysmon Configuration Error | `rules/windows/sysmon/sysmon_config_modification_error.yml` | 0.35 | error |
| `5010957` | [GITHUB] Repository Published | GitHub Repository Archive Status Changed | `rules/application/github/audit/github_repository_archive_status_changed.yml` | 0.35 | repository, github |
| `5014329` | [WINDOWS-SECURITY] Suspicious Service Control Command | New Service Creation | `deprecated/windows/proc_creation_win_new_service_creation.yml` | 0.35 | binpath, create |
| `5007258` | [SOPHOS] Failed to protect | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.35 | endpoint, sophos |
| `5007410` | [SOPHOS] System Clean failed | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.35 | endpoint, sophos |
| `5010625` | [CISCO-SCA] Unusually Large EC2 Instance | Unusually Long PowerShell CommandLine | `rules-threat-hunting/windows/process_creation/proc_creation_win_powershell_abnormal_commandline_size.yml` | 0.35 | unusually |
| `5006648` | [SentinelOne] Kill pending to reboot | Potential SentinelOne Shell Context Menu Scan Command T | `rules/windows/registry/registry_set/registry_set_sentinelone_shell_context_tampering.yml` | 0.35 | sentinelone |
| `5007285` | [SOPHOS] Access has been blocked by web filtering | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.35 | endpoint, sophos |
| `5007384` | [SOPHOS] AMSI Protection blocked a threat | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.35 | endpoint, sophos |
| `5007385` | [SOPHOS] AMSI Protection blocked a threat | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.35 | endpoint, sophos |
| `5001126` | [ADTRAN] TCP INTERNAL BLOCK | PUA - Ngrok Execution | `rules/windows/process_creation/proc_creation_win_pua_ngrok.yml` | 0.35 | tcp |
| `5003204` | [WINDOWS-MALWARE] Bad Rabbit Malware scheduled task det | Scheduled Task Executed Uncommon LOLBIN | `rules/windows/builtin/taskscheduler/win_taskscheduler_lolbin_execution_via_task_scheduler.yml` | 0.35 | scheduled, task |
| `5003893` | [CISCO-SECUREENDPOINT] Cloud Recall Quarantine Attempt | Windows Recall Feature Enabled - Registry | `rules/windows/registry/registry_set/registry_set_enable_windows_recall.yml` | 0.35 | recall |
| `5008753` | [WINDOWS-MALWARE] Bad Rabbit Malware scheduled task det | Scheduled Task Executed Uncommon LOLBIN | `rules/windows/builtin/taskscheduler/win_taskscheduler_lolbin_execution_via_task_scheduler.yml` | 0.35 | scheduled, task |
| `5017498` | [CROWDSTRIKE] Possible Defense Evasion Blocked - Proces | Removal Of AMSI Provider Registry Keys | `rules/windows/registry/registry_delete/registry_delete_removal_amsi_registry_key.yml` | 0.35 | amsi, provider |
| `5015509` | [WINDOWS-SECURITY] PsExec Executed from Suspicious Dire | Psexec Execution | `rules/windows/process_creation/proc_creation_win_sysinternals_psexec_execution.yml` | 0.35 | psexec.exe, psexec |
| `5017397` | [WINDOWS-SECURITY] Use Of LOLBIN Detected - wlrmdr.exe | HTTP Request With Empty User Agent | `rules/web/proxy_generic/proxy_ua_empty.yml` | 0.35 | empty |
| `5017641` | [CROWDSTRIKE] File classified as Adware or PUP based on | PUA - System Informer Driver Load | `rules/windows/driver_load/driver_load_win_pua_system_informer.yml` | 0.35 | sha256 |
| `5002091` | [WINDOWS-APPLOCKER] Application blocked | AppLocker Application Would Have Been Blocked | `rules/windows/builtin/applocker/win_applocker_application_would_have_been_blocked.yml` | 0.35 | applocker, blocked |
| `5006596` | [DELL EMC UNITY] A STORAGE PROCESSOR WRITE CACHE HAS BE | Write Protect For Storage Disabled | `rules/windows/process_creation/proc_creation_win_reg_write_protect_for_storage_disabled.yml` | 0.35 | write, storage, disabled |
| `5007403` | [SOPHOS] PUA cleaned up | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.35 | endpoint, sophos |
| `5008411` | [WINDOWS-APPLOCKER] Application blocked | AppLocker Application Would Have Been Blocked | `rules/windows/builtin/applocker/win_applocker_application_would_have_been_blocked.yml` | 0.35 | applocker, blocked |
| `5010617` | [CISCO-SCA] Suspicious SMB Activity | OpenCanary - SMB File Open Request | `rules/application/opencanary/opencanary_smb_file_open.yml` | 0.35 | smb |
| `5013835` | [WINDOWS-SYSMON] CMD set in Registry Key | Suspicious RunAs-Like Flag Combination | `rules/windows/process_creation/proc_creation_win_susp_privilege_escalation_cli_patterns.yml` | 0.35 | cmd, set |
| `5013920` | [WINDOWS-SECURITY] Possible lateral movement via wmic | WMIC Remote Command Execution | `rules/windows/process_creation/proc_creation_win_wmic_remote_execution.yml` | 0.35 | node, wmic |
| `5015827` | [Barracuda] WAF Virus Scan - Virus Found | Windows Defender Virus Scanning Feature Disabled | `rules/windows/builtin/windefend/win_defender_virus_scan_disabled.yml` | 0.35 | virus |
| `5007327` | [SOPHOS] Malware locally cleared | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.35 | endpoint, sophos, threat, malware |
| `5005766` | [DYNAMIC] PowerShell logs detect via program | PowerShell as a Service in Registry | `rules/windows/registry/registry_set/registry_set_powershell_as_service.yml` | 0.35 | powershell |
| `5003350` | [PASSWORDSTATE] Discovery Job Deleted | New BITS Job Created Via PowerShell | `rules/windows/builtin/bits_client/win_bits_client_new_job_via_powershell.yml` | 0.35 | job |
| `5015584` | [Barracuda] IMPERSONATION Account Takeover - Threat Fou | Suspicious Inbox Manipulation Rules | `rules/cloud/azure/identity_protection/azure_identity_protection_inbox_manipulation.yml` | 0.35 | inbox |
| `5006616` | [SentinelOne] New blocked threat | Potential SentinelOne Shell Context Menu Scan Command T | `rules/windows/registry/registry_set/registry_set_sentinelone_shell_context_tampering.yml` | 0.35 | sentinelone |
| `5014640` | [LINUX-SECURITY] User Added to SUDO Group Command Detec | Sudo Privilege Escalation CVE-2019-14287 | `rules-emerging-threats/2019/Exploits/CVE-2019-14287/proc_creation_lnx_exploit_cve_2019_14287.yml` | 0.35 | sudo |
| `5002333` | [BASH] LD_PRELOAD environment variable access | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.35 | bash |
| `5002334` | [BASH] LD_LIBRARY_PATH environment variable access | Linux Base64 Encoded Pipe to Shell | `rules/linux/process_creation/proc_creation_lnx_base64_execution.yml` | 0.35 | bash |
| `5007334` | [SOPHOS] Malicious outbound network traffic blocked | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.35 | endpoint, sophos |
| `5007335` | [SOPHOS] Malicious outbound network traffic blocked | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.35 | endpoint, sophos |
| `5001559` | [HUAWEI] ATCKDF - Trace route attack | New Network Trace Capture Started Via Netsh.EXE | `rules/windows/process_creation/proc_creation_win_netsh_packet_capture.yml` | 0.35 | trace |
| `5007138` | [WINDOWS-POWERSHELL] .NET Assembly Loaded | Potential In-Memory Execution Using Reflection.Assembly | `rules/windows/powershell/powershell_script/posh_ps_dotnet_assembly_from_file.yml` | 0.35 | reflection.assembly |
| `5014592` | [WINDOWS-SYSMON] Snapshot Creation Using ADExplorer Det | ADExplorer Writing Complete AD Snapshot Into .dat File | `rules/windows/file/file_event/file_event_win_sysinternals_adexplorer_dump_written.yml` | 0.35 | adexplorer, adexplorer.exe, dat, snapshot |
| `5007146` | [WINDOWS-POWERSHELL] Registry Set Value for WDigest Use | Wdigest CredGuard Registry Modification | `rules/windows/registry/registry_event/registry_event_disable_wdigest_credential_guard.yml` | 0.35 | uselogoncredential, wdigest, hklm, value, registry |
| `5001041` | [HOSTAPD] Possible downgrade attack | NetNTLM Downgrade Attack | `rules/windows/builtin/security/win_security_net_ntlm_downgrade.yml` | 0.35 | downgrade, attack |
| `5003882` | [CISCO-SECUREENDPOINT] Threat Detected in Exclusion | Windows Defender Exclusion List Modified | `rules/windows/builtin/security/win_security_windows_defender_exclusions_registry_modified.yml` | 0.35 | exclusion |
| `5007369` | [SOPHOS] exploit prevented | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.35 | endpoint, sophos |
| `5017784` | [CROWDSTRIKE] Machine Learning Analysis Blocked - TeamV | TeamViewer Log File Deleted | `rules/windows/file/file_delete/file_delete_win_delete_teamviewer_logs.yml` | 0.35 | teamviewer |
| `5007403` | [SOPHOS] PUA cleaned up | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.35 | endpoint, sophos |
| `5007358` | [SOPHOS] malicious behavior prevented | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.35 | endpoint, sophos |
| `5000931` | [FORTINET] New access profile added | PowerShell Profile Modification | `rules/windows/file/file_event/file_event_win_susp_powershell_profile.yml` | 0.35 | profile |
| `5002728` | [SONICWALL] Intrusion Detection - TCP Xmas Tree dropped | OpenCanary - NMAP XMAS Scan | `rules/application/opencanary/opencanary_portscan_nmap_xmas_scan.yml` | 0.35 | xmas |
| `5007343` | [SOPHOS] PUA cleaned up | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.35 | endpoint, sophos |
| `5012094` | [WINDOWS-SECURITY] RDP Tunnel Detected | RDP Over Reverse SSH Tunnel | `rules/windows/network_connection/net_connection_win_rdp_reverse_tunnel.yml` | 0.35 | tunnel, rdp |
| `5009359` | [WINDOWS-POWERSHELL] Registry Set Value for WDigest Use | Wdigest CredGuard Registry Modification | `rules/windows/registry/registry_event/registry_event_disable_wdigest_credential_guard.yml` | 0.35 | uselogoncredential, wdigest, hklm, value, registry |
| `5005843` | [DARKTRACE] Potential Malicious Anomalous Server Activi | Anomalous User Activity | `rules/cloud/azure/identity_protection/azure_identity_protection_anomalous_user.yml` | 0.35 | anomalous |
| `5005958` | [WEB-ATTACKS] Log4j exploit attempt - CVE-2021-44228 | Log4j RCE CVE-2021-44228 in Fields | `rules-emerging-threats/2021/Exploits/CVE-2021-44228/web_cve_2021_44228_log4j_fields.yml` | 0.35 | cve-2021-44228, jndi, log4j |
| `5017617` | [CROWDSTRIKE] Possible Impact Blocked - Process Attempt | Volume Shadow Copy Mount | `rules/windows/builtin/system/microsoft_windows_ntfs/win_system_volume_shadow_copy_mount.yml` | 0.35 | shadow, volume |
| `5003440` | [WINDOWS-SECURITY] The Windows Firewall Service failed | The Windows Defender Firewall Service Failed To Load Gr | `rules/windows/builtin/firewall_as/win_firewall_as_failed_load_gpo.yml` | 0.35 | firewall, failed |
| `5007351` | [SOPHOS] Threat remnants deleted | Potential Tampering With Security Products Via WMIC | `rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml` | 0.35 | endpoint, sophos, threat |
| `5007366` | [SOPHOS] CryptoGuard detected a ransomware attack | Tamper With Sophos AV Registry Keys | `rules/windows/registry/registry_set/registry_set_sophos_av_tamper.yml` | 0.35 | endpoint, sophos |
| `5017743` | [CROWDSTRIKE] Possible Defense Evasion Detected - Msiex | MsiExec Web Install | `rules/windows/process_creation/proc_creation_win_msiexec_web_install.yml` | 0.35 | msiexec |
| `5017212` | [DYNAMIC] AWS RDS Logs Detected | Modification or Deletion of an AWS RDS Cluster | `rules/cloud/aws/cloudtrail/aws_rds_dbcluster_actions.yml` | 0.35 | rds.amazonaws.com, rds, aws |
| `5008485` | [WINDOWS-AUTH] Potential Windows User Enumeration - Use | COM Object Execution via Xwizard.EXE | `rules/windows/process_creation/proc_creation_win_xwizard_runwizard_com_object_exec.yml` | 0.35 | a-fa-f0-9 |
| `5010844` | [CyberArk] Delete Group Member | User Removed From Group With CA Policy Modification Acc | `rules/cloud/azure/audit_logs/azure_group_user_removal_ca_modification.yml` | 0.35 | member, group |
| `5013811` | [WINDOWS-SECURITY] wmic process call create ntdsutil | Process Creation Attempt via Wmic.EXE | `rules/windows/process_creation/proc_creation_win_wmic_process_creation.yml` | 0.35 | wmic, call, create |
| `5017332` | [DYNAMIC] Azure Eventhub Windows Applocker Logs Detecte | AppLocker Prevented Application or Script from Running | `rules/windows/builtin/applocker/win_applocker_application_was_prevented_from_running.yml` | 0.35 | applocker |
| `5006640` | [SentinelOne] Kill performed successful (Process Termin | Potential SentinelOne Shell Context Menu Scan Command T | `rules/windows/registry/registry_set/registry_set_sentinelone_shell_context_tampering.yml` | 0.35 | sentinelone |
| `5008371` | [WINDOWS-CLIPBOARD] rundll32 command | Potential Obfuscated Ordinal Call Via Rundll32 | `rules/windows/process_creation/proc_creation_win_rundll32_obfuscated_ordinal_call.yml` | 0.35 | rundll32, rundll32.exe |
| `5013836` | [WINDOWS-SYSMON] PS1 set in Registry Key | Windows Binaries Write Suspicious Extensions | `rules/windows/file/file_event/file_event_win_shell_write_susp_files_extensions.yml` | 0.35 | ps1 |
| `5014583` | [WINDOWS-SYSMON] GitHub Cloning Of BloodHoundAD Detecte | Suspicious Git Clone - Linux | `rules/linux/process_creation/proc_creation_lnx_susp_git_clone.yml` | 0.35 | clone, git |
| `5010590` | [CISCO-SCA] Potential Data Exfiltration | Potential Browser Data Stealing | `rules/windows/process_creation/proc_creation_win_susp_copy_browser_data.yml` | 0.35 | data |
