#!/bin/bash
# Gadyen Safeguard - macOS computer self-check (READ-ONLY).
# Changes nothing, reads no client files. Writes gadyen-report.json in the current folder.
#   bash check-macos.sh

tf() { if [ "$1" = "true" ]; then echo true; elif [ "$1" = "false" ]; then echo false; else echo null; fi; }

disk=$(fdesetup status 2>/dev/null | grep -q "FileVault is On" && echo true || echo false)
fw_state=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
case "$fw_state" in *enabled*) fw=true ;; *disabled*) fw=false ;; *) fw=null ;; esac
# XProtect (built-in malware protection) is always present on supported macOS versions.
av=$( [ -d /Library/Apple/System/Library/CoreServices/XProtect.bundle ] && echo true || echo null )
au_raw=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null)
case "$au_raw" in 1) au=true ;; 0) au=false ;; *) au=null ;; esac
lock=null
idle=$(defaults -currentHost read com.apple.screensaver idleTime 2>/dev/null)
if [ -n "$idle" ] && [ "$idle" -gt 0 ] 2>/dev/null; then lock=$((idle / 60)); fi

cat > gadyen-report.json <<JSON
{
  "schema_version": 1,
  "hostname": "$(scutil --get ComputerName 2>/dev/null | tr -cd '[:alnum:]-_ ' | cut -c1-100)",
  "os": "macOS",
  "os_version": "$(sw_vers -productVersion)",
  "disk_encrypted": $(tf $disk),
  "firewall_enabled": $fw,
  "antivirus_enabled": $av,
  "auto_updates_enabled": $au,
  "screen_lock_minutes": $lock,
  "collected_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
echo "Report written to $(pwd)/gadyen-report.json - upload it in Gadyen Safeguard."
