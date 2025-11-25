# AD-Tools
PowerShell scripts to help with enumerating and abusing common misconfigurations. Inspired by HTB CAPE Path

## Enumerate Foreign-ACLs
```
1. Requires PowerView
2. Provides syntax for next steps
```
<img width="1362" height="210" alt="image" src="https://github.com/user-attachments/assets/b0cd0503-73a4-4eef-af4d-241fbc3a733f" />

## Child to Parent Domain Elevation

```
1. Assumes mimikatz and powerview loaded into memory
2. Bi-directional trust
```
<img width="785" height="386" alt="image" src="https://github.com/user-attachments/assets/2a869042-227a-411f-a503-67c8ea6af345" />


## Enumerate Foreign Security Principals

```
1. PowerView
```
<img width="955" height="216" alt="image" src="https://github.com/user-attachments/assets/aca0b7ed-fe17-4f4d-be49-c7d0840d70b3" />


## Enable SID and SAN (ESC7 > ESC16 > ESC6)

```
1. Enables SAN override (ESC7)
2. Disables SID security extension (ESC16)
3. Prepares the CA for SAN-based impersonation (ESC6)
4. Performs CA-level configuration abuse via ADCS COM
5. Request cert with certipy
```
`certipy req -u user@tgest.local -p 'password' -ca test-DC1-CA -template User -upn administrator@test.local -sid admin_sid -dc-ip 10.0.0.0`

```
