# FrankensteinAPCInjection
Novel Windows process injection: assembles existing open handles (process &amp; thread), natural RWX regions, and special user APC (NtQueueApcThreadEx2) for stealthy execution. Minimal permissions, no allocations/protection changes

## Why "Frankenstein"?
This technique is named "Frankenstein" because it "assembles" different existing parts from the system like a monster: pre-opened ("leaked") handles to processes and threads, natural RWX memory regions already present in the target, and forces execution with a special APC. No need to create suspicious new resources!

## Overview
Frankenstein APC Injection is a stealthy process injection method that runs shellcode in a remote process using only resources that already exist in the system:
- Scans for existing open handles with sufficient access (PROCESS_VM_WRITE/OPERATION and THREAD_SET_CONTEXT)
- Finds pre-existing RWX memory regions (no allocation or protection changes).
- Writes shellcode directly into RWX.
- Queues a special user APC via NtQueueApcThreadEx2 with QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC flag for immediate execution, even without alertable state.
- (Optional): Added a Speck shellcode encryption

This avoids many monitored APIs (VirtualAllocEx, VirtualProtectEx, CreateRemoteThread) and works with minimal privileges.

## Requirements
- Windows (tested on Windows 10/11)
- Shellcode compiled as x64 with non-null bytes (-b option in MSFVenom shellcode is x64 reverse shell)
- Run with standard user privileges (no SeDebugPrivilege needed for many targets)

![c49a3827-7090-43bb-b798-b2dd274c7103(1)](https://github.com/user-attachments/assets/8d7d78bf-4ee4-41b2-8b5b-a44c032f8095)
