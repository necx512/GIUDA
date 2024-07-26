### Before to start
```
"Hello... Iscariota's house?"
"Yes...!"
"Is GIUDA there?"
"No, he went to a dinner...!"
"Again?"
"Yes, but he says it's the last one."
"Sure?!?!?"
```

### Reasons for Using Pascal to Create Malware Instead of C# and C++

1. **Evasion of Security Tools**
   - **Detection and Analysis**: Many security tools and antivirus programs are more focused on modern and widely-used languages like C# and C++. Code written in Pascal might be less detected or less studied, making the malware harder to identify.
   - **Obfuscation**: Less common languages like Pascal can be used to obfuscate the code and reduce the likelihood of detection. Analysts might be less familiar with Pascal, making code analysis more challenging.

2. **Development Environment**
   - **Legacy Systems**: In some cases, malware may be designed to target older systems or specific development environments that use Pascal, such as legacy systems or outdated software that doesn’t support C#.

3. **Compatibility and Control**
   - **Access to System Resources**: Pascal, particularly in its variants like Delphi, can offer good control over system resources and interactions with the operating system, which can be exploited for malicious activities.

4. **Simplicity and Flexibility**
   - **Ease of Use**: Some developers might find Pascal easier or more suitable for certain operations. The language’s syntax and structure could be preferred for specific types of attacks or development techniques.

5. **Programming Style**
   - **Personal Preference**: Some malware creators may simply prefer Pascal or have more experience with it compared to C#. The choice of language can reflect their personal experience and skill set.



### Request a TGS (or better a TGT!) on behalf of another logged user:
1. What is (for the umpteenth time) a TGT
2. What's a Logon session
3. How the LSA requests Kerberos tickets
4. Stealing a TGT ticket
5. Then? If you make the right request then a TGS is the same as a TGT

There are several methods to compromise a user's session on a device. Surprisingly, one of these involves spoofing a TGT ticket receipt using legitimate Windows functions

GIUDA allows you to get the tickets of the logged-in user even without having his password! Today we will understand how GIUDA works

### What is (for the umpteenth time) a TGT

A Ticket Granting Ticket (TGT) is a unique type of ticket issued to a user upon successful authentication in the Kerberos system. Generated using the user's password, the TGT ensures that the password is never transmitted over the network, enhancing security..

Here's how TGT works.
1. **User Authentication:**
    - The user enters their login and password.
    - The Kerberos authentication server verifies the password.
    - Upon successful authentication, the server issues a Ticket Granting Ticket (TGT).

2. **TGT Issuance:**
    - The TGT contains information about the user, the time of authentication, and other metadata.
    - It also includes a session key used for further communication.

3. **Using the TGT to Obtain Other Tickets:**
    - The user can present the TGT to request additional tickets for accessing various network resources.
    - Each ticket is specific to a resource and is protected by a session key, ensuring secure communication.
      

### What's a Logon session

When a user logs into Windows, a user session is created where all user data is stored. Each new user on the Windows machine initiates a new session.

Each session is assigned a Locally Unique Identifier (LUID). As the name suggests, the LUID is unique to each session. This information is stored in a structured format.

Pascal
```
type
    _LUID = record
    LowPart: DWORD;
    HighPart: LongInt;
  end;
```

C
```
typedef struct _LUID {
ULONG LowPart;
LONG HighPart;
} LUID, *PLUID;
```

The LUID is represented by two values: DWORD (ULONG) and Longint (LONG). Typically, only the LowPart field is filled, while the HighPart remains relevant but less commonly used.

This structure is used by all WinAPI functions that are somehow related to user sessions.

You can use the GetTokenInformation() function to retrieve the custom LUID.

Now it's time to demonstrate how Kerberos tickets are requested by the LSA. This process will help us spoof the LUID and obtain someone else's ticket.

### How the LSA requests Kerberos tickets

To request a TGS ticket, the LSA receives a Service Principal Name (SPN) and passes it to the KDC. We can request TGS tickets ourselves using the LsaCallAuthenticationPackage() function.

Pascal
```
function LsaCallAuthenticationPackage (
    LsaHandle : THandle;
    AuthenticationPackage : ULONG;
    ProtocolSubmitBuffer : pointer;
    SubmitBufferLength : ULONG;
    var ProtocolReturnBuffer : pointer;
    var ReturnBufferLength : ULONG;
    var ProtocolStatus : NTStatus) : NTSTATUS; stdcall;
```

C
```
NTSTATUS LsaCallAuthenticationPackage(
  [in]  HANDLE  LsaHandle,
  [in]  ULONG   AuthenticationPackage,
  [in]  PVOID   ProtocolSubmitBuffer,
  [in]  ULONG   SubmitBufferLength,
  [out] PVOID   *ProtocolReturnBuffer,
  [out] PULONG  ReturnBufferLength,
  [out] PNTSTATUS ProtocolStatus
);
```

where:

LsaHandle - A handle pointing to the LSA service can be retrieved using either LsaRegisterLogonProcess() or LsaConnectUntrusted();

AuthenticationPackage - The AP number that you want to interact with.

ProtocolSubmitBuffer — the buffer being passed, we will give KERB_RETRIEVE_TKT_REQUEST;

SubmitBufferLength is the size of the buffer to be transferred;

ProtocolReturnBuffer is the response from AuthenticationPackage. The structure of the KERB_RETRIEVE_TKT_RESPONSE will fly to us;

ReturnBufferLength — the size of the buffer with the response;

ProtocolStatus is a value that will contain the error code from the AP.

So, how do you fill out the KERB_RETRIEVE_TKT_REQUEST structure to obtain a TGS ticket? The structure looks like this:

Pascal
```
KERB_RETRIEVE_TKT_REQUEST =record
    MessageType:KERB_PROTOCOL_MESSAGE_TYPE;
    LogonId:_LUID;
    TargetName:UNICODE_STRING;
    TicketFlags:ULONG;
    CacheOptions:ULONG;
    EncryptionType:LONG;
    CredentialsHandle:SecHandle;
    end;
    PKERB_RETRIEVE_TKT_REQUEST=^KERB_RETRIEVE_TKT_REQUEST;
```

C
```
typedef struct _KERB_RETRIEVE_TKT_REQUEST {
  KERB_PROTOCOL_MESSAGE_TYPE MessageType;
  LUID             LogonId;
  UNICODE_STRING       TargetName;
  ULONG            TicketFlags;
  ULONG            CacheOptions;
  LONG             EncryptionType;
  SecHandle          CredentialsHandle;
} KERB_RETRIEVE_TKT_REQUEST, *PKERB_RETRIEVE_TKT_REQUEST;
```

where:

MessageType: To obtain a TGS ticket, set the MessageType field to KerbRetrieveEncodedTicketMessage;

LogonID: Set the LogonID to the LUID of the session on whose behalf the AP is accessed. This is where the LUID will be substituted. However, if you connect to the LSA using LsaConnectUntrusted(), you won't be able to specify the LUID of another session, as this will result in a 0x5 ERROR_ACCESS_DENIED error. On the other hand, if you connect via LsaRegisterLogonProcess(), you can provide any LUID you choose, allowing you to request tickets from another user's session.;

TargetName: Set TargetName to specify the SPN (Service Principal Name) of the service for which you want to obtain a ticket;

CacheOptions: CacheOptions controls how the LSA cache is used. The LSA cache stores tickets, but it has some nuances. If you specify KERB_RETRIEVE_TICKET_AS_KERB_CRED (which requests the ticket in the form of KRB_CRED along with the session key) right away, there’s a risk that you might not receive a ticket. This is because the LSA cache might not have the ticket for the desired service. If the cache lacks the ticket and you request it as KRB_CRED, the LSA may return nothing, since there is no ticket to return. To address this, you should call LsaCallAuthenticationPackage() twice: first with KERB_RETRIEVE_TICKET_DEFAULT to request the ticket, allowing the LSA to contact the KDC and obtain it, and then with KERB_RETRIEVE_TICKET_AS_KERB_CRED to get the ticket in the desired format, including the session key;

EncryptionType: Set EncryptionType to specify the desired encryption type for the requested ticket. Use KERB_ETYPE_DEFAULT if the specific encryption type is not important.

CredentialsHandle, which is used for SSPI, it is not relevant in this context.


### Stealing a TGT ticket

Now that we understand how Kerberos ticket requests work on a local system, let's move on to the operations.

First, list all available sessions using the undetected method: KLIST SESSIONS. --- ;-)

![immagine](https://github.com/user-attachments/assets/f6cb4c98-8db8-4c64-9de0-0e8c22f16b63)


The next step is to connect to the LSA using LsaRegisterLogonProcess() in order to use the LUID from another session. To call this function, you will need the SeTcbPrivilege.

Pascal
```
LsaRegisterLogonProcess:function(
     LogonProcessName:PLSA_STRING;
     LsaHandle:PHANDLE;
     SecurityMode:PLSA_OPERATIONAL_MODE
  ):NTSTATUS;stdcall;
```

C
```
NTSTATUS LsaRegisterLogonProcess(
  [in]  PLSA_STRING           LogonProcessName,
  [out] PHANDLE               LsaHandle,
  [out] PLSA_OPERATIONAL_MODE SecurityMode
);
```

Next, use LsaLookupAuthenticationPackage() to retrieve the Kerberos AP number.

Pascal
```
  LsaLookupAuthenticationPackage:function(
       LsaHandle:HANDLE;
       PackageName:PLSA_STRING;
       AuthenticationPackage:PULONG
 ):NTSTATUS ;stdcall;
```

C
```
NTSTATUS LsaLookupAuthenticationPackage(
  [in]  HANDLE      LsaHandle,
  [in]  PLSA_STRING PackageName,
  [out] PULONG      AuthenticationPackage
);
```

With the handle, LUID, and Kerberos AP number in hand, it's time to proceed with the next step.

Use the function kuhl_m_kerberos_ask(target:string; export_:bool=false; logonid:int64=0):NTSTATUS;. This function calls LsaCallAuthenticationPackage to instruct the LSA to contact the KDC and obtain a new ticket. Initially, the ticket you receive will not be valid, as it will lack a session key and cannot be used.

After verifying that the call was successful, update CacheOptions to KERB_RETRIEVE_TICKET_AS_KERB_CRED and make another call to the LSA to retrieve a valid ticket.


Pascal
```
(first call to LsaCallAuthenticationPackage)
pKerbRetrieveRequest^.CacheOptions :=  KERB_RETRIEVE_TICKET_DEFAULT;
...
(if success change the CacheOptions)
pKerbRetrieveRequest^.CacheOptions:= pKerbRetrieveRequest^.CacheOptions or  KERB_RETRIEVE_TICKET_AS_KERB_CRED;
```

C
```
(first call to LsaCallAuthenticationPackage)
pKerbRetrieveRequest->CacheOptions = KERB_RETRIEVE_TICKET_DEFAULT;
...
(if success change the CacheOptions)
pKerbRetrieveRequest->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
```

Ticket got on behalf of other user without password, GIUDA betrayed!

![immagine](https://github.com/user-attachments/assets/b1dda5b8-ec6b-49f6-b7c0-425958bee7e2)



### Then? If you make the right request then a TGS is the same as a TGT

Obtaining a TGS ticket is certainly a significant achievement, but there's more to explore. Did you know that a TGT ticket is essentially a TGS ticket for the krbtgt service? In fact, with a TGS ticket for krbtgt, you can use it to request additional TGS tickets. And that's the key insight!

![immagine](https://github.com/user-attachments/assets/ccf117d0-6409-4de6-b3d3-d9bdbaabb024)


Hei Gringo your car is vavavumaaaaaaa (https://www.youtube.com/watch?v=MS5lh7BDFoc)

![immagine](https://github.com/user-attachments/assets/c33bce71-23b4-4211-9d62-d4cc1ad38747)


We can request other people's TGT tickets! Great GIUDA, it's time to continue to betray
