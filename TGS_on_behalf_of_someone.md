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

1. User authentication:
    The user enters his login and password.
    The Kerberos authentication server verifies that the password is correct.
    If authentication is successful, the server generates a TGT.
2. TGT Issuance:
    The TGT contains information about the user, the time of their authentication, and other metadata.
    The TGT also contains a session key that will be used for further communication.
3. Using TGT to get other tickets:
    A user can use TGT to request tickets to access various resources on the network.
Each ticket contains information about a specific resource and is protected by a session key, which ensures the security of the transfer.


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

TargetName — here specify the SPN of the service to which you want to get a ticket;

CacheOptions - Options related to the LSA cache. The LSA cache is a kind of storage in which tickets are stored. There are some peculiarities here too. If we immediately specify the KERB_RETRIEVE_TICKET_AS_KERB_CRED (the value for obtaining a ticket in the form KRB_CRED, immediately with the session key), then there is a chance that you will not get a ticket. The problem is that the LSA cache may not have a ticket for the service we want to go to. And if we immediately indicate KERB_RETRIEVE_TICKET_AS_KERB_CRED, then the LSA may simply not return any ticket, since there is nothing to return. Therefore, you will have to call the LsaCallAuthenticationPackage() function twice. The first time is with the meaning of KERB_RETRIEVE_TICKET_DEFAULT, the second time is with KERB_RETRIEVE_TICKET_AS_KERB_CRED. … DEFAULT is responsible for requesting a ticket. That is, we ask the LSA to contact the KDC and get a ticket;

EncryptionType - The desired type of encryption for the requested ticket. Specify KERB_ETYPE_DEFAULT — the type of encryption is not important to us;

CredentialsHandle - Used for SSPI, it doesn't matter in this case.


### Stealing a TGT ticket

We've figured out how Kerberos ticket request works on a local system. It's time to move on to operation!
First we list all the available sessions with undetected method "KLIST SESSIONS" --- ;-)

![immagine](https://github.com/user-attachments/assets/f6cb4c98-8db8-4c64-9de0-0e8c22f16b63)


The next step is to connect to the LSA using LsaRegisterLogonProcess()to pass the LUID to someone else's session. To call this function, you need the SeTcbPrivilege.

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

The next step is to use LsaLookupAuthenticationPackage() get the Kerberos AP number.

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

Finally, we have the handle, the LUID, and the Kerberos AP number. It's time for GIUDA to betray

To do this I used the function kuhl_m_kerberos_ask(target:string;export_:bool=false;logonid:int64=0):NTSTATUS;

This function uses LsaCallAuthenticationPackage to call the LSA, and LSA will now contact the KDC and receive a new ticket. If we try to extract it right away, it will not be valid. More precisely, it will not have a session key and you will not be able to use it.

Therefore, after making sure that the call was successful, change CacheOptions to KERB_RETRIEVE_TICKET_AS_KERB_CRED and refer to the LSA.

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

It would seem that getting a TGS ticket is a great result! But you always want more, right? Did you know that a TGT ticket is actually a TGS ticket, but for the krbtgt service? It turns out that we have a TGS ticket for krbtgt, and the krbtgt service allows us to issue other TGS tickets. That's all.
![immagine](https://github.com/user-attachments/assets/ccf117d0-6409-4de6-b3d3-d9bdbaabb024)


Hei Gringo your car is vavavumaaaaaaa

![immagine](https://github.com/user-attachments/assets/c33bce71-23b4-4211-9d62-d4cc1ad38747)


We can request other people's TGT tickets! Great GIUDA, it's time to continue to betray
