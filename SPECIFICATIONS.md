# Multi-user remote password manager

## 1. General idea

- Client store encrypted file in the server
  - File contains the list of user's password
  - File is encrypted using a key only known by the client (derived from the user's password) (**CIA**)
  - Each user has only one encrypted file on the server, identified by its hashed username
- Client **authenticate** itself to the server using his password
  - Server authenticate itself to the client with its certificate
- Server know which user own which encrypted files on the server but cannot decrypt them
  - Setup **access control** on files:
    - role user : read/write on owned files
    - role admin : add and delete users
- All activities on the server are **logged**
- Transmission between client and server are made on HTTPS

## 2. Interactions between client and server

Before accessing the password file, the client has to authenticate itself to the server. If validated, he receive a session token that he can use to download and upload the encrypted file.

### 2.1. Authentication

```sequence
participant client
participant server
note over client: Ask username and password to user
note over client: Hash password ?
note over client: Derive encryption key from password
client->server : Send username and password
note over server: Authenticate user with password
note over server: If user is valid, generate session token
server->client: Return session token
```



### 2.2. Download file

```sequence
participant client
participant server
note over client,server: Authentication
client->server: Request file download, send session token
note over server: Check if token is valid (authentication)
note over server: Check if user has permission over requested file
server->client: Send encrypted file
```

### 2.3. Upload modified file

```sequence
participant client
participant server
note over client,server: Authentication
note over client: Encrypt modified file
client->server: Send encrypted file and session token
note over server: Check if session token is valid
note over server: Check if user has permission to modify file
note over server: If yes, override stored file with new encrypted file
server->client: Confirm

```

## 3. Interaction between user and client

Once the client is authenticated and has downloaded user's file, user can :

- Read password
- Add new password
- Modify password
- Delete password

For each option, the encrypted file is decrypted, read/modified, and re-encrypted directly to avoid full decrypted file leak from memory.

For the last 3 options, the client update the passwords' file, encrypt it and send it to the server. The server override the old file with the new encrypted file.

If user has role admin, he can also :

- Add user
- Delete user



### 3.1. Read password

```sequence
participant user
participant client
note over client: Authenticated with the server and file downloaded
user->client: User want to read a password
note over client: Decrypt file, get all password's label and username
client->user: List of label and username
note over user: Select the password he want
user->client: Send choice
note over client: Decrypt file, get password's infos
client->user: Password's infos
```

### 3.2. Add new password

```sequence
participant user
participant client
note over client: Authenticated with the server and file downloaded
user->client: Input password, username and label
note over client: Decrypt file, add new password
note over client: Encrypt file and upload it to server
client->user: Confirm
```

### 3.3. Modify password

```sequence
participant user
participant client
note over client: Authenticated with the server and file downloaded
note over user,client: Same procedure as "Read password"
user->client: Input new password, username and label
note over client: Decrypt file, modify password
note over client: Encrypt file and upload it to server
client->user: Confirm
```

### 3.4. Delete password

```sequence
participant user
participant client
note over client: Authenticated with the server and file downloaded
user->client: User want to read a password
note over client: Decrypt file, get all password's label and username
client->user: List of label and username
note over user: Select the password he want to delete
user->client: Send choice
note over client: Decrypt file, delete password password
note over client: Encrypt file and upload it to server
client->user: Confirm
```

