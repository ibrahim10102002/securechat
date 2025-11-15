# Manual evidence checklist
# Quick Start

# Prerequisites
1. Python 3.8+ installed
2. PostgreSQL running locally (for database)
3. Required packages installed

# Setup (One-time)

# Set Python path (needed for app imports)
$env:PYTHONPATH = "."

# Install dependencies
python -m pip install -r requirements.txt


#Interactive Client (Full Testing - Your choice of inputs)

Allows you to manually register/login and send messages.

### Step 1: Start the Server (Terminal 1)

$env:PYTHONPATH = "."; python app/server.py

**Server Output:**
```
[SERVER] Starting SecureChat server...
=> Connected to PostgreSQL successfully!
[SERVER] Listening on 0.0.0.0:5000
```

Server is now waiting for client connections.

### Step 2: Run the Client (Terminal 2)

$env:PYTHONPATH = "."; python app/client.py

### Step 3: Follow the Prompts

**First Prompt: Register or Login?**
Do you want to (r)egister or (l)ogin? [r/l]: r
- Type `r` to register a new user
- Type `l` to login with existing credentials

**Username Prompt:**
username: alice
- Enter any username you want

**Password Prompt:**
password: 
- Enter a password (input hidden)
- For testing, you can use: `mypassword123`

### Step 4: Send Messages

After successful login/registration:
You: Hello, this is a secure message!

Type any message you want to send. The message will be:
1. Encrypted with AES-128-CBC
2. Signed with RSA-PSS
3. Sent to server

**Server acknowledges:**
```
[SERVER] Received msg seq=1 from client: Hello, this is a secure message!
[SERVER] receipt sent to client

**Client receives:**
[CLIENT] Receipt: {'msg_id': '...', 'status': 'delivered'}

### Step 5: Exit

Type `quit` or `exit` to disconnect:
```
You: quit
[CLIENT] Disconnected.

## Option 3: Manual Protocol Testing

Test individual components:

### Test 1: DH Key Exchange

$env:PYTHONPATH = "."; python app/crypto/dh.py

**Expected Output:**
Shared secret length: 256
Derived AES key (hex): 2568438195a91efbdc0d26fe7d921666
DH round-trip and AES key derivation OK
### Test 2: AES Encryption

$env:PYTHONPATH = "."; python app/crypto/aes.py

**Expected Output:**

AES round-trip OK

### Test 3: RSA Signing

$env:PYTHONPATH = "."; python app/crypto/sign.py

**Expected Output:**

SIG b64: <base64-encoded-signature>
Verified: True


## Testing Scenarios

### Scenario 1: New User Registration

```
Server: [SERVER] Listening on 0.0.0.0:5000
Client: python app/client.py
Prompt: (r)egister or (l)ogin? → r
Prompt: username: → newuser
Prompt: password: → mypass123
Server: [SERVER] Registered user newuser
Client: Can now send messages
```

### Scenario 2: Returning User Login

```
Server: [SERVER] Listening on 0.0.0.0:5000
Client: python app/client.py
Prompt: (r)egister or (l)ogin? → l
Prompt: username: → alice
Prompt: password: → mypassword123
Server: [SERVER] Login attempt user=alice ok=True
Client: Can now send messages
```

### Scenario 3: Multiple Messages

After login, send multiple messages:

```
You: First message
[CLIENT] Receipt: delivered
You: Second message with special chars: !@#$%
[CLIENT] Receipt: delivered
You: Third message
[CLIENT] Receipt: delivered
You: quit


## Troubleshooting

### Error: "ModuleNotFoundError: No module named 'app'"

**Fix:** Set PYTHONPATH before running:
```powershell
$env:PYTHONPATH = "."
python app/server.py
```

### Error: "Address already in use (port 5000)"

**Fix:** Kill existing Python processes:
```powershell
Get-Process python -ErrorAction SilentlyContinue | Stop-Process -Force
```

Then restart server.

### Error: "Connection refused"

**Fix:** Make sure server is running in another terminal before starting client.

### Error: "Certificate validation failed"

**Fix:** Ensure cert files exist:
ls certs/ca_cert.pem
ls certs/server/server_cert.pem
ls certs/client/client_cert.pem

### Error: "duplicate key value violates unique constraint"

**Fix:** User already registered. Try logging in or use a different username.


## What Gets Tested

### Protocol Flow
Client certificate verification
Ephemeral DH key exchange (registration)
Session DH key exchange (messaging)
Message encryption/decryption
Digital signatures (RSA-PSS)
Replay protection (sequence numbers)

### Security Features
AES-128-CBC encryption
RSA-PSS signature verification
Certificate chain validation
Salted password hashing (SHA-256)
Secure DH parameter sharing

### Database Operations
User registration with salted hashing
User authentication
Session management
Transcript logging

### Github Link

https://github.com/ibrahim10102002/securechat.git