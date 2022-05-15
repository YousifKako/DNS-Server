# DNS Server
A DNS Server

# Build and Run
Run two terminals  
Terminal A: `cargo run`  
Terminal B: `dig @{LOCAL IP} -p {PORT} {WEBSITE}` example `dig @192.168.1.1 -p 8888 google.com`

# Check List
- [x] DNS Packet Parser
- [x] Query Types: A, NS, CNAME, MX, AAAA
- [x] Recursive Resolver