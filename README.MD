This is simple Javacard Applet with this instructions:
- get name ( hardcoded in code)
- set data ( send data to apdu maxlen = 20B )
- get data ( get data from card, must require exact size ) 
- encrypt  ( encrypt with AES128 mode CBC with no padding, only aligned data required, also sign with mac, max data size = 64B )
- decrypt  ( verify mac, then decrypt data with AES128 CBC )

MAC ( size = 16B ) is appended at the end of ciphered data

.script files are test scripts for Eclipse enviroment.
text.txt if for physical card tested with GPshell.

