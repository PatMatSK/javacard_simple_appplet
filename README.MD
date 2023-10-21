This is simple Javacard Applet with this instructions:
- get name ( hardcoded in code)
- set data ( send data to apdu maxlen = 20 )
- get data ( get data from card, must require exact size ) 
- encrypt  ( encrypt with AES mode CBC with no padding, only aligned data required, also sign with mac, max data size = 64B )
- decrypt  ( verify mac, then decrypt data )

MAC - ( size = 16 ) is appended at the end of ciphered data

