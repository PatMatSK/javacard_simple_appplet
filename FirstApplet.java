/** 
 * Copyright (c) 1998, 2021, Oracle and/or its affiliates. All rights reserved.
 * 
 */


package hwb1;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 * Applet class
 * 
 * @author matulpat
 */
public class FirstApplet extends Applet {

	AESKey enc_key, mac_key;
	static final byte enc_key_data [] = {
			0x00, 0x01, 0x02, 0x03,
			0x00, 0x01, 0x02, 0x03,
			0x00, 0x01, 0x02, 0x03,
			0x00, 0x01, 0x02, 0x03,
	};
	
	static final byte mac_key_data [] = {
			0x00, 0x01, 0x02, 0x03,
			0x00, 0x01, 0x02, 0x03,
			0x00, 0x01, 0x02, 0x03,
			0x00, 0x01, 0x02, 0x03,
	};
	
	Cipher enc;
	Signature mac;
	
	static final byte my_name [] = {'F', 'E', 'N', 'O', 'M', 'E', 'N'};
	byte outBuf [];
	byte user_data[];
	short user_len = 0;
	OwnerPIN pin;
	
    /**
     * Installs this applet.
     * 
     * @param bArray
     *            the array containing installation parameters
     * @param bOffset
     *            the starting offset in bArray
     * @param bLength
     *            the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new FirstApplet(bArray, bOffset, bLength);
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected FirstApplet(byte[] bArray, short bOffset, byte bLength) {
    	
    	user_data = new byte[20];
    	pin = new OwnerPIN((byte)3, (byte)4);

    	byte iLen = bArray[bOffset]; // aid length
        bOffset = (short) (bOffset + iLen + 1);
        byte cLen = bArray[bOffset]; // info length
        bOffset = (short) (bOffset + cLen + 1);
        byte aLen = bArray[bOffset]; // applet data length
     
		pin.update(bArray, (short)(bOffset+1), aLen);
		//pin.update(bArray, (byte)17, (byte)4);

   		enc_key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
    	enc_key.setKey(enc_key_data, (short)0 );
        enc = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        
        mac_key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128 , false);
        mac_key.setKey(mac_key_data, (short) 0);
        mac = Signature.getInstance(Signature.ALG_AES_MAC_128_NOPAD , false);
    	
    	
    	register();
    }
    
    private void select(APDU apdu) {
    	
    	if ( pin.getTriesRemaining() < 1 )
			ISOException.throwIt(ISO7816.SW_APPLET_SELECT_FAILED );
    	
    	if ( selectingApplet() )
    		ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }
	
    /**
     * Processes an incoming APDU.
     * 
     * @see APDU
     * @param apdu
     *            the incoming APDU
     */
    public void process(APDU apdu) {
    	
    	select(apdu);
    	
    	byte buf [] = apdu.getBuffer();
    	short len;
    	
        if ( (byte)buf[ISO7816.OFFSET_CLA] != (byte)0x80 )
        	ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED );
        else
        {
	        switch (buf[ISO7816.OFFSET_INS])
	        {
	     // ---------------------------------------------------------------------------------------------------
	     // --------------------------------SEND NAME----------------------------------------------------------
	        	case 0x00:
	        		len = apdu.setOutgoing();
	        		if (len > (short)my_name.length) 
	        			len = (short)my_name.length;
	        		apdu.setOutgoingLength(len);
	        		apdu.sendBytesLong(my_name, (short)0, len);
	        		break;
        // ---------------------------------------------------------------------------------------------------
	    // --------------------------------RECEIVE DATA-------------------------------------------------------
	        	case 0x02:
	        		if ( !pin.isValidated() )
	        			ISOException.throwIt((short)0x6301);

	        		len = apdu.setIncomingAndReceive();

	        		if (len > 20) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	        		user_len = len;
	        		Util.arrayCopyNonAtomic(buf, ISO7816.OFFSET_CDATA , user_data, (short)0, len);
	        		break;
	   // ---------------------------------------------------------------------------------------------------
	   // -----------------------------------SEND DATA-------------------------------------------------------
	        	case 0x04:
	        		if ( !pin.isValidated() )
	        			ISOException.throwIt((short)0x6301);

	        		len = apdu.setOutgoing();
	        		if ( len != user_len )
	        			ISOException.throwIt( (short) (ISO7816.SW_CORRECT_LENGTH_00 + user_len) );
	        		apdu.setOutgoingLength(len);
	        		apdu.sendBytesLong(user_data, (short)0, len);
	        		break;
        // ---------------------------------------------------------------------------------------------------
	    // ----------------------------------VERIFY PIN-------------------------------------------------------
	        	case 0x20: //verify pin
	        		len = apdu.setIncomingAndReceive();
	        		if ( pin.check(buf, ISO7816.OFFSET_CDATA, (byte)len ) == false )
	        			ISOException.throwIt( (short)0x6300 );
	        		
	        		break;
        // ---------------------------------------------------------------------------------------------------
	    // ---------------------------------ENCRYPT-DATA------------------------------------------------------
	        	case 0x42:
	        		if ( !pin.isValidated() )
	        			ISOException.throwIt((short)0x6301);
	        		
	        		len = apdu.setIncomingAndReceive();
	        		
	        		if ( len > 64 || len < 16 || len % 16 != 0 )
	        		    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	        		
	        		enc.init(enc_key, Cipher.MODE_ENCRYPT);
	        		try {
	        			enc.doFinal(buf, ISO7816.OFFSET_CDATA, len, buf, (short)0);
	        		}catch(CryptoException e){
	        			ISOException.throwIt( e.getReason() );
	        		}
	        		
	        		mac.init(mac_key, Signature.MODE_SIGN );
	        		try {
		        	    mac.sign(buf, (short)0, len, buf, len);
	        		}catch( CryptoException e){
	        			ISOException.throwIt( e.getReason() );
	        		}
	        		
	        		apdu.setOutgoing();
	        		apdu.setOutgoingLength((short)(len+16));
	        		apdu.sendBytesLong(buf, (short)0, (short)(len+16));
	        		break;
	    // ---------------------------------------------------------------------------------------------------
	    // ------------------------------DECRYPT-DATA---------------------------------------------------------
	        	case 0x44:
	        		if ( !pin.isValidated() )
	        			ISOException.throwIt((short)0x6301);

	        		len = apdu.setIncomingAndReceive();
                    
	        		if ( len > 80 || len <= 16 || len % 16 != 0 )
	        		    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	        		len -= 16;
	        		
	        		mac.init(mac_key, Signature.MODE_VERIFY);
	        		try {
		        	    if ( mac.verify(buf, ISO7816.OFFSET_CDATA, len, buf, (short)(ISO7816.OFFSET_CDATA+len), (short)16 ) == false )
		        	    	ISOException.throwIt( ISO7816.SW_WRONG_DATA );
	        		}catch( CryptoException e){
	        			ISOException.throwIt( e.getReason() );
	        		}
	        		
	        		enc.init(enc_key, Cipher.MODE_DECRYPT);
                    try {
           	            enc.doFinal(buf, ISO7816.OFFSET_CDATA, len, buf, (short)0);
                    } catch ( CryptoException e ) {
                    	ISOException.throwIt( e.getReason() );
                    }
                    
                    apdu.setOutgoing();
                    apdu.setOutgoingLength(len);
	        		apdu.sendBytesLong(buf, (short)0, len);
	        		break;
        // ---------------------------------------------------------------------------------------------------
	    // ------------------------------DEFAULT--------------------------------------------------------------
	        	default:
	        		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
	        		break;
	        }
        }
    }
}







