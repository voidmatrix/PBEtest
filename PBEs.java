package securityhomework;



import java.security.Key;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;



/**
 * Example of using Password-based encryption 
 */
 
public class PBEs
{
    public static void main(
        String[]    args)
        throws Exception
    {
           PBEKeySpec pbeKeySpec; 
           PBEParameterSpec pbeParamSpec; 
           SecretKeyFactory keyFac; 
                
// Salt 
           byte[] salt = { (byte)0xc7, (byte)0x73, (byte)0x21, 
                      (byte)0x8c, (byte)0x7e, (byte)0xc8, (byte)0xee, (byte)0x99 };
// Iteration count 
          int count = 2048; 

// Create PBE parameter set 
          pbeParamSpec = new PBEParameterSpec(salt, count); 

//Initialization of the password
          Scanner br = new Scanner(System.in);
          System.out.println("pls input ur password, 0~9 only:");
          String  typein = br.nextLine();
          char[] password = typein.toCharArray();

//Create parameter for key generation 
          pbeKeySpec = new PBEKeySpec(password); 

// Create instance of SecretKeyFactory for password-based encryption 
// using DES and MD5    
          keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES"); 

// Generate a key 
     Key pbeKey = keyFac.generateSecret(pbeKeySpec); 

// Create PBE Cipher 
  Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
 
 // Initialize PBE Cipher with key and parameters 
        pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);
 // Our plaintext 

byte[]  cleartext = "This is another example".getBytes(); 

// Encrypt the plaintext 

byte[]  ciphertext = pbeCipher.doFinal(cleartext); 
System.out.println("cipher : " + Utils.toHex(ciphertext));
  
//Decrypt
pbeCipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec);
System.out.println("pls input ur password:");
Scanner buf = new Scanner(System.in);
String check = buf.nextLine();  
if(check.equals(typein)){
byte[]  plaintext = pbeCipher.doFinal(ciphertext);
String stringplaintext = new String(plaintext);
System.out.println("decrypt: " + stringplaintext);
		}
else{
	System.out.println("ur password is incorrect, pls try again later.");
}	

    }
}