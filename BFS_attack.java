package securityhomework;

import java.util.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.Buffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

//import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class BFS_attack
{
public static void main(String[] args)
throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException
{
	System.out.println("pls input plaintext:");
	BufferedReader buf = new BufferedReader(new InputStreamReader(System.in));
	String plaintext = buf.readLine();
	System.out.println("pls input ciphertext:");
	buf = new BufferedReader(new InputStreamReader(System.in));
	String ciphertext = buf.readLine();	
	System.out.println("pls enter length of password:");
	Scanner input = new Scanner(System.in);
	int length = input.nextInt();
	System.out.println("pls enter iteration count:");
	int count = input.nextInt();
	// Salt 
    byte[] salt = { (byte)0xc7, (byte)0x73, (byte)0x21, 
               (byte)0x8c, (byte)0x7e, (byte)0xc8, (byte)0xee, (byte)0x99 };
    //time
    long starttime=System.currentTimeMillis();
    Findpassword(plaintext,ciphertext,salt,count,length);
    long endtime=System.currentTimeMillis();
    System.out.println("time used:" + (endtime-starttime) + "ms");
}
static void Findpassword(String plaintext, String ciphertext, byte[] salt, int count, int length)
		throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException
		{
	PBEKeySpec pbeKeySpec; 
    PBEParameterSpec pbeParamSpec; 
    SecretKeyFactory keyFac;
    String password = "";
    boolean match = false;
    keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
	Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");

 // Create PBE parameter set 
    pbeParamSpec = new PBEParameterSpec(salt, count);
    int len = 0;
    for(;len<Math.pow(10, length);len++){
		password = Integer.toString(len);
		int Plength = password.length();

    //start form 0000...
    if(Plength<= length){
    	for(int i = Plength; i<length; i++){
    		password="0"+password;
    	}
    }
    //Create parameter for key generation 
    char[] pass = password.toCharArray();
    pbeKeySpec = new PBEKeySpec(pass); 

//Create instance of SecretKeyFactory for password-based encryption 
//using DES and MD5    
    keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES"); 

//Generate a key 
Key pbeKey = keyFac.generateSecret(pbeKeySpec); 

//Create PBE Cipher 
//Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");

// Initialize PBE Cipher with key and parameters 
  pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);
  byte[]  cleartext = plaintext.getBytes(); 

//Re-encrypt the plaintext 

byte[]  reciphertext = pbeCipher.doFinal(cleartext); 
System.out.println("password : " + password);
String newciphertext = Utils.toHex(reciphertext);
// match,use BFS
char[] cipher1 = newciphertext.toCharArray();
char[] cipher2 = ciphertext.toCharArray();

for(int i =0, j=0; i<= ciphertext.length();i++){
		if(j> cipher2.length-1){
			break;
		}
		if(cipher1[i] == cipher2[j])
		{
			i++;
			j++;
			if(i==j && i== cipher1.length-1 && j== cipher2.length-1){
				match=true;
				break;
			}
			else
				break;
		}
	if(match == true){
		System.out.println("password: "+password);
		break;
	}
	else if(match== false&&len == Math.pow(10, length)-1)
		{
		System.out.println("password finding failed.");
		//break;
		}
	}
/*if(newciphertext1.equals(ciphertext)){
	match = true;
}
else{
	match = false;
}
if(match = true){
	System.out.println("password is:"+ password);
}
else{
	System.out.println("fail");
}*/
	}
}
}