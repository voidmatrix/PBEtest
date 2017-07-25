package securityhomework;


/*在当前workspace新建一个class，然后把下面的粘贴上去， 
package不对就把他改成你的package名字，
package是左边栏src文件夹里面的那个田字格*/




import java.util.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
//import PBE.Utils;

import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;


import javax.crypto.spec.PBEParameterSpec;


public class FindPassword {
	public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException{
		//receive data; 


		
		System.out.println("Please input plaintext:");
		BufferedReader buffer = new BufferedReader(new InputStreamReader(System.in));
		String plaintext = buffer.readLine();

		System.out.println("Please input ciphertext:");
		buffer = new BufferedReader(new InputStreamReader(System.in));
		String ciphertext = buffer.readLine();
		
		System.out.println("Please input iteration court:");
		Scanner in = new Scanner(System.in);
		int count = in.nextInt();
		System.out.println("Please input password length:");
		in = new Scanner(System.in);
		int n = in.nextInt();


		
		
		//no idea how to impute salt;
		byte[] salt = { (byte)0xc7, (byte)0x73, (byte)0x21, 
                        (byte)0x8c, (byte)0x7e, (byte)0xc8, 
                        (byte)0xee, (byte)0x99 };
		 
		//System.out.println(plaintext + ciphertext + count);
		
		long startTime = System.currentTimeMillis();
		
		BFSPassword(plaintext, ciphertext, salt, count, n);
		
		long endTime = System.currentTimeMillis();
		System.out.println("running time is: " + (endTime - startTime) + "ms");
		
		
	}
	
	static void BFSPassword(String plaintext, String ciphertext, byte[] salt, int count, int n) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{

		
		PBEKeySpec pbeKeySpec; 
        PBEParameterSpec pbeParamSpec; 
        SecretKeyFactory keyFac; 
		String password = "";
		Boolean  state = false;
		keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
		Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
		
		pbeParamSpec = new PBEParameterSpec(salt, count); 
		int number = 0;

		for(;number<Math.pow(10, n);number++){
			password = Integer.toString(number);
			int Plength = password.length();
			
			//fill with zero
			
			if(Plength <= n){
				for(int i=Plength;i<n;i++){
					password = "0" + password;
				}
			}			 
		
			char[]  Cpassword = password.toCharArray();
			pbeKeySpec = new PBEKeySpec(Cpassword); 
			Key pbeKey = keyFac.generateSecret(pbeKeySpec); 
			pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);
			byte[]  cleartext = plaintext.getBytes();
			byte[]  Rciphertext = pbeCipher.doFinal(cleartext); 
			System.out.println(password);
			String Rciphertext1 = Utils.toHex(Rciphertext);
			System.out.println(Utils.toHex(Rciphertext));
			char[] ciphertext1 = Rciphertext1.toCharArray();
			char[] ciphertext2 = ciphertext.toCharArray();
			// BF search
			int i = 0;
			int j = 0;
			for(;i<ciphertext.length();){
				if(j >= ciphertext2.length-1)
					break;
				if(ciphertext1[i] == ciphertext2[j]){
					i++;
					j++;
					if(i == j && i== ciphertext1.length-1 && j== ciphertext2.length-1)
						{
						state = true;
						break;
						}
				}
				else
					break;
				

				
			}
			
			if(state == true){
				System.out.println("the password is " + password);
				break;
			}
			if(state == false&&number == Math.pow(10, n)-1){
				System.out.println("can not find the password.");
			}
		}
		
		
		
	}
	
}


