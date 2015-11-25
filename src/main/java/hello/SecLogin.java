package hello;

import java.io.BufferedWriter;
import java.io.CharArrayWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
//import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
//import java.nio.file.attribute.UserPrincipalNotFoundException;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;


public class SecLogin {
	
	/** Variable precision */
	private static final int VAR_PREC = 150;
	
	/** Threshold for feature values in calculating X and Y */
	private static final int THRESH = 150;
	
	/** Size of user history files */
	private static final int HIST_SIZE = 8 << 10; // 8KB
	
	/** Magic text */
	private static final String HIST_TEXT = "This is a history file.";
	
	/** History file size limit */
	private static final int HIST_LIMIT = 20;
	
	/** Static q */
	private static final BigInteger q =
			new BigInteger("957117109103230102421885836974304804951875593197");
	
	/** Static k */
	private static final double k = 0.5;
	
	/** Number of logins for sampling user keystroke dynamics */
	private static final int n = 10;
	
	/** Distinguishing feature count */
	//private static final int DIST_FEAT_CNT = 15;
	
	/** Error correcting parameter */
	private static final int max_errors = 2;
	
	/** Logger */
	private static final Logger log = Logger.getLogger(SecLogin.class.getName());
	
	/** Directory of history files */
	private static final String hist_dir = "hist1/";
	
	/** Directory of instruction files */
	private static final String ab_dir = "ab1/";
	
	/** Directory of log files */
	private static final String log_dir = "log1/";
	
	
	/**
	 * Parse input file and make a series of login attempts
	 * @param filename The name of the file from which features are read
	 * @throws Exception 
	 */
	public Greeting parseMain(String username,String password,
								 long fingerprint,int[] latency) throws Exception {
		// Create an 8-character password - if password length is < 8
			if(password.length()<8) {
				char[] pass_chars = new char[] {
						'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
				};
				for(int i = 0; i < Math.min(8, password.length()); ++i) {
					pass_chars[i] = password.charAt(i);
				}
				password = new String(pass_chars);
			}	
			
			System.out.println("password is " + password);
			
			LoginFeatures lf = new LoginFeatures(username,fingerprint,latency);
			Greeting result = loginAttempt(lf, password);
			if(result.getAttempt() == true) {
	    		log.info("Login success");
	    	} else {
	    		log.info("Login fail");
	    	}
				
			return result;
	}
	
	/**
	 * Perform Gr(x).
	 * @param password What we are encrypting with HmacSHA-1
	 * @param x Seed for the SHA-1 digest
	 * @return The completed calculation of Gr(x)
	 */
	private static BigInteger calculate_hash(String password, int x) {
		// HmacSHA1 for G(x) - Key is the password (user input) supplied in file 
		BigInteger Alpha1 = null;
		try {
			Mac mac = Mac.getInstance("HmacSHA1");
			SecretKeySpec secret=new SecretKeySpec(password.getBytes(),mac.getAlgorithm());
			mac.init(secret);
			String input =  "" + x;
			byte[] rawHmac = mac.doFinal(input.getBytes());
			Alpha1 = new BigInteger(1,rawHmac);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return Alpha1;
	}
	
	/**
	 * Calculate the polynomial given coefficients
	 * @param hpwd The constant for the polynomial
	 * @param coeff The coefficient values for the polynomial
	 * @param x The value of the polynomial variable
	 * @return The summed polynomial
	 */
	private static BigInteger calculatePoly(BigInteger hpwd, int feature_length,BigInteger[] coeff, int x) {
		BigInteger a0 = hpwd;
		for(int i = 1; i < feature_length; ++i) {
			BigInteger xval = BigInteger.valueOf(x);
			BigInteger aval = coeff[i - 1];
			BigInteger b = xval.pow(i);
			b = b.multiply(aval);
			a0 = a0.add(b);
		}
		return a0;
	}
	
	private static volatile boolean ERASE_FILES_ON_RUN = false;
	static {
		if(ERASE_FILES_ON_RUN) {
			new File("prabhendu.hist").delete();
			new File("prabhendu.ab").delete();
		}
	}
	
	/**
	 * Attempt to log in
	 * @param lf Features for this login attempt
	 * @return Whether or not the login was successful
	 * @throws Exception 
	 */
	private static Greeting loginAttempt(LoginFeatures lf, String password) throws Exception {
		
		int features_length = lf.features.length;
		features_length = 2 * password.length() - 1;
		// Forward declaration of common variables
		BigInteger[] alpha = new BigInteger[features_length],
		             beta  = new BigInteger[features_length];
		Random rand = new Random();
		BigInteger hpwd;
		
		double[] feat_means = new double[features_length];
		double[] feat_devs = new double[features_length];
		
		
		// If this is the first time, create history file and alpha/beta
		if(!new File(hist_dir + lf.username + String.valueOf(lf.fingerprint) +".hist").exists()) {
			// Create new hardened password
			hpwd = new BigInteger(VAR_PREC, Integer.MAX_VALUE, rand);
			
			// Create coefficients for polynomial
			BigInteger[] coeff = new BigInteger[features_length];
			for(int i = 0; i < features_length; ++i) {
				coeff[i] = new BigInteger(VAR_PREC, 0, rand);
			}
			
			// Create new alpha and beta values - Secret shares
			for(int i = 0; i < features_length; ++i) {
				BigInteger gr_pwd1 = calculate_hash(password, (i + 1) << 1);
				BigInteger gr_pwd2 = calculate_hash(password, ((i + 1) << 1) + 1);
				BigInteger y1 = calculatePoly(hpwd, features_length,coeff, (i + 1) << 1);
				BigInteger y2 = calculatePoly(hpwd, features_length,coeff, ((i + 1) << 1) + 1);
				alpha[i] = y1.multiply(gr_pwd1.mod(q));
				beta[i]  = y2.multiply(gr_pwd2.mod(q));
			}
			
			// Create instruction table file
			CharArrayWriter cawInstruction = new CharArrayWriter();
			PrintWriter pw = new PrintWriter(cawInstruction);
			pw.write("Instruction File\n");
			for(int i = 0; i < features_length; ++i) {
				pw.write(alpha[i] + "\n");
				pw.write(beta[i] + "\n");
			}
			pw.close();
			char[] instruction_contents = cawInstruction.toCharArray();
			byte[] instruction_key = password.getBytes();
			byte[] instruction_encrypted = encrypt(instruction_contents,instruction_key);
			FileOutputStream fos = new FileOutputStream(ab_dir + lf.username + String.valueOf(lf.fingerprint) + ".ab");
			fos.write(instruction_encrypted);
			fos.close();
			
			// Create history file contents
			CharArrayWriter caw = new CharArrayWriter(HIST_SIZE);
			pw = new PrintWriter(caw);
			pw.write(HIST_TEXT + "\n");
			pw.write(1 + "\n");
			for(int i = 0; i < features_length; ++i) {
				pw.write(lf.features[i] + "\n");
			}
			pw.close();
			
			// Encrypt history file contents using hpwd - hardened password
			System.out.println("Original hpwd : " + hpwd);
			char[] hist_contents = Arrays.copyOf(caw.toCharArray(), HIST_SIZE - 1);
			byte[] hist_key = hpwd.toByteArray();
			byte[] hist_encrypted = encrypt(hist_contents, hist_key);
			fos = new FileOutputStream(hist_dir + lf.username + String.valueOf(lf.fingerprint) + ".hist");
			fos.write(hist_encrypted);
			fos.close();
			
		} else {
			// Code part for subsequent logins (after initial login)
			
			// Retrieve alpha beta values for this login attempt
//			Path instruction_path = Paths.get(ab_dir + lf.username + String.valueOf(lf.fingerprint) +".ab");
//			byte[] instruction_bytes = Files.readAllBytes(instruction_path);
//			byte[] instruction_key = password.getBytes();
//			instruction_key = Arrays.copyOf(instruction_key, 16);
//			SecretKeySpec secretkeyspec = new SecretKeySpec(instruction_key,"AES");
//			Cipher cipher = Cipher.getInstance("AES");
//			String instruction_decrypted_string = null;
//			try {
//				cipher.init(Cipher.DECRYPT_MODE, secretkeyspec);
//				byte[] instruction_decrypted = cipher.doFinal(instruction_bytes);
//				instruction_decrypted_string = new String(instruction_decrypted);
//			} catch (BadPaddingException e) {
//				System.out.println(e.getMessage());
//				writeLog(lf,"Couldnot decrypt Instruction file",feat_means, feat_devs);
//				return new Greeting(lf.username,false,"Couldnot decrypt Instruction file");
//			}	
//			Scanner scan = new Scanner(instruction_decrypted_string);
//			if(!scan.nextLine().equals("Instruction File")) {
//				scan.close();
//				log.info("Wrong password");
//				//return false;
//				writeLog(lf,"Wrong text password",feat_means, feat_devs);
//				return new Greeting(lf.username,false,"Wrong password");
//			}
//			
//			for(int i = 0; i < features_length; ++i) {
//				alpha[i] = new BigInteger(scan.nextLine());
//				beta[i]  = new BigInteger(scan.nextLine());
//			}
//			scan.close();
//			
//			// Calculate X and Y values
//			BigInteger X[] = new BigInteger[features_length],
//			           Y[] = new BigInteger[features_length];
//			
//			boolean hist_decrypt_success = false;
//			BigInteger hpwd_sum = new BigInteger("0");
//			Scanner hist_file_scanner = null;
			
			FuncReturn result = null;
			for(int i=0;i<=max_errors;i++) {
				switch(i) {
				case 0:
					result = decryptHistory(password, lf, features_length);
					break;
				case 1:
					result = decryptHistory_1(password, lf, features_length);
					break;
				case 2:
					result = decryptHistory_2(password, lf, features_length);
					break;
				default:
					System.out.println("Can't correct more than two errors");
					break;
				}
				
				if (result.greeting.getAttempt() == false) {
					System.out.format("Login failed when max_error correction is %d\n", i);
					continue;
				} else {
					break;
				}
				
			}
			
			//FuncReturn result = decryptHistory_1(password, lf, features_length);
			
			if (result.greeting.getAttempt() == false) {
				return result.greeting;
			}
			BigInteger hpwd_sum = result.new_hpwd;
			
			// Read history file contents
			Scanner hist_file_scanner = new Scanner(result.greeting.getQuote());
			System.out.println(hist_file_scanner.nextLine());
			int login_count = Integer.parseInt(hist_file_scanner.nextLine());
			LoginFeatures[] feat_arr = new LoginFeatures[login_count];
			for(int i = 0; i < login_count; ++i) {
				int[] feat_args = new int[features_length];
				for(int j = 0; j < features_length; ++j) {
					feat_args[j] = Integer.parseInt(hist_file_scanner.nextLine());
				}
				feat_arr[i] = new LoginFeatures(lf.username,lf.fingerprint,feat_args);
			}
			hist_file_scanner.close();
			
			// Calculate feature means (includes the current feature values)
			//feat_means = new double[features_length];
			for(int i = 0; i < features_length; ++i) {
				int sum = 0;
				for(int j = 0; j < login_count; ++j) {
					sum += feat_arr[j].features[i];
				}
				sum += lf.features[i];
				feat_means[i] = (double) sum / (login_count + 1);
			}
			
			// Calculate feature standard deviations (includes the current feature values)
			//feat_devs = new double[features_length];
			for(int i = 0; i < features_length; ++i) {
				double sqdif_sum = 0;
				for(int j = 0; j < login_count; ++j) {
					double dif = feat_arr[j].features[i] - feat_means[i];
					sqdif_sum += dif * dif;
				}
				double dif = lf.features[i] - feat_means[i];
				sqdif_sum += dif * dif;
				double sqdif_avg = sqdif_sum / (login_count + 1);
				feat_devs[i] = Math.sqrt(sqdif_avg);
			}
			
			// Create new random coefficients for polynomial after successful login
			BigInteger[] coeff = new BigInteger[features_length];
			for(int i = 0; i < features_length; ++i) {
				coeff[i] = new BigInteger(VAR_PREC, 0, rand);
			}
			
			// Calculating new alpha and beta values
			BigInteger y1, y2, gr_pwd1, gr_pwd2;
			for(int i = 0; i < features_length; ++i) {
				if(Math.abs(feat_means[i] - (double) THRESH) > k * feat_devs[i] &&
						login_count > n) {
					if (feat_means[i] < (double) THRESH) {
					    y1 = calculatePoly(hpwd_sum, features_length,coeff, (i + 1) << 1);
						y2 = new BigInteger(VAR_PREC, 0, rand);
						
					} else {
						y1 = new BigInteger(VAR_PREC, 0, rand);
						y2 = calculatePoly(hpwd_sum, features_length,coeff, ((i + 1) << 1) + 1);
					}
				} else {
					y1 = calculatePoly(hpwd_sum,features_length, coeff, (i + 1) << 1);
					y2 = calculatePoly(hpwd_sum, features_length,coeff, ((i + 1) << 1) + 1);
				}
				gr_pwd1  = calculate_hash(password, (i + 1) << 1);
				alpha[i] = y1.multiply(gr_pwd1.mod(q));
				gr_pwd2  = calculate_hash(password, ((i + 1) << 1) + 1);
				beta[i]  = y2.multiply(gr_pwd2.mod(q));
			}
			
			// Create new instruction table file with new alpha beta values
			new File(ab_dir + lf.username + String.valueOf(lf.fingerprint) + ".ab").delete();
			CharArrayWriter cawInstruction = new CharArrayWriter();
			PrintWriter pw = new PrintWriter(cawInstruction);
			pw.write("Instruction File\n");
			for(int i = 0; i < features_length; ++i) {
				pw.write(alpha[i] + "\n");
				pw.write(beta[i] + "\n");
			}
			pw.close();
			char[] instruction_contents = cawInstruction.toCharArray();
			byte[] instruction_key = password.getBytes();
			byte[] instruction_encrypted = encrypt(instruction_contents,instruction_key);
			FileOutputStream fos = new FileOutputStream(ab_dir + lf.username + String.valueOf(lf.fingerprint) + ".ab");
			fos.write(instruction_encrypted);
			fos.close();

			System.out.println("\tMeans:");
			for(int i = 0; i < features_length; ++i) {
				System.out.print("\t" + (int) feat_means[i]);
				System.out.print(i == features_length - 1 ? "\n" : "");
			}
			System.out.println("\tDevs:");
			for(int i = 0; i < features_length; ++i) {
				System.out.printf("\t%3.3f", feat_devs[i]);
				System.out.print(i == features_length - 1 ? "\n" : "");
			}
			
			// Create new history file
			new File(hist_dir + lf.username + lf.fingerprint + ".hist").delete();
			CharArrayWriter caw = new CharArrayWriter(HIST_SIZE);
			pw = new PrintWriter(caw);
			pw.write(HIST_TEXT + "\n");
			pw.write(Math.min(login_count + 1, HIST_LIMIT) + "\n");
			//pw.write(lf.fingerprint + "\n");
			if(login_count < HIST_LIMIT) {
				for(int i = 0; i < login_count; ++i) {
					for(int j = 0; j < features_length; ++j) {
						pw.write(feat_arr[i].features[j] + "\n");
					}
				}
			} else {
				for(int i = 1; i < HIST_LIMIT; ++i) {
					for(int j = 0; j < features_length; ++j) {
						pw.write(feat_arr[i].features[j] + "\n");
					}
				}
			}
			for(int i = 0; i < features_length; ++i) {
				pw.write(lf.features[i] + "\n");
			}
			fos = new FileOutputStream(hist_dir + lf.username + lf.fingerprint + ".hist");
			
			// Encrypt history file contents
			char[] hist_contents = Arrays.copyOf(caw.toCharArray(), HIST_SIZE - 1);
			byte[] hist_encrypted = encrypt(hist_contents, hpwd_sum.toByteArray());
			fos.write(hist_encrypted);
			fos.close();
		}
		
		//return true;
		writeLog(lf,"Login Success",feat_means,feat_devs);
		return new Greeting(lf.username,true,"Successfully logged in..!");
	}
	
	/** Function to calculate hpwd without error correction
	 * 
	 * @param password
	 * @param lf
	 * @return
	 * @throws Exception
	 */
	private static FuncReturn decryptHistory (String password, LoginFeatures lf, int features_length) throws Exception {
		// Calculate X and Y values
		BigInteger hpwd_sum = new BigInteger("0");
		Path instruction_path = Paths.get(ab_dir + lf.username + String.valueOf(lf.fingerprint) +".ab");
		byte[] instruction_bytes = Files.readAllBytes(instruction_path);
		byte[] instruction_key = password.getBytes();
		instruction_key = Arrays.copyOf(instruction_key, 16);
		SecretKeySpec secretkeyspec = new SecretKeySpec(instruction_key,"AES");
		Cipher cipher = Cipher.getInstance("AES");
		String instruction_decrypted_string = null;
		try {
			cipher.init(Cipher.DECRYPT_MODE, secretkeyspec);
			byte[] instruction_decrypted = cipher.doFinal(instruction_bytes);
			instruction_decrypted_string = new String(instruction_decrypted);
		} catch (BadPaddingException e) {
			System.out.println(e.getMessage());
			writeLog(lf,"Couldnot decrypt Instruction file",null, null);
			return new FuncReturn(new Greeting(lf.username,false,"Couldnot decrypt Instruction file"),hpwd_sum);
		}	
		Scanner scan = new Scanner(instruction_decrypted_string);
		if(!scan.nextLine().equals("Instruction File")) {
			scan.close();
			log.info("Wrong password");
			//return false;
			writeLog(lf,"Wrong text password",null, null);
			return new FuncReturn(new Greeting(lf.username,false,"Wrong password"),hpwd_sum);
		}
		
		//int features_length = lf.features.length;
		BigInteger[] alpha = new BigInteger[features_length],
					  beta = new BigInteger[features_length];
		
		for(int i = 0; i < features_length; ++i) {
			alpha[i] = new BigInteger(scan.nextLine());
			beta[i]  = new BigInteger(scan.nextLine());
		}
		scan.close();
		
		BigInteger X[] = new BigInteger[features_length],
		           Y[] = new BigInteger[features_length];
		
		for(int i = 0; i < features_length; ++i) {
			if(lf.features[i] < THRESH) {
				X[i] = BigInteger.valueOf((i + 1) << 1);
				BigInteger gr_pwd = calculate_hash(password, (i + 1) << 1);
				Y[i] = alpha[i].divide(gr_pwd.mod(q));
			} else {
				X[i] = BigInteger.valueOf(((i + 1) << 1) + 1);
				BigInteger gr_pwd = calculate_hash(password, ((i + 1) << 1) + 1);
				Y[i] = beta[i].divide(gr_pwd.mod(q));
			}
		}
		
		// Calculate lambda - Lagrange's Coefficient
		BigInteger[] lambda = new BigInteger[features_length];
		for(int i = 0; i < features_length; ++i) {
			BigInteger lambda_num = new BigInteger("1"),
			           lambda_den = new BigInteger("1");
			lambda[i] = new BigInteger("1");
			for(int j = 0; j < features_length; ++j) {
				if(i != j) {
					lambda_num = lambda_num.multiply(X[j]);
					lambda_den = lambda_den.multiply(X[j].subtract(X[i]));
				}
			}
			lambda[i] = lambda[i].multiply(Y[i]).multiply(lambda_num);
			lambda[i] = lambda[i].divide(lambda_den);
		}
		
		// Calculate hpwd' - new hardened password
		hpwd_sum = new BigInteger("0");
		for(int i = 0; i < features_length; ++i) {
			hpwd_sum = hpwd_sum.add(lambda[i]).mod(q);
		}
		
		System.out.println("Calculated hpwd : " + hpwd_sum);
		
		// Open the history file for this login attempt
		Path hist_path = Paths.get(hist_dir + lf.username + String.valueOf(lf.fingerprint) +".hist");
		byte[] hist_bytes = Files.readAllBytes(hist_path);
		byte[] hist_key = hpwd_sum.toByteArray();
		hist_key = Arrays.copyOf(hist_key, 16);
		secretkeyspec = new SecretKeySpec(hist_key,"AES");
		cipher = Cipher.getInstance("AES");
		String hist_decrypted_string = null;
		try {
			cipher.init(Cipher.DECRYPT_MODE, secretkeyspec);
			byte[] hist_decrypted = cipher.doFinal(hist_bytes);
			hist_decrypted_string = new String(hist_decrypted);
		} catch (BadPaddingException e) {
			writeLog(lf,"Couldnot decrypt history file",null, null);
			return new FuncReturn(new Greeting(lf.username,false,"Couldnot decrypt history file"),hpwd_sum);
		}
		
		// Verify that the static string in history file retrieved is correct
		Scanner hist_file_scanner = new Scanner(hist_decrypted_string);
		String hist_magic_text = hist_file_scanner.nextLine();
		if(!HIST_TEXT.equals(hist_magic_text)) {
			hist_file_scanner.close();
			log.info("Wrong hardened password..Nice try..!");
			writeLog(lf,"Wrong hardened password",null, null);
			return new FuncReturn(new Greeting(lf.username,false,"Wrong hardened password"),hpwd_sum);
		}
		
		hist_file_scanner.close();

		return new FuncReturn(new Greeting(lf.username,true, hist_decrypted_string),hpwd_sum);
	}

	/** Function to correct one error in latency features
	 * 
	 * @param password
	 * @param lf
	 * @return
	 * @throws Exception
	 */
	private static FuncReturn decryptHistory_1 (String password, LoginFeatures lf, int features_length) throws Exception {
		// Retrieve alpha beta values for this login attempt
		BigInteger hpwd_sum = new BigInteger("0");
		Path instruction_path = Paths.get(ab_dir + lf.username + String.valueOf(lf.fingerprint) +".ab");
		byte[] instruction_bytes = Files.readAllBytes(instruction_path);
		byte[] instruction_key = password.getBytes();
		instruction_key = Arrays.copyOf(instruction_key, 16);
		SecretKeySpec secretkeyspec = new SecretKeySpec(instruction_key,"AES");
		Cipher cipher = Cipher.getInstance("AES");
		String instruction_decrypted_string = null;
		try {
			cipher.init(Cipher.DECRYPT_MODE, secretkeyspec);
			byte[] instruction_decrypted = cipher.doFinal(instruction_bytes);
			instruction_decrypted_string = new String(instruction_decrypted);
		} catch (BadPaddingException e) {
			System.out.println(e.getMessage());
			writeLog(lf,"Couldnot decrypt Instruction file",null,null);
			return new FuncReturn(new Greeting(lf.username,false,"Couldnot decrypt Instruction file"),hpwd_sum);
		}	
		Scanner scan = new Scanner(instruction_decrypted_string);
		if(!scan.nextLine().equals("Instruction File")) {
			scan.close();
			log.info("Wrong password");
			//return false;
			writeLog(lf,"Wrong text password",null,null);
			return new FuncReturn(new Greeting(lf.username,false,"Wrong password"),hpwd_sum);
		}
		
		//int features_length = lf.features.length;
		BigInteger[] alpha = new BigInteger[features_length],
					  beta = new BigInteger[features_length];
	
		for(int i = 0; i < features_length; ++i) {
			alpha[i] = new BigInteger(scan.nextLine());
			beta[i]  = new BigInteger(scan.nextLine());
		}
		scan.close();
			
		// Calculate X and Y values
		BigInteger X[] = new BigInteger[features_length],
		           Y[] = new BigInteger[features_length];
		
		boolean hist_decrypt_success = false;
		//BigInteger hpwd_sum = new BigInteger("0");
		String hist_decrypted_string = null;
		Scanner hist_file_scanner = null;
									
		// Introducing 1 error correction
		int m=0;	
		while ( m < features_length) {
			for(int i = 0; i < features_length; ++i) {
				if(i >= m && i<m+1) {
					if(lf.features[i] >= THRESH) {
						X[i] = BigInteger.valueOf((i + 1) << 1);
						BigInteger gr_pwd = calculate_hash(password, (i + 1) << 1);
						Y[i] = alpha[i].divide(gr_pwd.mod(q));
					} else {
						X[i] = BigInteger.valueOf(((i + 1) << 1) + 1);
						BigInteger gr_pwd = calculate_hash(password, ((i + 1) << 1) + 1);
						Y[i] = beta[i].divide(gr_pwd.mod(q));
					}
				} else {
					if(lf.features[i] < THRESH) {
						X[i] = BigInteger.valueOf((i + 1) << 1);
						BigInteger gr_pwd = calculate_hash(password, (i + 1) << 1);
						Y[i] = alpha[i].divide(gr_pwd.mod(q));
					} else {
						X[i] = BigInteger.valueOf(((i + 1) << 1) + 1);
						BigInteger gr_pwd = calculate_hash(password, ((i + 1) << 1) + 1);
						Y[i] = beta[i].divide(gr_pwd.mod(q));
					}
				}
			}
			//do all processing
			// Calculate lambda - Lagrange's Coefficient
			BigInteger[] lambda = new BigInteger[features_length];
			for(int i = 0; i < features_length; ++i) {
				BigInteger lambda_num = new BigInteger("1"),
				           lambda_den = new BigInteger("1");
				lambda[i] = new BigInteger("1");
				for(int j = 0; j < features_length; ++j) {
					if(i != j) {
						lambda_num = lambda_num.multiply(X[j]);
						lambda_den = lambda_den.multiply(X[j].subtract(X[i]));
					}
				}
				lambda[i] = lambda[i].multiply(Y[i]).multiply(lambda_num);
				lambda[i] = lambda[i].divide(lambda_den);
			}
				
			// Calculate hpwd' - new hardened password
			hpwd_sum = new BigInteger("0");
			for(int i = 0; i < features_length; ++i) {
				hpwd_sum = hpwd_sum.add(lambda[i]).mod(q);
			}
			System.out.println("Calculated hpwd : " + hpwd_sum);
						
			// Open the history file for this login attempt
			Path hist_path = Paths.get(hist_dir + lf.username + String.valueOf(lf.fingerprint) +".hist");
			byte[] hist_bytes = Files.readAllBytes(hist_path);
			byte[] hist_key = hpwd_sum.toByteArray();
			hist_key = Arrays.copyOf(hist_key, 16);
			secretkeyspec = new SecretKeySpec(hist_key,"AES");
			cipher = Cipher.getInstance("AES");
			
			try {
				cipher.init(Cipher.DECRYPT_MODE, secretkeyspec);
				byte[] hist_decrypted = cipher.doFinal(hist_bytes);
				hist_decrypted_string = new String(hist_decrypted);
			} catch (BadPaddingException e) {
				log.info("Could not decrypt history file");
				//writeLog(lf,"Couldnot decrypt history file",feat_means, feat_devs);
				//return new Greeting(lf.username,false,"Couldnot decrypt history file");
				m = m+1;
				continue;
			}
						
			// Verify that the static string in history file retrieved is correct
			hist_file_scanner = new Scanner(hist_decrypted_string);
			String hist_magic_text = hist_file_scanner.nextLine();
			if(!HIST_TEXT.equals(hist_magic_text)) {
				hist_file_scanner.close();
				log.info("Wrong hardened password..Nice try..!");
				//writeLog(lf,"Wrong hardened password",feat_means, feat_devs);
				//return new Greeting(lf.username,false,"Wrong hardened password");
				m = m+1;
				continue;
			} else {
				hist_decrypt_success = true;
				break;
			}
		}
					
		if(!hist_decrypt_success) {
			writeLog(lf,"Wrong hardened password-after correction",null, null);
			return new FuncReturn(new Greeting(lf.username,false,"Wrong hardened password"),hpwd_sum);
		}		
		hist_file_scanner.close();

		return new FuncReturn(new Greeting(lf.username,true, hist_decrypted_string),hpwd_sum);
	}
	
	/** Function to correct two errors in latency features
	 * 
	 * @param password
	 * @param lf
	 * @return
	 * @throws Exception
	 */
	private static FuncReturn decryptHistory_2 (String password, LoginFeatures lf, int features_length) throws Exception {
		// Retrieve alpha beta values for this login attempt
		BigInteger hpwd_sum = new BigInteger("0");
		Path instruction_path = Paths.get(ab_dir + lf.username + String.valueOf(lf.fingerprint) +".ab");
		byte[] instruction_bytes = Files.readAllBytes(instruction_path);
		byte[] instruction_key = password.getBytes();
		instruction_key = Arrays.copyOf(instruction_key, 16);
		SecretKeySpec secretkeyspec = new SecretKeySpec(instruction_key,"AES");
		Cipher cipher = Cipher.getInstance("AES");
		String instruction_decrypted_string = null;
		try {
			cipher.init(Cipher.DECRYPT_MODE, secretkeyspec);
			byte[] instruction_decrypted = cipher.doFinal(instruction_bytes);
			instruction_decrypted_string = new String(instruction_decrypted);
		} catch (BadPaddingException e) {
			System.out.println(e.getMessage());
			writeLog(lf,"Couldnot decrypt Instruction file",null,null);
			return new FuncReturn(new Greeting(lf.username,false,"Couldnot decrypt Instruction file"),hpwd_sum);
		}	
		Scanner scan = new Scanner(instruction_decrypted_string);
		if(!scan.nextLine().equals("Instruction File")) {
			scan.close();
			log.info("Wrong password");
			//return false;
			writeLog(lf,"Wrong text password",null,null);
			return new FuncReturn(new Greeting(lf.username,false,"Wrong password"),hpwd_sum);
		}
		
		//int features_length = lf.features.length;
		BigInteger[] alpha = new BigInteger[features_length],
					  beta = new BigInteger[features_length];
	
		for(int i = 0; i < features_length; ++i) {
			alpha[i] = new BigInteger(scan.nextLine());
			beta[i]  = new BigInteger(scan.nextLine());
		}
		scan.close();
			
		// Calculate X and Y values
		BigInteger X[] = new BigInteger[features_length],
		           Y[] = new BigInteger[features_length];
		
		boolean hist_decrypt_success = false;
		//BigInteger hpwd_sum = new BigInteger("0");
		String hist_decrypted_string = null;
		Scanner hist_file_scanner = null;
									
		// Introducing 1 error correction
		//while ( m < features_length) {
		for(int k=0; k<features_length; k++) {
		for(int l=k+1; l<features_length; l++) {
			for(int i = 0; i < features_length; ++i) {
				if(i == l || i== k) {
					if(lf.features[i] >= THRESH) {
						X[i] = BigInteger.valueOf((i + 1) << 1);
						BigInteger gr_pwd = calculate_hash(password, (i + 1) << 1);
						Y[i] = alpha[i].divide(gr_pwd.mod(q));
					} else {
						X[i] = BigInteger.valueOf(((i + 1) << 1) + 1);
						BigInteger gr_pwd = calculate_hash(password, ((i + 1) << 1) + 1);
						Y[i] = beta[i].divide(gr_pwd.mod(q));
					}
				} else {
					if(lf.features[i] < THRESH) {
						X[i] = BigInteger.valueOf((i + 1) << 1);
						BigInteger gr_pwd = calculate_hash(password, (i + 1) << 1);
						Y[i] = alpha[i].divide(gr_pwd.mod(q));
					} else {
						X[i] = BigInteger.valueOf(((i + 1) << 1) + 1);
						BigInteger gr_pwd = calculate_hash(password, ((i + 1) << 1) + 1);
						Y[i] = beta[i].divide(gr_pwd.mod(q));
					}
				}
			}
			//do all processing
			// Calculate lambda - Lagrange's Coefficient
			BigInteger[] lambda = new BigInteger[features_length];
			for(int i = 0; i < features_length; ++i) {
				BigInteger lambda_num = new BigInteger("1"),
				           lambda_den = new BigInteger("1");
				lambda[i] = new BigInteger("1");
				for(int j = 0; j < features_length; ++j) {
					if(i != j) {
						lambda_num = lambda_num.multiply(X[j]);
						lambda_den = lambda_den.multiply(X[j].subtract(X[i]));
					}
				}
				lambda[i] = lambda[i].multiply(Y[i]).multiply(lambda_num);
				lambda[i] = lambda[i].divide(lambda_den);
			}
				
			// Calculate hpwd' - new hardened password
			hpwd_sum = new BigInteger("0");
			for(int i = 0; i < features_length; ++i) {
				hpwd_sum = hpwd_sum.add(lambda[i]).mod(q);
			}
			System.out.println("Calculated hpwd : " + hpwd_sum);
						
			// Open the history file for this login attempt
			Path hist_path = Paths.get(hist_dir + lf.username + String.valueOf(lf.fingerprint) +".hist");
			byte[] hist_bytes = Files.readAllBytes(hist_path);
			byte[] hist_key = hpwd_sum.toByteArray();
			hist_key = Arrays.copyOf(hist_key, 16);
			secretkeyspec = new SecretKeySpec(hist_key,"AES");
			cipher = Cipher.getInstance("AES");
			
			try {
				cipher.init(Cipher.DECRYPT_MODE, secretkeyspec);
				byte[] hist_decrypted = cipher.doFinal(hist_bytes);
				hist_decrypted_string = new String(hist_decrypted);
			} catch (BadPaddingException e) {
				log.info("Could not decrypt history file");
				//writeLog(lf,"Couldnot decrypt history file",feat_means, feat_devs);
				//return new Greeting(lf.username,false,"Couldnot decrypt history file");
				continue;
			}
						
			// Verify that the static string in history file retrieved is correct
			hist_file_scanner = new Scanner(hist_decrypted_string);
			String hist_magic_text = hist_file_scanner.nextLine();
			if(!HIST_TEXT.equals(hist_magic_text)) {
				hist_file_scanner.close();
				log.info("Wrong hardened password..Nice try..!");
				//writeLog(lf,"Wrong hardened password",feat_means, feat_devs);
				//return new Greeting(lf.username,false,"Wrong hardened password");
				continue;
			} else {
				hist_decrypt_success = true;
				break;
			}
		}
			if(hist_decrypt_success) {
				break;
			} else {
				continue;
			}
		}
					
		if(!hist_decrypt_success) {
			writeLog(lf,"Wrong hardened password-after correction",null, null);
			return new FuncReturn(new Greeting(lf.username,false,"Wrong hardened password"),hpwd_sum);
		}		
		hist_file_scanner.close();

		return new FuncReturn(new Greeting(lf.username,true, hist_decrypted_string),hpwd_sum);
	}
	
	
	/**
	 * Function to encrypt charArray contents using byteArray key
	 * @throws Exception 
	 */
	private static byte[] encrypt (char[] original, byte[] key) throws Exception {
		if(key==null || original==null) return null;
		
		key = Arrays.copyOf(key, 16);
		SecretKeySpec secretkeyspec = new SecretKeySpec(key,"AES");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, secretkeyspec);
		return cipher.doFinal(new String(original).getBytes());
		
	}
	
	private static void writeLog (LoginFeatures lf, String reason, double[] feat_means, double[] feat_devs) throws Exception {
		File logFile = new File(log_dir + lf.username+String.valueOf(lf.fingerprint)+".log");
		if(!logFile.exists()) {
			logFile.createNewFile();
		}
		FileWriter fW = new FileWriter(logFile,true);
		BufferedWriter bW = new BufferedWriter(fW);
		bW.write("-----start of log for this attempt----\n");
		bW.write(reason+" : ");
		for(int i=0;i<lf.features.length;i++) {
			bW.write(lf.features[i] + ",");
		}
		bW.write("\n");
		if(reason.equals("Login Success")) {
			bW.write("\tMeans:");
			for(int i = 0; i < feat_means.length; ++i) {
				bW.write("\t" + (int) feat_means[i]);
				bW.write(i == feat_means.length - 1 ? "\n" : "");
			}
			bW.write("\tDevs:");
			for(int i = 0; i < feat_devs.length; ++i) {
				bW.write("\t" + String.valueOf(feat_devs[i]));
				bW.write(i == feat_devs.length - 1 ? "\n" : "");
			}
		}
		bW.write("------end of log for this attempt-----\n");
		bW.close();
	}
	
	/**
	 * Object to contain the login features of one line in the input file
	 */
	private static class LoginFeatures {
		//public int seqnum;
		public String username;
		public long fingerprint;
		public int[] features;
		public LoginFeatures(String username, long fingerprint,int[] latency) {
			
			this.username = username;
			this.fingerprint = fingerprint;
			features = new int[latency.length];
			this.features = latency;
		}
	}
	
	private static class FuncReturn {
		public Greeting greeting;
		public BigInteger new_hpwd;
		public FuncReturn(Greeting greeting, BigInteger new_hpwd) {
			this.greeting = greeting;
			this.new_hpwd = new_hpwd;
		}
	}
	
}