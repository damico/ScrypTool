package org.jdamico.scryptool.commons;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jdamico.scryptool.entities.AppProperties;



public class Utils {
	
	public static Utils INSTANCE = null;
	
	public static Utils getInstance(){
		if(INSTANCE == null) INSTANCE = new Utils();
		return INSTANCE;
	}
	
	private Utils(){}

	private static Log log = LogFactory.getLog(Utils.class);
	
	/**
     * Reads the specified file into a byte array.
     */
    public byte[] readFileInByteArray(String aFileName) throws IOException {
        File file = new File(aFileName);
        FileInputStream fileStream = new FileInputStream(file);
        try {
            int fileSize = (int) file.length();
            byte[] data = new byte[fileSize];
            int bytesRead = 0;
            while (bytesRead < fileSize) {
                bytesRead += fileStream.read(data, bytesRead, fileSize-bytesRead);
            }
            return data;
        }
        finally {
            fileStream.close();
        }
    }
    
	public String readFile( File file ) throws IOException {
	    BufferedReader reader = new BufferedReader( new FileReader (file));
	    String         line = null;
	    StringBuilder  stringBuilder = new StringBuilder();
	    String         ls = System.getProperty("line.separator");

	    while( ( line = reader.readLine() ) != null ) {
	        stringBuilder.append( line );
	        stringBuilder.append( ls );
	    }

	    return stringBuilder.toString();
	}
    
    public byte[] readFileInByteArray(File file) throws IOException {

        FileInputStream fileStream = new FileInputStream(file);
        try {
            int fileSize = (int) file.length();
            byte[] data = new byte[fileSize];
            int bytesRead = 0;
            while (bytesRead < fileSize) {
                bytesRead += fileStream.read(data, bytesRead, fileSize-bytesRead);
            }
            return data;
        }
        finally {
            fileStream.close();
        }
    }
    
    public void byteArrayToFile(byte[] bytes, String strFilePath) {
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(strFilePath);
			fos.write(bytes);

		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if(null!=fos)
				try {
					fos.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
		}
	}

	public String getCurrentDateTimeFormated(String string) {
		// TODO Auto-generated method stub
		return null;
	}
	
	public void handleVerboseLog(AppProperties appProperties, char type, String data){

		if(appProperties != null){

			if(appProperties.getLog().equalsIgnoreCase("yes")){
				log(data, type);
			}
			if(appProperties.getVerbose().equalsIgnoreCase("yes")){
				verbose(data, type);
			}
		}else verbose(data, type);
	}

	public void log(String data, char type){



		switch (type) {
		case 'i':
			log.info(data);
			break;

		case 'w':
			log.warn(data);
			break;

		case 'e':
			log.error(data);
			break;

		default:
			log.info(data);
			break;
		}


	}

	public void verbose(String data, char type){
		switch (type) {


		case 'e':
			System.err.println(data);
			break;

		default:
			System.out.println(data);
			break;
		}

	}
}
