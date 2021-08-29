package alf.security.fiola.utility.validator.file;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;

import alf.security.fiola.utility.common.AppConstants;
import alf.security.fiola.utility.common.BaseComponent;
import alf.security.fiola.utility.common.FileBase64Utils;

public class FileBase64Validator extends BaseComponent{	

	public static boolean checkFileBase64ContentSizeInKB(String fileBase64Content, long minSizeInKB, long maxSizeInKB)
			throws Exception {
		transLog.info("Checking file base64 content size . . .");
		if (StringUtils.isBlank(fileBase64Content))
			throw new Exception("Invalid ImageBase64 : " + fileBase64Content);
		if (minSizeInKB < 0 || maxSizeInKB < 0 || maxSizeInKB < minSizeInKB)
			throw new Exception("Invalid size validation (min:" + minSizeInKB + ", max:" + maxSizeInKB + ")");

		double fileSizeInBytes = 4 * Math.ceil((fileBase64Content.length() / 3)) * 0.5624896334383812;
		double fileSizeInKB = fileSizeInBytes / 1024;

		if (fileSizeInKB < minSizeInKB || fileSizeInKB > maxSizeInKB)
			return false;
		return true;
	}
	
	public static boolean checkFileBase64HeaderFormat(String fileBase64Header, String[] allowedFormats) throws Exception {
		transLog.info("Checking file base64 header format . . .");
		if(StringUtils.isBlank(fileBase64Header)) throw new Exception("Invalid imageBase64Header : "+fileBase64Header);
		
		final String[] imageBaseFormat = {"data:image/",";base64"};
		final String[] appBaseFormat = {"data:application/",";base64"};

		List<String> modifiedAllowedFormats = new ArrayList<String>();
		
		//check for all defined formats if null or length==0
		//TODO
		if(allowedFormats==null || allowedFormats.length == 0) allowedFormats = AppConstants.FILE_FORMAT_ALL_LIST;
			
		for (String allowedFormat : allowedFormats) {
			/** Add specified format to its appropriate header*/
			String format = null;
			switch (allowedFormat) {
				case AppConstants.FILE_FORMAT_PDF:	/**data:application */
					format = appBaseFormat[0]+allowedFormat+appBaseFormat[1];
					break;
				default:	/**data:image*/
					format = imageBaseFormat[0]+allowedFormat+imageBaseFormat[1];
			}
			modifiedAllowedFormats.add(format);
		}
		
		for (String allowedHeaderFormat : modifiedAllowedFormats) 
			if(fileBase64Header.equals(allowedHeaderFormat)) return true;

		return false;
	}

	public static boolean isFileBase64(String fileBase64) throws Exception {
		//TODO
        return isFileBase64(fileBase64, AppConstants.FILE_FORMAT_ALL_LIST);
    }
	
	public static boolean isFileBase64(String fileBase64, String[] allowedFormats) throws Exception {
		transLog.info("Checking whole file base64 (header and content) . . .");
		if(StringUtils.isBlank(fileBase64)) throw new Exception("Invalid fileBase64 : "+fileBase64);
		
		boolean isValid = true;
		String[] imageBase64Data = fileBase64.split(",", -1);
        if (imageBase64Data.length != 2) isValid = false;
        else if (StringUtils.isBlank(imageBase64Data[0]) || !checkFileBase64HeaderFormat(imageBase64Data[0], allowedFormats)) isValid = false;
        else if (StringUtils.isBlank(imageBase64Data[1]) || !Base64.isBase64(imageBase64Data[1])) isValid = false;
        else if (!checkFileBase64Content(fileBase64)) isValid = false;
        return isValid;
    }
	
	public static boolean isFileBase64(String fileBase64, int minSizeInKB, int maxSizeInKB) throws Exception {
		transLog.info("Checking whole file base64 (header, content, and size) . . .");
		if(StringUtils.isBlank(fileBase64)) throw new Exception("Invalid fileBase64 : "+fileBase64);
		
		boolean isValid = true;
		String[] imageBase64Data = fileBase64.split(",", -1);
        if (imageBase64Data.length != 2) isValid = false;
        //TODO
        else if (StringUtils.isBlank(imageBase64Data[0]) || !checkFileBase64HeaderFormat(imageBase64Data[0], AppConstants.FILE_FORMAT_ALL_LIST)) isValid = false;
        else if (StringUtils.isBlank(imageBase64Data[1]) || !Base64.isBase64(imageBase64Data[1])) isValid = false;
        else if (!checkFileBase64Content(fileBase64)) isValid = false;
        else if (!checkFileBase64ContentSizeInKB(imageBase64Data[1], minSizeInKB, maxSizeInKB)) isValid = false;
        return isValid;
    }
	
	public static boolean isFileBase64(String fileBase64, String[] allowedFormats, int minSizeInKB, int maxSizeInKB) throws Exception {
		transLog.info("Checking whole file base64 (header, content, and size) . . .");
		if(StringUtils.isBlank(fileBase64)) throw new Exception("Invalid fileBase64 : "+fileBase64);
		
		boolean isValid = true;
		String[] fileBase64Data = fileBase64.split(",", -1);
        if (fileBase64Data.length != 2) isValid = false;
        else if (StringUtils.isBlank(fileBase64Data[0]) || !checkFileBase64HeaderFormat(fileBase64Data[0], allowedFormats)) isValid = false;
        else if (StringUtils.isBlank(fileBase64Data[1]) || !Base64.isBase64(fileBase64Data[1])) isValid = false;
        else if (!checkFileBase64Content(fileBase64)) isValid = false;
        else if (!checkFileBase64ContentSizeInKB(fileBase64Data[1], minSizeInKB, maxSizeInKB)) isValid = false;
        transLog.info("Finish to check whole file base64 (header, content, and size) . . .");
        return isValid;
    }
	

	public static boolean checkFileBase64Content(String fileBase64) {
		transLog.info("Start to check image content . . .");
		boolean safeState = true;
		String fileBase64Extension = FileBase64Utils.getFileBase64Extension(fileBase64);
		String fileBase64Content = FileBase64Utils.getFileBase64Content(fileBase64);
		
		switch(fileBase64Extension) {
		case AppConstants.FILE_FORMAT_PDF:
//			byte[] imageContentBytes = java.util.Base64.getEncoder().encode(imageContent.getBytes());
//			try {
//				InputStream in = new ByteArrayInputStream(imageContent.getBytes("UTF-8"));
//			
//				final String encodingType = "base64";
//				try {
//					in = MimeUtility.decode(in, encodingType);
//					safeState = PdfDocumentValidatorImpl.isSafe(in);
//				} catch (MessagingException e) {
//					e.printStackTrace();
//					safeState = false;
//				} finally {
//					in.close();
//				}
//			} catch (IOException e) {
//				e.printStackTrace();
//				safeState = false;
//			}
			//TODO
//			safeState = PdfFileValidator.isSafe(fileBase64Content);
			break;
		}
		
		transLog.info("Finish to check image content . . .");
		return safeState;
	}
	
	
//	@SuppressWarnings("resource")
//	public static String sanitizeFileBase64(String fileBase64) throws Exception {
//		transLog.info("Sanitizing file . . .");
//		String fileBase64Header = FileBase64Utils.getFileBase64Header(fileBase64);
//		String fileBase64Extension = FileBase64Utils.getFileBase64Extension(fileBase64);
//		String fileBase64Content = FileBase64Utils.getFileBase64Content(fileBase64);
//		String sanitizedFileBase64 = null;
//		
//		File tmpFile = null;
//		InputStream generatedFileInputStream = null;
//		byte[] byteData = null;
//		try {
//			
//			InputStream in = new ByteArrayInputStream(fileBase64Content.getBytes("UTF-8"));
//			final String encodingType = "base64";
//			
//				switch(fileBase64Extension) {
//				case AppConstants.FILE_FORMAT_IMAGE_JPG:
//				case AppConstants.FILE_FORMAT_IMAGE_JPEG:
//				case AppConstants.FILE_FORMAT_IMAGE_PNG:
//					
//					final String tmpFolder = PropertiesConstants.mapsTempFolder;
//					try {
//						in = MimeUtility.decode(in, encodingType);
//						
//						transLog.info("Creating new temp file . . .");
//						tmpFile = File.createTempFile("sitevisit-image_", null, new File(tmpFolder));
//						FileUtils.copyInputStreamToFile(in, tmpFile);
//					} catch (MessagingException e) {
//						e.printStackTrace();
//					} finally {
//						in.close();
//					}
//						
//					if(!ImageDocumentSanitizerImpl.sanitizeFile(tmpFile)) {
//						throw new Exception("Error when sanitizing file!");
//					}
//					
//					try {
//						generatedFileInputStream = new FileInputStream(tmpFile);
//						byteData = IOUtils.toByteArray(generatedFileInputStream);
//					} finally {
//						generatedFileInputStream.close();
//					}
//					
////						//TODO delete temp code
////						String filepath = "tmpFolder+"/test."+fileBase64Extension";
////						File testFile = new File(filepath);
////						testFile.createNewFile();
////						
////						if(!testFile.canWrite())
////							System.out.println("FILE: CANNOT WRITE!");
////						Files.write(testFile.toPath(), byteData, StandardOpenOption.WRITE);
////						if(!testFile.exists())
////							throw new Exception("Error when read sanitized file : "+testFile.exists());
//					
//					
//					sanitizedFileBase64 = fileBase64Header +","+Base64.encodeBase64String(byteData);
////					System.out.println("RES: "+sanitizedFileBase64);
//					break;
//				}
//		} catch (IOException e) {
//			e.printStackTrace();
//		} finally {
//			if(tmpFile != null) tmpFile.delete();
//			if(generatedFileInputStream != null) generatedFileInputStream.close();
//		}
//		transLog.info("Finish to file . . .");
//		return sanitizedFileBase64;
//	}
	
}
