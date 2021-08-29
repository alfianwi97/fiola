package alf.security.fiola.utility.common;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;

import javax.imageio.ImageIO;
import javax.imageio.stream.ImageInputStream;

import org.apache.commons.imaging.Imaging;

public class CommonFileUtils extends BaseComponent{
	/** @throws Exception */
	public static String getFileFormatCategory(String fileFormat) throws Exception {
		String fileFormatCategory = null;
		
		for (String format : AppConstants.FILE_FORMAT_IMAGES_LIST) {
			if(fileFormat.equalsIgnoreCase(format)) {
				fileFormatCategory = AppConstants.FILE_CATEGORY_IMAGE;
				break;
			}
		}
		
		if(fileFormatCategory==null) {
			if(fileFormat.equalsIgnoreCase(AppConstants.FILE_FORMAT_PDF)) fileFormatCategory = AppConstants.FILE_FORMAT_PDF;
		}
		if(fileFormatCategory==null)
			for (String format : AppConstants.FILE_FORMAT_DOCS_LIST) {
				if(fileFormat.equalsIgnoreCase(format)) {
					fileFormatCategory = AppConstants.FILE_CATEGORY_DOC_WORD;
					break;
				}
			}
		
		if(fileFormatCategory == null) throw new Exception("No file format category is match with format : "+fileFormat);
		transLog.info("Detected file format category : {}", fileFormatCategory);
		return fileFormatCategory;
	}
	
	/** @throws Exception */
	public static List<String> getFileFormatCategory(List<String> fileFormats) throws Exception {
		List<String> fileFormatCategory = new ArrayList<String>();
		
		for (String fileFormat : fileFormats) {
			for (String format : AppConstants.FILE_FORMAT_IMAGES_LIST) {
				if(fileFormat.toLowerCase().equals(format)) {
					fileFormatCategory.add(AppConstants.FILE_CATEGORY_IMAGE);
					break;
				}
			}
		}
		
		for (String fileFormat : fileFormats) {
			if(fileFormat.equalsIgnoreCase(AppConstants.FILE_FORMAT_PDF)) {
				fileFormatCategory.add(AppConstants.FILE_FORMAT_PDF);
				break;
			}
		}
	
		for (String fileFormat : fileFormats) {
			for (String format : AppConstants.FILE_FORMAT_DOCS_LIST) {
				if(fileFormat.toLowerCase().equals(format)) {
					fileFormatCategory.add(AppConstants.FILE_CATEGORY_DOC_WORD);
					break;
				}
			}
		}
		
		if(fileFormatCategory.size()==0) throw new Exception("No file format category is match with format : "+fileFormats);
		transLog.info("Detected file format category : {}", fileFormatCategory);
		return fileFormatCategory;
	}
	
	/** @throws Exception */
	public static String mapFileBase64MediaTypeToFileFormatCategory(String fileExtension) throws Exception {
		String fileFormatCategory = null;
		
		for (String format : AppConstants.FILE_FORMAT_IMAGES_LIST) {
			if(fileExtension.toLowerCase().equals(format)) {
				fileFormatCategory = AppConstants.FILE_CATEGORY_IMAGE;
				break;
			}
		}
		
		if(fileFormatCategory==null)
			for (String format : AppConstants.FILE_FORMAT_DOCS_LIST) {
				if(fileExtension.toLowerCase().equals(format)) {
					fileFormatCategory = AppConstants.FILE_CATEGORY_DOC_WORD;
					break;
				}
			}
		
		if(fileFormatCategory == null) throw new Exception("No file format category is match with format : "+fileExtension);
		transLog.info("Detected file format category : {}", fileFormatCategory);
		return fileFormatCategory;
	}

	public static BufferedImage getBufferedImage(byte[] f, boolean isFallbackOnApacheCommonsImaging, 
			ByteArrayInputStream is, ImageInputStream iis) {
		BufferedImage bufferedImage = null;
//		ByteArrayInputStream is = null;
//        ImageInputStream iis = null;
		try {
			if (!isFallbackOnApacheCommonsImaging) {
	         	is = new ByteArrayInputStream(f);
	         	iis = ImageIO.createImageInputStream(is);
	         	bufferedImage = ImageIO.read(iis);
	         	
	         } else {
	        	bufferedImage = Imaging.getBufferedImage(f);
	         }
		} catch(Exception e) {
			transLog.warn("Error to get buffered image!", e);
		} finally {
//			try {if(is != null) is.close();} catch (IOException e) {e.printStackTrace();}
//			try {if(iis!= null) iis.close();} catch (IOException e) {e.printStackTrace();}
		}
		return bufferedImage;
	}
}
