package alf.security.fiola.utility.sanitizer;

import java.awt.Graphics;
import java.awt.Image;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;

import javax.imageio.ImageIO;
import javax.imageio.stream.ImageInputStream;

import org.apache.commons.imaging.ImageParser;
import org.apache.commons.imaging.formats.bmp.BmpImageParser;
import org.apache.commons.imaging.formats.dcx.DcxImageParser;
import org.apache.commons.imaging.formats.gif.GifImageParser;
import org.apache.commons.imaging.formats.pcx.PcxImageParser;
import org.apache.commons.imaging.formats.png.PngImageParser;
import org.apache.commons.imaging.formats.tiff.TiffImageParser;
import org.apache.commons.imaging.formats.wbmp.WbmpImageParser;
import org.apache.commons.imaging.formats.xbm.XbmImageParser;
import org.apache.commons.imaging.formats.xpm.XpmImageParser;

import alf.security.fiola.utility.code.diagnostic.detection.DetectionCode;
import alf.security.fiola.utility.common.BaseComponent;
import alf.security.fiola.utility.common.CommonFileUtils;
import alf.security.fiola.utility.common.image.ImageMetadata;
import alf.security.fiola.utility.extractor.image.ImageExtractor;

public class ImageFileSanitizer extends BaseComponent {
	
	public static SanitizerResult sanitizeImageFileContent(byte[] f, List<String> expectedFileFormats) {
    	transLog.info("Start to sanitize file");
    	SanitizerResult sr = new SanitizerResult();
    	
        byte[] sanitizedFileBytes = null;
        ByteArrayInputStream  is = null;
        ByteArrayOutputStream baos = null;
        ImageInputStream iis = null;
        try {
            if ((f != null) && f.length > 0) {
            	ImageMetadata imageMetadata = ImageExtractor.getImageMetadata(f);
            	
            	//validation
            	boolean isFormatValid = false;
            	for (String expectedFormat : expectedFileFormats) {
            		if(imageMetadata.getFormatName().toLowerCase().equals(expectedFormat.toLowerCase())) {
            			isFormatValid = true;
            			break;
            		}
				}
            	
            	if(!isFormatValid) {
            		String msg = String.format("Extracted file format is not matched with expected file format! (Extracted %s| Expected %s)", imageMetadata.getFormatName(), expectedFileFormats);
            		sr.getDiagnostic().setMessage(msg);
            		sr.getDiagnostic().setDetectionCode(DetectionCode.DC_FILE_FORMAT_NOT_MATCH);
            		throw new IllegalArgumentException(msg);
            	}
            		
            	
                // Load the image
            	BufferedImage originalImage = CommonFileUtils.getBufferedImage(f, imageMetadata.isFallbackOnApacheCommonsImaging(),
            			is, iis);
            	
//                BufferedImage originalImage;
//                
//                if (!imageMetadata.isFallbackOnApacheCommonsImaging()) {
//                	is = new ByteArrayInputStream(f);
//                	iis = ImageIO.createImageInputStream(is);
//                    originalImage = ImageIO.read(iis);
//                } else {
//                    originalImage = Imaging.getBufferedImage(f);
//                }
//
//                // Check that image has been successfully loaded
//                if (originalImage == null) {
//                    throw new IOException("Cannot load the original image !");
//                }

                // Get current Width and Height of the image
                int originalWidth = imageMetadata.getWidthInPx();
                int originalHeight = imageMetadata.getHeightInPx();

                // Resize the image by removing 1px on Width and Height
                Image resizedImage = originalImage.getScaledInstance(originalWidth - 1, 
                                                                     originalHeight - 1, 
                                                                     Image.SCALE_SMOOTH);

                // Resize the resized image by adding 1px on Width and Height
                // In fact set image to is initial size
                Image initialSizedImage = resizedImage.getScaledInstance(originalWidth, 
                                                                         originalHeight,
                                                                         Image.SCALE_SMOOTH);

                // Save image by overwriting the provided source file content
                BufferedImage sanitizedImage = new BufferedImage(initialSizedImage.getWidth(null), 
                                                                 initialSizedImage.getHeight(null), 
                                                                 BufferedImage.TYPE_INT_RGB);
                Graphics bg = sanitizedImage.getGraphics();
                bg.drawImage(initialSizedImage, 0, 0, null);
                bg.dispose();
                baos = new ByteArrayOutputStream();
                
                if (!imageMetadata.isFallbackOnApacheCommonsImaging()) {
                    ImageIO.write(sanitizedImage, imageMetadata.getFormatName(), baos);
                } else {
                    ImageParser imageParser;
                    //Handle only formats for which Apache Commons Imaging can successfully write 
                    // (YES in Write column of the reference link) the image format
                    //See reference link in the class header
                    switch (imageMetadata.getFormatName().toUpperCase()) {
                        case "TIFF": {
                            imageParser = new TiffImageParser();
                            break;
                        }
                        case "PCX": {
                            imageParser = new PcxImageParser();
                            break;
                        }
                        case "DCX": {
                            imageParser = new DcxImageParser();
                            break;
                        }
                        case "BMP": {
                            imageParser = new BmpImageParser();
                            break;
                        }
                        case "GIF": {
                            imageParser = new GifImageParser();
                            break;
                        }
                        case "PNG": {
                            imageParser = new PngImageParser();
                            break;
                        }
                        case "WBMP": {
                            imageParser = new WbmpImageParser();
                            break;
                        }
                        case "XBM": {
                            imageParser = new XbmImageParser();
                            break;
                        }
                        case "XPM": {
                            imageParser = new XpmImageParser();
                            break;
                        }
                        default: {
                            throw new IOException("Format of the original image is not" + 
                                                  " supported for write operation !");
                        }

                    }
                    transLog.info("Parser used for sanitizing : {}", imageParser.getClass().toString());
                    imageParser.writeImage(sanitizedImage, baos, new HashMap<>());
                }                

                // Set state flag
                sanitizedFileBytes = baos.toByteArray();
                sr.setSanitizedData(sanitizedFileBytes);
                sr.getDiagnostic().setDetectionCode(DetectionCode.DC_CLEAN);
            }
        } catch (Exception e) {
            transLog.warn("Error during Image file processing !", e);
        } finally {
			try {
				if(is != null) is.close();
				if(baos != null) baos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
//			try{iis.close();} catch (IOException e) {}
        }
        
        transLog.info("Finish to sanitize file");
        return sr;
    }
	
	public static SanitizerResult sanitizeImageFileContent(byte[] f, List<String> expectedFileFormats, ImageMetadata imageMetadata) {
    	transLog.info("Start to sanitize file");
    	SanitizerResult sr = new SanitizerResult();
    	
        byte[] sanitizedFileBytes = null;
        ByteArrayInputStream  is = null;
        ByteArrayOutputStream baos = null;
        ImageInputStream iis = null;
        try {
            if ((f != null) && f.length > 0) {
            	
                // Load the image
            	BufferedImage originalImage = CommonFileUtils.getBufferedImage(f, imageMetadata.isFallbackOnApacheCommonsImaging(),
            			is, iis);
            	
//                BufferedImage originalImage;
//                
//                if (!imageMetadata.isFallbackOnApacheCommonsImaging()) {
//                	is = new ByteArrayInputStream(f);
//                	iis = ImageIO.createImageInputStream(is);
//                    originalImage = ImageIO.read(iis);
//                } else {
//                    originalImage = Imaging.getBufferedImage(f);
//                }
//
//                // Check that image has been successfully loaded
//                if (originalImage == null) {
//                    throw new IOException("Cannot load the original image !");
//                }

                // Get current Width and Height of the image
                int originalWidth = imageMetadata.getWidthInPx();
                int originalHeight = imageMetadata.getHeightInPx();

                // Resize the image by removing 1px on Width and Height
                Image resizedImage = originalImage.getScaledInstance(originalWidth - 1, 
                                                                     originalHeight - 1, 
                                                                     Image.SCALE_SMOOTH);

                // Resize the resized image by adding 1px on Width and Height
                // In fact set image to is initial size
                Image initialSizedImage = resizedImage.getScaledInstance(originalWidth, 
                                                                         originalHeight,
                                                                         Image.SCALE_SMOOTH);

                // Save image by overwriting the provided source file content
                BufferedImage sanitizedImage = new BufferedImage(initialSizedImage.getWidth(null), 
                                                                 initialSizedImage.getHeight(null), 
                                                                 BufferedImage.TYPE_INT_RGB);
                Graphics bg = sanitizedImage.getGraphics();
                bg.drawImage(initialSizedImage, 0, 0, null);
                bg.dispose();
                baos = new ByteArrayOutputStream();

                if (!imageMetadata.isFallbackOnApacheCommonsImaging()) {
                    ImageIO.write(sanitizedImage, imageMetadata.getFormatName(), baos);
                } else {
                    ImageParser imageParser;
                    //Handle only formats for which Apache Commons Imaging can successfully write 
                    // (YES in Write column of the reference link) the image format
                    //See reference link in the class header
                    switch (imageMetadata.getFormatName().toUpperCase()) {
                        case "TIFF": {
                            imageParser = new TiffImageParser();
                            break;
                        }
                        case "PCX": {
                            imageParser = new PcxImageParser();
                            break;
                        }
                        case "DCX": {
                            imageParser = new DcxImageParser();
                            break;
                        }
                        case "BMP": {
                            imageParser = new BmpImageParser();
                            break;
                        }
                        case "GIF": {
                            imageParser = new GifImageParser();
                            break;
                        }
                        case "PNG": {
                            imageParser = new PngImageParser();
                            break;
                        }
                        case "WBMP": {
                            imageParser = new WbmpImageParser();
                            break;
                        }
                        case "XBM": {
                            imageParser = new XbmImageParser();
                            break;
                        }
                        case "XPM": {
                            imageParser = new XpmImageParser();
                            break;
                        }
                        default: {
                            throw new IOException("Format of the original image is not" + 
                                                  " supported for write operation !");
                        }

                    }
                    transLog.info("Parser used for sanitizing : {}", imageParser.getClass().toString());
                    imageParser.writeImage(sanitizedImage, baos, new HashMap<>());
                }                

                // Set state flag
                sanitizedFileBytes = baos.toByteArray();
                sr.setSanitizedData(sanitizedFileBytes);
                sr.getDiagnostic().setDetectionCode(DetectionCode.DC_CLEAN);
            }
        } catch (Exception e) {
        	sr.getDiagnostic().setDetectionCode(DetectionCode.DC_FILE_FORMAT_NOT_MATCH);
        	sr.getDiagnostic().setMessage("Error during Image file processing! "+e.getMessage());
            transLog.warn("Error during Image file processing !", e);
        } finally {
			try {
				if(is != null) is.close();
				if(baos != null) baos.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
//			try{iis.close();} catch (IOException e) {}
        }
        
        transLog.info("Finish to sanitize file");
        return sr;
    }
	
}
