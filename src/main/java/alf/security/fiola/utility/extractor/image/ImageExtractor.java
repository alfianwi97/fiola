package alf.security.fiola.utility.extractor.image;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Iterator;

import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;

import org.apache.commons.imaging.ImageInfo;
import org.apache.commons.imaging.Imaging;

import alf.security.fiola.utility.common.BaseComponent;
import alf.security.fiola.utility.common.image.ImageMetadata;

public class ImageExtractor extends BaseComponent {
	
	public static ImageMetadata getImageMetadata(byte[] f) {
		ImageMetadata imageMetadata = new ImageMetadata();
        ByteArrayInputStream  is = null;
        ImageInputStream iis = null;
		
		try {
            if ((f != null) && f.length > 0) {
            	is = new ByteArrayInputStream(f);
            	iis = ImageIO.createImageInputStream(is);

            	Iterator<ImageReader> imageReaderIterator = ImageIO.getImageReaders(iis);
                //If there not ImageReader instance found so it's means that the current 
                // format is not supported by the Java built-in API
                if (!imageReaderIterator.hasNext()) {
                    ImageInfo imageInfo = Imaging.getImageInfo(f);
                    if (imageInfo != null && imageInfo.getFormat() != null 
                    && imageInfo.getFormat().getName() != null) {
                    	imageMetadata.setFormatName(imageInfo.getFormat().getName());
                    	imageMetadata.setFallbackOnApacheCommonsImaging(true);
                    	imageMetadata.setComments(imageInfo.getComments());
//                    	imageMetadata.setHeightInPx(imageInfo.getHeight());
//                        imageMetadata.setWidthInPx(imageInfo.getWidth());
                    } else {
                        throw new IOException("Format of the original image is " + 
                                            "not supported for read operation !");
                    }
                } else {
                    ImageReader reader = imageReaderIterator.next();
                    imageMetadata.setFormatName(reader.getFormatName());
                    imageMetadata.setFallbackOnApacheCommonsImaging(false);
//                    imageMetadata.setHeightInPx(reader.getHeight(imageIndex));
//                    imageMetadata.setWidthInPx(reader.getWidth(0));
//                    System.out.println("METADATAAAAAAAA: "+reader.getImageMetadata(0).toString());
                }
                
             // Load the image
                BufferedImage originalImage;
                if (!imageMetadata.isFallbackOnApacheCommonsImaging()) {
                	is = new ByteArrayInputStream(f);
                	iis = ImageIO.createImageInputStream(is);
                    originalImage = ImageIO.read(iis);
                } else {
                    originalImage = Imaging.getBufferedImage(f);
                }

                // Check that image has been successfully loaded
                if (originalImage == null) {
                    throw new IOException("Cannot load the original image !");
                }
                
                imageMetadata.setHeightInPx(originalImage.getHeight());
                imageMetadata.setWidthInPx(originalImage.getWidth());
                
                transLog.info("Detected image format name : {}", imageMetadata.getFormatName());
                transLog.info("Detected image comment(s) : {}", imageMetadata.getComments() == null ? null : imageMetadata.getComments().toString());
                transLog.info("Detected image mime type : {}", imageMetadata.getMimeType());
                transLog.info("Detected image height : {} px", imageMetadata.getHeightInPx());
                transLog.info("Detected image width : {} px", imageMetadata.getWidthInPx());
            }
        } catch (Exception e) {
            transLog.warn("Error during Image file processing !", e);
            imageMetadata = null;
        } finally {
			try {
				if(is != null) is.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
			try{iis.close();} catch (IOException e) {}
        }
		
		return imageMetadata;
	}
}
