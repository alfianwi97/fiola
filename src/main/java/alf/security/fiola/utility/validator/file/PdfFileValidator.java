package alf.security.fiola.utility.validator.file;

import java.io.InputStream;

import com.itextpdf.text.exceptions.InvalidPdfException;
import com.itextpdf.text.pdf.PdfArray;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;

import alf.security.fiola.utility.code.diagnostic.Diagnostic;
import alf.security.fiola.utility.code.diagnostic.DiagnosticFactory;
import alf.security.fiola.utility.code.diagnostic.detection.DetectionCode;
import alf.security.fiola.utility.common.BaseComponent;

/**input: File, String fileBase64Content, byte[], InputStream*/
public class PdfFileValidator extends BaseComponent {
    
//	@SuppressWarnings("resource")
//	public static ValidatorResult isSafe(String fileBase64Content) {
//		if(fileBase64Content==null || StringUtils.isBlank(fileBase64Content)) return null;
//		boolean safeState = false;
//		try {
//			InputStream in = new ByteArrayInputStream(fileBase64Content.getBytes("UTF-8"));
//			final String encodingType = "base64";
//			try {
//				in = MimeUtility.decode(in, encodingType);
//				safeState = isSafe(in);
//			} catch (MessagingException e) {
//				e.printStackTrace();
//			} finally {
//				in.close();
//			}
//		} catch (IOException e) {
//			e.printStackTrace();
//		}
//    	return safeState;
//	}
//	
//    public static ValidatorResult isSafe(File file) {
//        if(file == null || !file.exists()) return null;
//        PdfReader reader;
//		try {
//			reader = new PdfReader(file.getAbsolutePath());
//		} catch (IOException e) {
//			e.printStackTrace();
//			return false;
//		}
//    	return check(reader);
//    }
    
    public static ValidatorResult isSafe(InputStream is) throws InvalidPdfException {
        if(is == null) return null;
        PdfReader reader;
		try {
			reader = new PdfReader(is);
		} catch (Exception e) {
			transLog.info(e.getMessage());
			ValidatorResult vr = new ValidatorResult();
			vr.setSafe(false);
			vr.setDiagnostic(DiagnosticFactory.fileFormatNotMatch("Failed to read PDF file!"));
			return vr;
		}
    	return check(reader);
    }
    
    public static ValidatorResult isSafe(byte[] byteData) {
        if(byteData == null) return null;
        PdfReader reader;
		try {
			reader = new PdfReader(byteData);
		} catch (Exception e) {
			transLog.info(e.getMessage());
			ValidatorResult vr = new ValidatorResult();
			vr.setSafe(false);
			vr.setDiagnostic(DiagnosticFactory.fileFormatNotMatch("Failed to read PDF file!"));
			return vr;
		}
    	return check(reader);
    }
    
    private static ValidatorResult check(PdfReader reader) {
    	ValidatorResult vr = new ValidatorResult();
    	Diagnostic diagnostic = new Diagnostic();
    	boolean safeState = false;
        try {
            // Check 1:
            // Detect if the document contains any JavaScript code
            String jsCode = reader.getJavaScript();
            System.out.println("Total pages: "+reader.getNumberOfPages());
            System.out.println("Permission: "+reader.getPermissions());
            System.out.println("File length: "+reader.getFileLength());
            System.out.println("Is encrypted: "+reader.isEncrypted());
            System.out.println("Is tampered: "+reader.isTampered());
            System.out.println("Is metadata encrypted: "+reader.isMetadataEncrypted());
            System.out.println("Get Info: "+reader.getInfo().toString());
            if (jsCode == null) {
                // OK no JS code then when pass to check 2:
                // Detect if the document has any embedded files
                PdfDictionary root = reader.getCatalog();
                PdfDictionary names = root.getAsDict(PdfName.NAMES);
                PdfArray namesArray = null;
                if (names != null) {
                    PdfDictionary embeddedFiles = names.getAsDict(PdfName.EMBEDDEDFILES);
                    namesArray = embeddedFiles.getAsArray(PdfName.NAMES);
                }
                // Get safe state from number of embedded files
                safeState = ((namesArray == null) || namesArray.isEmpty());
            } else {
            	diagnostic.setMessage("PDF file may contains mallicious JS script!");
            	diagnostic.setDetectionCode(DetectionCode.DC_CONTAIN_MALLICIOUS_CODE);
            }
        } catch (Exception e) {
            safeState = false;
            diagnostic.setMessage("Error during Pdf file analysis! "+e.getMessage());
            transLog.error("Error during Pdf file analysis!", e);
        }
        
        if(safeState) diagnostic.setDetectionCode(DetectionCode.DC_CLEAN);
        else diagnostic.setDetectionCode(DetectionCode.DC_FILE_FORMAT_NOT_MATCH);
        
        vr.setSafe(safeState);
        vr.setDiagnostic(diagnostic);
        return vr;
    }
}
