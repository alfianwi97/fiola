package alf.security.fiola.internals.service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.springframework.stereotype.Service;

import alf.security.fiola.internals.model.apigw.v1.EaiOutputSchema;
import alf.security.fiola.internals.model.filecompletehandle.DocumentFileConstraint;
import alf.security.fiola.internals.model.filecompletehandle.ExecutorResult;
import alf.security.fiola.internals.model.filecompletehandle.FileBase64CompleteHandleClientInput;
import alf.security.fiola.internals.model.filecompletehandle.FileBase64CompleteHandleRequest;
import alf.security.fiola.internals.model.filecompletehandle.ImageFileConstraint;
import alf.security.fiola.internals.model.filesanitizer.FileBase64SanitizingClientOutput;
import alf.security.fiola.internals.model.filesanitizer.single.FileBase64OutputCompleteHandleResponse;
import alf.security.fiola.internals.model.filevalidator.FileConstraint;
import alf.security.fiola.internals.model.filevalidator.IFileConstraintValidationRequest;
import alf.security.fiola.utility.code.diagnostic.Diagnostic;
import alf.security.fiola.utility.code.diagnostic.DiagnosticFactory;
import alf.security.fiola.utility.code.diagnostic.detection.DetectionCode;
import alf.security.fiola.utility.code.returncode.ReturnCode;
import alf.security.fiola.utility.common.AppConstants;
import alf.security.fiola.utility.common.CommonFileUtils;
import alf.security.fiola.utility.common.FileBase64Utils;
import alf.security.fiola.utility.common.image.ImageMetadata;
import alf.security.fiola.utility.extractor.image.ImageExtractor;
import alf.security.fiola.utility.sanitizer.ImageFileSanitizer;
import alf.security.fiola.utility.sanitizer.SanitizerResult;
import alf.security.fiola.utility.validator.file.CommonFileFValidator;
import alf.security.fiola.utility.validator.file.PdfFileValidator;
import alf.security.fiola.utility.validator.file.ValidatorResult;

@Service
public class FileCompleteHandleService extends BaseService{
	
	public EaiOutputSchema<FileBase64OutputCompleteHandleResponse> handleFileBase64ContentToBase64(FileBase64CompleteHandleRequest request) {
		EaiOutputSchema<FileBase64OutputCompleteHandleResponse> responseSchema = new EaiOutputSchema<FileBase64OutputCompleteHandleResponse>() {
			private static final long serialVersionUID = -2034141028637127318L;};
			
		FileBase64OutputCompleteHandleResponse responseObject = new FileBase64OutputCompleteHandleResponse();
		FileBase64SanitizingClientOutput fileClientOutput = new FileBase64SanitizingClientOutput();
		if(request.getFileClientInput() == null) request.setFileClientInput(new FileBase64CompleteHandleClientInput());
		fileClientOutput.setFileName(request.getFileClientInput().getFileName());
		fileClientOutput.setDiagnostic(new Diagnostic());
		responseObject.setFileClientOutput(fileClientOutput);
		responseSchema.setOutputSchema(responseObject);
		
		transLog.info("===Start to do complete handle on file : {} ({})", request.getFileClientInput().getFileName(), request.getFileClientInput().getExpectedFileFormats());
		
		try {
			String fileBase64Extension = FileBase64Utils.getFileBase64Extension(request.getFileClientInput().getData());
						
			//validation
			Diagnostic diagnostic = getInputError(request, fileBase64Extension);
			if(diagnostic.getDetectionCode() != null) {
				responseSchema.getOutputSchema().getFileClientOutput().setDiagnostic(diagnostic);
				throw new IllegalArgumentException("Invalid input value : "+request.getFileClientInput().toString());
			}
			
			if(request.getFileClientInput().getFileConstraint() != null) {
				diagnostic = getFileConstraintInputError(request.getFileClientInput());
				if(diagnostic.getDetectionCode() != null) {
					responseSchema.getOutputSchema().getFileClientOutput().setDiagnostic(diagnostic);
					throw new IllegalArgumentException("Invalid input value : "+request.getFileClientInput().toString());
				}
			}
			
			String fileBase64Header = FileBase64Utils.getFileBase64Header(request.getFileClientInput().getData());	
			String fileBase64Content = FileBase64Utils.getFileBase64Content(request.getFileClientInput().getData());
			
			byte[] imageByte = Base64.decodeBase64(fileBase64Content.getBytes());
			
			transLog.info("Format valid");
			
			//sanitizer
			ExecutorResult er = null;
			if(!StringUtils.isBlank(request.getFileClientInput().getFileName())) { //use filename
				String filenameExt = request.getFileClientInput().getFileName().substring(request.getFileClientInput().getFileName().lastIndexOf('.')+1);
				String fileFormatCategoryFromFilenameExt = CommonFileUtils.getFileFormatCategory(filenameExt);
				er = executeValidatorAndSanitizer(imageByte, fileFormatCategoryFromFilenameExt, request.getFileClientInput().getExpectedFileFormats(), request.getFileClientInput().getFileConstraint());
			} else if(!StringUtils.isBlank(fileBase64Extension)) { //use base64 header
				String fileFormatCategoryFromBase64Header = CommonFileUtils.getFileFormatCategory(fileBase64Extension);
				er = executeValidatorAndSanitizer(imageByte, fileFormatCategoryFromBase64Header, request.getFileClientInput().getExpectedFileFormats(), request.getFileClientInput().getFileConstraint());
			} else { //use expected formats
				List<String> expectedFileFormatCategories = new ArrayList<String>();
				expectedFileFormatCategories = CommonFileUtils.getFileFormatCategory(request.getFileClientInput().getExpectedFileFormats());
				
				//make unique list
				expectedFileFormatCategories = expectedFileFormatCategories.stream().distinct().collect(Collectors.toList());
				er = executeValidatorAndSanitizer(imageByte, expectedFileFormatCategories, request.getFileClientInput().getExpectedFileFormats(), request.getFileClientInput().getFileConstraint());
			}
			
			if(er.getDiagnostic().getDetectionCode().equals(DetectionCode.DC_CLEAN)) {
				String sanitizedFileBase64 = fileBase64Header==null ?
						Base64.encodeBase64String(er.getData()) : fileBase64Header +","+Base64.encodeBase64String(er.getData());

				responseObject.getFileClientOutput().setData(sanitizedFileBase64);
			}
			
			responseObject.getFileClientOutput().setDiagnostic(er.getDiagnostic());
			responseSchema.setOutputSchema(responseObject);
			
			transLog.info("Executor result: "+er.getDiagnostic().toString());
			setReturnMessage(responseSchema, ReturnCode.RC_SERVICE_SUCCESS);
		} catch(IllegalArgumentException e) {
			transLog.error("Error : {}", e.getMessage());
//			responseSchema.getOutputSchema().getFileClientOutput().getDiagnostic().setStateCode(StateCode.SC_VALIDATED);
			setReturnMessage(responseSchema, ReturnCode.RC_SERVICE_BAD_INPUT);
		} catch (Exception e){
			e.printStackTrace();
			transLog.error("Error : {}", e.getStackTrace().toString());
//			responseSchema.getOutputSchema().getFileClientOutput().getDiagnostic().setStateCode(StateCode.SC_PROCESSING_ERROR);
			setReturnMessage(responseSchema, ReturnCode.RC_SERVICE_GENERAL_ERROR);
		}
		transLog.info("===Finish to do complete handle on file : {} ({})", request.getFileClientInput().getFileName(), request.getFileClientInput().getExpectedFileFormats());
		return responseSchema;
	}
	
	private Diagnostic getFileConstraintInputError(IFileConstraintValidationRequest fci) {
		Diagnostic diagnostic = new Diagnostic();
		String detectedError = null;
		String message = null;
		
		FileConstraint fileConstraint = fci.getFileConstraint();
		
		if(fileConstraint.getMaxHeightInPx() != null && fileConstraint.getMaxHeightInPx().compareTo(0) < 0) {
			detectedError = DetectionCode.DC_COMMON_INPUT_VIOLATION;
			message = "Max height is not valid : "+fileConstraint.getMaxHeightInPx();
		} else if(fileConstraint.getMinHeightInPx() != null && fileConstraint.getMinHeightInPx().compareTo(0) < 0) {
			detectedError = DetectionCode.DC_COMMON_INPUT_VIOLATION;
			message = "Min height is not valid : "+fileConstraint.getMinHeightInPx();
		} else if(fileConstraint.getMaxWidthInPx() != null && fileConstraint.getMaxWidthInPx().compareTo(0) < 0) {
			detectedError = DetectionCode.DC_COMMON_INPUT_VIOLATION;
			message = "Max width is not valid : "+fileConstraint.getMaxWidthInPx();
		} else if(fileConstraint.getMinWidthInPx() != null && fileConstraint.getMinWidthInPx().compareTo(0) < 0) {
			detectedError = DetectionCode.DC_COMMON_INPUT_VIOLATION;
			message = "Min width is not valid : "+fileConstraint.getMinWidthInPx();
		} else if(fileConstraint.getMaxSizeInKb() != null && fileConstraint.getMaxSizeInKb().compareTo(0L) < 0) {
			detectedError = DetectionCode.DC_COMMON_INPUT_VIOLATION;
			message = "Max size is not valid : "+fileConstraint.getMaxSizeInKb();
		} else if(fileConstraint.getMinSizeInKb() != null && fileConstraint.getMinSizeInKb().compareTo(0L) < 0) {
			detectedError = DetectionCode.DC_COMMON_INPUT_VIOLATION;
			message = "Min size is not valid : "+fileConstraint.getMinSizeInKb();
		}
		
		if(detectedError != null) {
			transLog.info(message);
			diagnostic.setDetectionCode(detectedError);
			diagnostic.setMessage(message);
		}
		
		return diagnostic;
	}
	
	private Diagnostic getInputError(FileBase64CompleteHandleRequest request, String fileBase64Extension) {
		Diagnostic diagnostic = new Diagnostic();
		String detectedError = null;
		String message = null;
		
		String filenameExt = null;
		
		boolean isFilenameNull = request.getFileClientInput().getFileName()==null;
		
		if(!isFilenameNull) {
			if(!CommonFileFValidator.isFilenameLengthFit(request.getFileClientInput().getFileName(), AppConstants.MAX_FILENAME_LENGTH)) {
				detectedError = DetectionCode.DC_FILENAME_LENGTH_VIOLATION;
				message = String.format("Filename length is not valid : %s chars", request.getFileClientInput().getFileName().length());
			}
			else if(!CommonFileFValidator.isFilenameSafe(request.getFileClientInput().getFileName())) {
				detectedError = DetectionCode.DC_CONTAIN_MALLICIOUS_FILENAME;
				message = String.format("Invalid filename: '%s', valid pattern: %s", request.getFileClientInput().getFileName(), AppConstants.FILENAME_VALID_REGEX_PATTERN);
			}
		}
		
		if(detectedError==null)
			if(request.getFileClientInput().getExpectedFileFormats() == null || request.getFileClientInput().getExpectedFileFormats().size() == 0 
					|| StringUtils.isBlank(request.getFileClientInput().getData())) {
				detectedError = DetectionCode.DC_MISSING_MANDATORY_VALUES;
				message = "Input is blank: "+request.getFileClientInput().toString();
			}
		
		if(!isFilenameNull && detectedError==null) {
			boolean isFormatValid = false;
			filenameExt = request.getFileClientInput().getFileName().substring(request.getFileClientInput().getFileName().lastIndexOf('.')+1);
			for(String expectedFormat : request.getFileClientInput().getExpectedFileFormats()) {
				if(expectedFormat.equalsIgnoreCase(filenameExt)) {
					isFormatValid = true;
					break;
				}
			}
			
			if(!isFormatValid) {
				detectedError = DetectionCode.DC_FILE_FORMAT_NOT_MATCH;
				message = String.format("Invalid file format : %s, expected: %s", request.getFileClientInput().getFileName(), request.getFileClientInput().getExpectedFileFormats());
			}
		}
		
		if(fileBase64Extension!=null && detectedError==null) {
			boolean isFormatValid = false;
			for(String expectedFormat : request.getFileClientInput().getExpectedFileFormats()) {
				if(expectedFormat.equalsIgnoreCase(fileBase64Extension)) {
					isFormatValid = true;
					break;
				}
			}
			if(!isFormatValid) {
				detectedError = DetectionCode.DC_FILE_FORMAT_NOT_MATCH;
				message = String.format("Invalid file format : base64 header format %s, expected: %s", fileBase64Extension, request.getFileClientInput().getExpectedFileFormats());
			}
		}
		
		diagnostic.setDetectionCode(detectedError);
		diagnostic.setMessage(message);
		
		return diagnostic;
	}
		
	private ExecutorResult executeValidatorAndSanitizer(byte[] fileBytes, String fileFormatCategory, List<String> expectedFileFormats, FileConstraint fileConstraint) throws IOException {
		transLog.info(String.format("Execute validator and sanitizer with params: file format category :%s | expected formats:%s", fileFormatCategory, expectedFileFormats));
		ExecutorResult er = new ExecutorResult();
		ValidatorResult vr = null;
		SanitizerResult sr = null;
		
//		ByteArrayInputStream bais = null;
		
		switch(fileFormatCategory) {
		case AppConstants.FILE_FORMAT_PDF:
			transLog.info("[Executor] Start PDF processing");
			vr = PdfFileValidator.isSafe(fileBytes);
			transLog.info("[Executor] End of PDF processing");
			break;
		case AppConstants.FILE_CATEGORY_IMAGE:
			transLog.info("[Executor] Start image processing");
//			sr = ImageFileSanitizer.sanitizeImageFileContent(fileBytes, expectedFileFormats);
			
			sr = new SanitizerResult();
			String msg = null;
			ImageMetadata imageMetadata;
			
			imageMetadata = ImageExtractor.getImageMetadata(fileBytes);
			if(imageMetadata == null) {
				msg = String.format("Cannot extract image metadata! Invalid file format!");
        		sr.setDiagnostic(DiagnosticFactory.fileFormatNotMatch(msg));
				break;
			}
			
			//validation
        	boolean isFormatValid = false;
        	for (String expectedFormat : expectedFileFormats) {
        		if(imageMetadata.getFormatName().toLowerCase().equals(expectedFormat.toLowerCase())) {
        			isFormatValid = true;
        			break;
        		}
			}
        	
        	if(!isFormatValid) {
        		msg = String.format("Extracted file format is not matched with expected file format! (Extracted %s| Expected %s)", imageMetadata.getFormatName(), expectedFileFormats);
        		sr.setDiagnostic(DiagnosticFactory.fileFormatNotMatch(msg));
        		break;
        	}
        	
        	sr = ImageFileSanitizer.sanitizeImageFileContent(fileBytes, expectedFileFormats, imageMetadata);
        	if(!sr.getDiagnostic().getDetectionCode().equals(DetectionCode.DC_CLEAN)) {
        		break;
        	}
        	
        	//file contraint validation
        	Diagnostic diagnostic = checkImageFileConstraint(fileConstraint, imageMetadata, fileBytes);
        	if(!diagnostic.getDetectionCode().equals(DetectionCode.DC_CLEAN)) {
        		sr.setDiagnostic(diagnostic);
        		break;
        	}
        	
        	transLog.info("[Executor] End of image processing");
			break;
		case AppConstants.FILE_CATEGORY_DOC_WORD:
				//TODO GANTI KE VR RESPONSE
//				safeState = DocFileValidator.isSafe(bais);
			break;
		case AppConstants.FILE_CATEGORY_DOC_EXCEL:
			//sanitizer method for doc excel
			break;
		}
		
		if(vr != null) {
			er.setDiagnostic(vr.getDiagnostic());
			if(er.getDiagnostic().getDetectionCode().equals(DetectionCode.DC_CLEAN))
				er.setData(fileBytes);
		} else if(sr != null){
			er.setDiagnostic(sr.getDiagnostic());
			if(er.getDiagnostic().getDetectionCode().equals(DetectionCode.DC_CLEAN))
				er.setData(sr.getSanitizedData());
		} else {
			String msg = "File format is not match with any available format!";
			er.setDiagnostic(DiagnosticFactory.fileFormatNotMatch(msg));
		}
		
		return er;
	}
	
	private ExecutorResult executeValidatorAndSanitizer(byte[] fileBytes, List<String> fileFormatCategories, List<String> expectedFileFormats, FileConstraint fileConstraint) throws IOException {
		transLog.info(String.format("Execute validator and sanitizer with params: file format category :%s | expected formats:%s", fileFormatCategories, expectedFileFormats));
		
		boolean finishHandle = false;
		ExecutorResult er = new ExecutorResult();
		ValidatorResult vr = null;
		SanitizerResult sr = null;
		ByteArrayInputStream bais = null;
		
		try{
			bais = new ByteArrayInputStream(fileBytes);
			
			for (String fileFormatCategory : fileFormatCategories) {
				if(!finishHandle) {
					switch(fileFormatCategory) {
					case AppConstants.FILE_FORMAT_PDF:
						transLog.info("[Executor] Start PDF processing");
						try {
							vr = PdfFileValidator.isSafe(fileBytes);
						}catch(Exception ex) {
							transLog.info("Failed to validate PDF");
						}
						transLog.info(vr.isSafe()+"");
						finishHandle = vr.isSafe();
						transLog.info("[Executor] End of PDF processing");
						if(finishHandle) break;
						continue;
					case AppConstants.FILE_CATEGORY_IMAGE:
						transLog.info("[Executor] Start image processing");
						try {
							sr = new SanitizerResult();
							String msg = null;
							ImageMetadata imageMetadata = ImageExtractor.getImageMetadata(fileBytes);
							if(imageMetadata == null) {
								sr.setDiagnostic(DiagnosticFactory.fileFormatNotMatch("Failed to read image metadata!"));
								continue;
							}
							
							//validation
				        	boolean isFormatValid = false;
				        	for (String expectedFormat : expectedFileFormats) {
				        		if(imageMetadata.getFormatName().toLowerCase().equals(expectedFormat.toLowerCase())) {
				        			isFormatValid = true;
				        			break;
				        		}
							}
				        	
				        	if(!isFormatValid) {
				        		msg = String.format("Extracted file format is not matched with expected file format! (Extracted %s| Expected %s)", imageMetadata.getFormatName(), expectedFileFormats);
				        		sr.setDiagnostic(DiagnosticFactory.fileFormatNotMatch(msg));
				        		continue;
				        	}
				        	
				        	//sanitizing
				        	sr = ImageFileSanitizer.sanitizeImageFileContent(fileBytes, expectedFileFormats, imageMetadata);
				        	if(!sr.getDiagnostic().getDetectionCode().equals(DetectionCode.DC_CLEAN) || sr.getSanitizedData() == null) {
				        		continue;
				        	}
				        	
				        	//file contraint validation
				        	Diagnostic diagnostic = checkImageFileConstraint(fileConstraint, imageMetadata, fileBytes);
				        	if(!diagnostic.getDetectionCode().equals(DetectionCode.DC_CLEAN)) {
				        		sr.setDiagnostic(diagnostic);
				        		break;
				        	}
				        	
//				        	sr = ImageFileSanitizer.sanitizeImageFileContent(fileBytes, expectedFileFormats, imageMetadata);
				        	if(sr.getDiagnostic().getDetectionCode().equals(DetectionCode.DC_CLEAN)) finishHandle = true;
						} catch (Exception e) {
							transLog.info("Failed to sanitize image");
						}
						if(sr.getSanitizedData()!=null) finishHandle = true;
						transLog.info("[Executor] End of image processing");
						break;
					case AppConstants.FILE_CATEGORY_DOC_WORD:
//						try {
							//TODO GANTI KE VR RESPONSE
//							safeState = DocFileValidator.isSafe(bais);
//						}catch(Exception ex) {
//							
//						}
//						finishHandle = safeState;
//						break;
					case AppConstants.FILE_CATEGORY_DOC_EXCEL:
						//sanitizer method for doc excel
						break;
					}
				} else break;
			}
			
			if(!finishHandle) {
				if(vr == null || sr == null){
					er.getDiagnostic().setDetectionCode(DetectionCode.DC_FILE_FORMAT_NOT_MATCH);
					er.getDiagnostic().setMessage("File is mallicious or its file format is not expected!");
				} else if(vr!=null && vr.getDiagnostic().getDetectionCode().equals(DetectionCode.DC_FILE_FORMAT_NOT_MATCH) 
						&& (sr==null || sr.getDiagnostic().getDetectionCode().equals(DetectionCode.DC_FILE_FORMAT_NOT_MATCH))){
					er.getDiagnostic().setDetectionCode(DetectionCode.DC_FILE_FORMAT_NOT_MATCH);
					er.getDiagnostic().setMessage("File is mallicious or its file format is not expected!");
				} else if(sr != null && sr.getDiagnostic().getDetectionCode().equals(DetectionCode.DC_FILE_FORMAT_NOT_MATCH)
						&& (vr==null || vr.getDiagnostic().getDetectionCode().equals(DetectionCode.DC_FILE_FORMAT_NOT_MATCH))) {
					er.getDiagnostic().setDetectionCode(DetectionCode.DC_FILE_FORMAT_NOT_MATCH);
					er.getDiagnostic().setMessage("File is mallicious or its file format is not expected!");
				} else {
					if(vr!=null && !vr.getDiagnostic().getDetectionCode().equals(DetectionCode.DC_FILE_FORMAT_NOT_MATCH)){
						er.setDiagnostic(vr.getDiagnostic());
					} else {
						er.setDiagnostic(sr.getDiagnostic());
					}
				}
			} else {
				if(vr!=null && vr.getDiagnostic().getDetectionCode().equals(DetectionCode.DC_CLEAN)) {
					er.setData(fileBytes);
					er.setDiagnostic(vr.getDiagnostic());
				} else {
					er.setData(sr.getSanitizedData());
					er.setDiagnostic(sr.getDiagnostic());
				}
			}
			
		} finally {
			if(bais!=null) bais.close();
		}

		return er;
	}
	
	private Diagnostic checkImageFileConstraint(ImageFileConstraint fileConstraint, ImageMetadata imageMetadata, byte[] fileBytes) {
		Diagnostic diagnostic = new Diagnostic();
		String msg = null;
		
    	if(fileConstraint != null) {
    		if(fileConstraint.getMaxSizeInKb() != null || fileConstraint.getMinSizeInKb() != null) {
    			long maxSize = fileConstraint.getMaxSizeInKb() == null ? Long.MAX_VALUE : fileConstraint.getMaxSizeInKb();
    			long minSize = fileConstraint.getMinSizeInKb() == null ? 0 : fileConstraint.getMinSizeInKb();
    			try {
    				if(!CommonFileFValidator.checkFileBytesContentSizeInKB(fileBytes, minSize, maxSize)) {
						msg = String.format("File constraint violation. Min-max constraint: (%s) - (%s) KB | actual size: %s KB", 
								fileConstraint.getMinSizeInKb(), fileConstraint.getMaxSizeInKb(), fileBytes.length/1024);
						diagnostic.setMessage(msg);
						diagnostic.setDetectionCode(DetectionCode.DC_FILE_SIZE_CONSTRAINT_VIOLATION);
						return diagnostic;
    				}
				} catch (Exception e) {
					msg = e.getMessage();
					diagnostic.setMessage(msg);
					diagnostic.setDetectionCode(DetectionCode.DC_COMMON_INPUT_VIOLATION);
					e.printStackTrace();
					return diagnostic;
				}
    		}
    		
    		if(fileConstraint.getMaxHeightInPx() != null && fileConstraint.getMaxHeightInPx().compareTo(imageMetadata.getHeightInPx()) < 0) {
        		msg = String.format("Image height (%s) is more than height max constraint (%s)", imageMetadata.getHeightInPx(), fileConstraint.getMaxHeightInPx());
        		diagnostic.setMessage(msg);
				diagnostic.setDetectionCode(DetectionCode.DC_FILE_SIZE_CONSTRAINT_VIOLATION);
				return diagnostic;
        	}
    		if(fileConstraint.getMinHeightInPx() != null && fileConstraint.getMinHeightInPx().compareTo(imageMetadata.getHeightInPx()) > 0) {
    			msg = String.format("Image height (%s) is less than height min constraint (%s)", imageMetadata.getHeightInPx(), fileConstraint.getMinHeightInPx());
    			diagnostic.setMessage(msg);
				diagnostic.setDetectionCode(DetectionCode.DC_FILE_SIZE_CONSTRAINT_VIOLATION);
				return diagnostic;
    		}
    		if(fileConstraint.getMaxWidthInPx() != null && fileConstraint.getMaxWidthInPx().compareTo(imageMetadata.getWidthInPx()) < 0) {
    			msg = String.format("Image width (%s) is more than width max constraint (%s)", imageMetadata.getWidthInPx(), fileConstraint.getMaxWidthInPx());
    			diagnostic.setMessage(msg);
				diagnostic.setDetectionCode(DetectionCode.DC_FILE_SIZE_CONSTRAINT_VIOLATION);
				return diagnostic;
    		}
    		if(fileConstraint.getMinWidthInPx() != null && fileConstraint.getMinWidthInPx().compareTo(imageMetadata.getWidthInPx()) > 0) {
    			msg = String.format("Image width (%s) is less than width min constraint (%s)", imageMetadata.getWidthInPx(), fileConstraint.getMinWidthInPx());
    			diagnostic.setMessage(msg);
				diagnostic.setDetectionCode(DetectionCode.DC_FILE_SIZE_CONSTRAINT_VIOLATION);
				return diagnostic;
    		}
    	}
    	diagnostic.setDetectionCode(DetectionCode.DC_CLEAN);
    	return diagnostic;
	}
	
	private Diagnostic checkDocumentFileConstraint(DocumentFileConstraint fileConstraint, ImageMetadata imageMetadata, byte[] fileBytes) {
		Diagnostic diagnostic = new Diagnostic();
		String msg = null;
		
    	if(fileConstraint != null) {
    		if(fileConstraint.getMaxSizeInKb() != null || fileConstraint.getMinSizeInKb() != null) {
    			long maxSize = fileConstraint.getMaxSizeInKb() == null ? Long.MAX_VALUE : fileConstraint.getMaxSizeInKb();
    			long minSize = fileConstraint.getMinSizeInKb() == null ? 0 : fileConstraint.getMinSizeInKb();
    			try {
    				if(!CommonFileFValidator.checkFileBytesContentSizeInKB(fileBytes, minSize, maxSize)) {
						msg = String.format("File constraint violation. Min-max constraint: (%s) - (%s) KB | actual size: %s KB", 
								fileConstraint.getMinSizeInKb(), fileConstraint.getMaxSizeInKb(), fileBytes.length/1024);
						diagnostic.setMessage(msg);
						diagnostic.setDetectionCode(DetectionCode.DC_FILE_SIZE_CONSTRAINT_VIOLATION);
						return diagnostic;
    				}
				} catch (Exception e) {
					msg = e.getMessage();
					diagnostic.setMessage(msg);
					diagnostic.setDetectionCode(DetectionCode.DC_COMMON_INPUT_VIOLATION);
					e.printStackTrace();
					return diagnostic;
				}
    		}
    		
    	}
    	diagnostic.setDetectionCode(DetectionCode.DC_CLEAN);
    	return diagnostic;
	}
}
