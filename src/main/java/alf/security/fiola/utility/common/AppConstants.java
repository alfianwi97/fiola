package alf.security.fiola.utility.common;

import java.util.HashMap;
import java.util.Map;

public class AppConstants {
	public static final int MAX_FILENAME_LENGTH = 255;

	public static final String EXCEPTION_DAO_HEADER = "*********** DAO Error : \n";
	public static final String EXCEPTION_IMPL_HEADER = "*********** Impl Error : \n";
	public static final String EXCEPTION_PAGING_HEADER = "*********** Paging Error : \n";
	public static final String EXCEPTION_SVC_HEADER = "*********** Service Error : \n";

	public static final String FMT_DATE_DATETIME = "dd-MMM-yyyy HH:mm:ss";
	public static final String FMT_DATE_DATETIME_YYYYMMDD = "yyyy-MM-dd HH:mm:ss";
	public static final String FMT_DATE_DATEONLY_DDMMMYYYY = "dd-MMM-yyyy";
	public static final String FMT_DATE_DATEONLY_DDMMYYYY = "dd/MM/yyyy";
	public static final String FMT_DATE_DATEONLY_DDMMYYYY_V2 = "dd-MM-yyyy";
	public static final String FMT_DATE_DATEONLY_DDMMYYYY_V3 = "dd Month yyyy";
	public static final String FMT_DATE_DATEONLY_DDMMYYYY_V4 = "yyyy-mm-dd";


	public static final String FILENAME_VALID_REGEX_PATTERN = "[\\w!@#$%^&*(),{}`+~=\\[\\]-]+[\\w\\s!@#$%^&*(),{}`+~=\\[\\]-]*\\.[a-zA-Z0-9]+";
	public static final String FILENAME_STRICT_VALID_REGEX_PATTERN = "[\\w()+[]-]+[\\w\\s()+[]-]*\\.[a-zA-Z0-9]+";
	
	public static final String FILE_BASE64_HEADER_PATTERN = "data:[A-Za-z0-9]+/[A-Za-z0-9]+;base64,";
	
	// image
	public static final String FILE_FORMAT_IMAGE_JPEG = "jpeg";
	public static final String FILE_FORMAT_IMAGE_JPG = "jpg";
	public static final String FILE_FORMAT_IMAGE_PNG = "png";
	
	//pdf
	public static final String FILE_FORMAT_PDF = "pdf";
	// word
	public static final String FILE_FORMAT_DOC_DOC = "doc";
	public static final String FILE_FORMAT_DOC_DOCX = "docx";
	public static final String FILE_FORMAT_DOC_DOCM = "docm";
	public static final String FILE_FORMAT_DOC_WML = "wml";
	public static final String FILE_FORMAT_DOC_DOT = "dot";
	public static final String FILE_FORMAT_DOC_DOTM = "dotm";
	
	// excel
	
	
	public static final String[] FILE_FORMAT_ALL_LIST = {
		FILE_FORMAT_IMAGE_JPEG, FILE_FORMAT_IMAGE_JPG, FILE_FORMAT_IMAGE_PNG, FILE_FORMAT_PDF, FILE_FORMAT_DOC_DOC, FILE_FORMAT_DOC_DOCX, FILE_FORMAT_DOC_DOCM, FILE_FORMAT_DOC_WML, FILE_FORMAT_DOC_DOT, FILE_FORMAT_DOC_DOTM
	};
	public static final String[] FILE_FORMAT_IMAGES_LIST = {
		FILE_FORMAT_IMAGE_JPEG, FILE_FORMAT_IMAGE_JPG, FILE_FORMAT_IMAGE_PNG
	};
	public static final String[] FILE_FORMAT_DOCS_LIST = {
		FILE_FORMAT_DOC_DOC, FILE_FORMAT_DOC_DOCX, FILE_FORMAT_DOC_DOCM, FILE_FORMAT_DOC_WML, FILE_FORMAT_DOC_DOT, FILE_FORMAT_DOC_DOTM
	}; //FILE_FORMAT_PDF is special
	
	public static final String FILE_CATEGORY_IMAGE = "image_file_type";
	public static final String FILE_CATEGORY_DOC_WORD = "image_word_doc_type";
	public static final String FILE_CATEGORY_DOC_EXCEL = "image_excel_doc_type";
	
	
	//Ref : https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Complete_list_of_MIME_types
	@SuppressWarnings("serial")
	private static final Map<String, String> extensionAndMimeTypeMap = new HashMap<String, String>() {{
        put("gif", "image/gif");
        put("jpg", "image/jpeg");
        put("jpeg", "image/jpeg");
        put("png", "image/png");
        put("pdf", "application/pdf");
        put("doc", "application/msword");
        put("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
        put("xls", "application/vnd.ms-excel");
        put("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    }};
}
