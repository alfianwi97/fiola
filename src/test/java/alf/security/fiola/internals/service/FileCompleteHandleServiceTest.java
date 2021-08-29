package alf.security.fiola.internals.service;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.junit.Assert;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import alf.security.fiola.internals.model.apigw.v1.EaiOutputSchema;
import alf.security.fiola.internals.model.filecompletehandle.FileBase64CompleteHandleClientInput;
import alf.security.fiola.internals.model.filecompletehandle.FileBase64CompleteHandleRequest;
import alf.security.fiola.internals.model.filesanitizer.single.FileBase64OutputCompleteHandleResponse;
import alf.security.fiola.internals.model.filevalidator.FileConstraint;
import alf.security.fiola.internals.service.FileCompleteHandleService;
import alf.security.fiola.utility.code.diagnostic.detection.DetectionCode;

@SpringBootTest
public class FileCompleteHandleServiceTest {

    @Autowired
    private FileCompleteHandleService fileCompleteHandleService;
    
    @BeforeAll
    static void setup() {
        System.out.println("@BeforeAll");
    }
    
    private static File[] getResourceFolderFiles (String folder) {
    	ClassLoader loader = Thread.currentThread().getContextClassLoader();
    	URL url = loader.getResource(folder);
    	String path = url.getPath();
    	return new File(path).listFiles();
    }
    
    private String getFileExtension(String fullFilename) {
    	return fullFilename.substring(fullFilename.indexOf('.')+1);
    }
    private String getFilename(String fullFilename) {
    	return fullFilename.substring(0, fullFilename.indexOf('.'));
    }
    
    @DisplayName("Invalid Image Type Test")
	@Test
	public void invalidImageType() throws IOException {		
		for (File file : getResourceFolderFiles("file/invalid-extension")) {
			byte[] fileContent = FileUtils.readFileToByteArray(file);
			String dummyBase64 = Base64.getEncoder().encodeToString(fileContent);
			
			FileBase64CompleteHandleRequest request = new FileBase64CompleteHandleRequest();
			request.setFileClientInput(new FileBase64CompleteHandleClientInput());
			request.getFileClientInput().setFileName(getFilename(file.getName())+"."+getFileExtension(file.getName()));
		
			List<String> expectedFormats = new ArrayList<String>();
			expectedFormats.add(getFileExtension(file.getName()));
			request.getFileClientInput().setExpectedFileFormats(expectedFormats);
			
			request.getFileClientInput().setData(dummyBase64);
			
			
			EaiOutputSchema<FileBase64OutputCompleteHandleResponse> responseObject = fileCompleteHandleService.handleFileBase64ContentToBase64(request);
			Assert.assertEquals(DetectionCode.DC_FILE_FORMAT_NOT_MATCH, responseObject.getOutputSchema().getFileClientOutput().getDiagnostic().getDetectionCode());
			Assert.assertEquals(null, responseObject.getErrorSchema().getErrorCode());
		}
   }
	
    @DisplayName("Invalid Filename Test")
	@Test
	public void invalidFilename() throws IOException {
		Resource resource = new ClassPathResource("file/image/dummy.png");
	
		File file = resource.getFile();

		byte[] fileContent = FileUtils.readFileToByteArray(file);
		String dummyImageBase64 = Base64.getEncoder().encodeToString(fileContent);
		
		List<String> filenames = new ArrayList<>();
		filenames.add("");
		filenames.add("f.png.exe");
		filenames.add("fi/le.png");
		filenames.add("f");
		filenames.add("f\\.png");
		filenames.add("f:f.png");
		filenames.add("f?f.png");
		filenames.add("f|f.png`");
		filenames.add(".png");
		filenames.add("f. png");
		filenames.add("f.");
		filenames.add("<script>alert('done')</script>.png");
		filenames.add("\"><h1>test</h1>");
		filenames.add("'+alert(1)+'");
		filenames.add("“><img src=x onerror=prompt(“XSS”)>.jpg");
		filenames.add("\"><img src=x onerror=alert(document.cookie);.png");
		filenames.add("\"><svg onload=alert(1)>.png");
		filenames.add("{{constructor.constructor('alert(1)')()}}.png");
		filenames.add("{{[].pop.constructor&#40'alert\\u00281\\u0029'&#41&#40&#41}}.png");
		filenames.add("{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}.png");
		filenames.add("{{x=valueOf.name.constructor.fromCharCode;constructor.constructor(x(97,108,101,114,116,40,49,41))()}}");
		filenames.add("{{$on.constructor(\"var _ = document.createElement('script');_.src='//localhost/m';document.getElementsByTagName('body')[0].appendChild(_)\")()}}.png");
		filenames.add("{{a=\"a\"[\"constructor\"].prototype;a.charAt=a.trim;$eval('a\",eval(`var _=document\\\\x2ecreateElement(\\'script\\');_\\\\x2esrc=\\'//localhost/m\\';document\\\\x2ebody\\\\x2eappendChild(_);`),\"')}}.png");
		filenames.add("f\u0000.png");
		filenames.add("%00%00%00%00%00%3C%00%00%00s%00%00%00v%00%00%00g%00%00%00/%00%00%00o%00%00%00n%00%00%00l%00%00%00o%00%00%00a%00%00%00d%00%00%00=%00%00%00a%00%00%00l%00%00%00e%00%00%00r%00%00%00t%00%00%00(%00%00%00)%00%00%00%3E.png");
		filenames.add("<<script>alert('xss')<!--a-->a.png");
		
		for (String filename : filenames) {
			FileBase64CompleteHandleRequest request = new FileBase64CompleteHandleRequest();
			request.setFileClientInput(new FileBase64CompleteHandleClientInput());
			request.getFileClientInput().setFileName(filename);
		
			List<String> expectedFormats = new ArrayList<String>();
			expectedFormats.add("png");
			request.getFileClientInput().setExpectedFileFormats(expectedFormats);
			
			request.getFileClientInput().setData(dummyImageBase64);
			
			EaiOutputSchema<FileBase64OutputCompleteHandleResponse> responseObject = fileCompleteHandleService.handleFileBase64ContentToBase64(request);
			Assert.assertNotEquals(null, responseObject.getErrorSchema().getErrorCode());
			Assert.assertEquals(DetectionCode.DC_CONTAIN_MALLICIOUS_FILENAME, responseObject.getOutputSchema().getFileClientOutput().getDiagnostic().getDetectionCode());
		}
   }
	
    @DisplayName("Valid Filename Test")
	@Test
	public void validFilename() throws IOException {
		Resource resource = new ClassPathResource("file/image/dummy.png");
	
		File file = resource.getFile();

		byte[] fileContent = FileUtils.readFileToByteArray(file);
		String dummyImageBase64 = Base64.getEncoder().encodeToString(fileContent);
		
		List<String> filenames = new ArrayList<>();
		filenames.add(null);
		filenames.add("f.png");
		filenames.add("F.png");
		filenames.add("F1.png");
		filenames.add("123.png");
		filenames.add("_file_.png");
		filenames.add("f !.png");
		filenames.add("#-=.png");
		filenames.add("@f[{}].png");
		filenames.add("%.png");
		filenames.add("^.png");
		filenames.add("&.png");
		filenames.add("().png");
		filenames.add("_.png");
		filenames.add(",.png");
		filenames.add("+ -~ .png");
		filenames.add("` .png");
		
		for (String filename : filenames) {
			FileBase64CompleteHandleRequest request = new FileBase64CompleteHandleRequest();
			request.setFileClientInput(new FileBase64CompleteHandleClientInput());
			request.getFileClientInput().setFileName(filename);
		
			List<String> expectedFormats = new ArrayList<String>();
			expectedFormats.add("png");
			request.getFileClientInput().setExpectedFileFormats(expectedFormats);
			
			request.getFileClientInput().setData(dummyImageBase64);
			
			EaiOutputSchema<FileBase64OutputCompleteHandleResponse> responseObject = fileCompleteHandleService.handleFileBase64ContentToBase64(request);
			Assert.assertEquals(null,responseObject.getErrorSchema().getErrorCode());
			Assert.assertEquals(DetectionCode.DC_CLEAN, responseObject.getOutputSchema().getFileClientOutput().getDiagnostic().getDetectionCode());
			Assert.assertNotEquals(null,responseObject.getOutputSchema().getFileClientOutput().getData());
		}
   }
    
    @DisplayName("Valid File Base64 with Base64 header (IMAGE)")
	@Test
	public void validImageFileBase64WithBase64Header() throws IOException {
    	final String dummyImageBase64 = "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAFBQUFBVUFpkZFp9h3iHfbmqm5uquf/I18jXyP////////////////////////////////////////////////8BUFBQUFVQWmRkWn2HeId9uaqbm6q5/8jXyNfI///////////////////////////////////////////////////CABEIBQADiAMBIgACEQEDEQH/xAAZAAEBAAMBAAAAAAAAAAAAAAAABQECAwT/2gAIAQEAAAAA9QAAZAAAAAAAAyAAAAwAAAYAAGQAAAAMgAAAAAABgAADAADIAAAAAZAAAAAAADAAAYAAZAAAADIAAAAAAAAMAADAAGQAAAAZAAAAAAAAAYAAYABkAAAAZAAAAAAAAABgADAAZAAAAZAAAAAAAAAADAAYAGQAAAMgAAAAAAAAAAMADABkAAAGQAAAAAAAAAAAwAYAZAAADIAAAAAAAAAAABgDAGQAABkAAAAAAAAAAAAMAYBkAABkAAAAAAAAAAAAAwDAMgAGQAAAAAAAAAAAAADAYDIAGQAAAAAAAAAAAAAAMDAyAMgAAAAAAAAAAAAAAAwABkAAAAAAAAAAAAAAAAYADIAAAABk1ZyYAAAAAAAAABgAyAAAAAGdfPptnvuwAAAAAAAAAGABkAAAAAHh57b529OXDTbvrwbd+PbIAAAAAAAMAMgAAAAA5+Hp7s+bl378Md+fLrp34tO/Pfl6OboAAAAAAAYGQAAAAAOXj9HqcvH39Xm67vJ35dOfTnvp6fJ6+TqAAAAAAAYMgAAAAANfFn158enr78M9OGvbll6PM37eT18nUAAAAAAAwZAAAAAAy8/HGjf27a+Zr06ad/L349/P356Y7dQAAAAAAAAAAAAAMnLmzp6N8AAAAAAAAAAAAAAAAAZAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGm+Q5b5MuXU0bmDXYAAAAAAAAAAAAADPPG/PZvplrkxh00M4NmwAAAAAAAAAAAAADUxuzg1yxnGdtcMsZMgAAAAAAAAAAAAADIAAAAwAAAAAAAAAAAAAGQAAAADAAAAAAAAAAAAAMgAAAAAYAAAAAAAAAAAAGQAAAAAMAAAAAAAAAAAAMjkzy3wx24b5abtDbVvo3z0AGAAAAAAAAAAA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";
		final List<String> expectedFormats = new ArrayList<>();
		expectedFormats.add("jpeg");
		
		final List<String> expectedFormats2 = new ArrayList<>();
		expectedFormats2.add("jpeg");
		expectedFormats2.add("pdf");
		
		final List<String> unexpectedFormats = new ArrayList<>();
		unexpectedFormats.add("pdf");
		
		final List<String> unexpectedFormats2 = new ArrayList<>();
		unexpectedFormats2.add("pdf");
		unexpectedFormats2.add("png");
		
    	
		List<FileBase64CompleteHandleRequest> requests = new ArrayList<FileBase64CompleteHandleRequest>();
		
		//with name
		FileBase64CompleteHandleRequest req1 = new FileBase64CompleteHandleRequest();
		FileBase64CompleteHandleClientInput fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyImageBase64);
		fci.setFileName("file.jpeg");
		fci.setExpectedFileFormats(expectedFormats);
		req1.setFileClientInput(fci);
		requests.add(req1);
		
		//without filename
		FileBase64CompleteHandleRequest req2 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyImageBase64);
		fci.setExpectedFileFormats(expectedFormats);
		req2.setFileClientInput(fci);
		requests.add(req2);
		
		//with name + expected formats 1
		FileBase64CompleteHandleRequest req3 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyImageBase64);
		fci.setFileName("file.jpeg");
		fci.setExpectedFileFormats(expectedFormats2);
		req3.setFileClientInput(fci);
		requests.add(req3);
		
		//without filename + expected formats 2
		FileBase64CompleteHandleRequest req4 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyImageBase64);
		fci.setExpectedFileFormats(expectedFormats2);
		req4.setFileClientInput(fci);
		requests.add(req4);
		
		for (FileBase64CompleteHandleRequest request : requests) {
			EaiOutputSchema<FileBase64OutputCompleteHandleResponse> responseObject = fileCompleteHandleService.handleFileBase64ContentToBase64(request);
			Assert.assertEquals(null,responseObject.getErrorSchema().getErrorCode());
			Assert.assertEquals(DetectionCode.DC_CLEAN,responseObject.getOutputSchema().getFileClientOutput().getDiagnostic().getDetectionCode());
			Assert.assertNotEquals(null,responseObject.getOutputSchema().getFileClientOutput().getData());
		}
   }
    
	@DisplayName("Valid File Base64 with Base64 header (PDF)")
	@Test
	public void validPdfFileBase64WithBase64Header() throws IOException {
		Resource resource = new ClassPathResource("file/pdf/file.pdf");
		
		File file = resource.getFile();

		byte[] fileContent = FileUtils.readFileToByteArray(file);
		String dummyImageBase64 = "data:application/pdf;base64,"+Base64.getEncoder().encodeToString(fileContent);
		
		final List<String> expectedFormats = new ArrayList<>();
		expectedFormats.add("pdf");
		
		final List<String> expectedFormats2 = new ArrayList<>();
		expectedFormats2.add("jpeg");
		expectedFormats2.add("pdf");
		
		final List<String> unexpectedFormats = new ArrayList<>();
		unexpectedFormats.add("jpg");
		
		
		List<FileBase64CompleteHandleRequest> requests = new ArrayList<FileBase64CompleteHandleRequest>();
		
		//with name
		FileBase64CompleteHandleRequest req1 = new FileBase64CompleteHandleRequest();
		FileBase64CompleteHandleClientInput fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyImageBase64);
		fci.setFileName("file.pdf");
		fci.setExpectedFileFormats(expectedFormats);
		req1.setFileClientInput(fci);
		requests.add(req1);
		
		//without filename
		FileBase64CompleteHandleRequest req2 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyImageBase64);
		fci.setExpectedFileFormats(expectedFormats);
		req2.setFileClientInput(fci);
		requests.add(req2);
		
		//with name + expected formats 1
		FileBase64CompleteHandleRequest req3 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyImageBase64);
		fci.setFileName("file.pdf");
		fci.setExpectedFileFormats(expectedFormats2);
		req3.setFileClientInput(fci);
		requests.add(req3);
		
		//without filename + expected formats 2
		FileBase64CompleteHandleRequest req4 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyImageBase64);
		fci.setExpectedFileFormats(expectedFormats2);
		req4.setFileClientInput(fci);
		requests.add(req4);
			
		for (FileBase64CompleteHandleRequest request : requests) {
			EaiOutputSchema<FileBase64OutputCompleteHandleResponse> responseObject = fileCompleteHandleService.handleFileBase64ContentToBase64(request);
			Assert.assertEquals(null,responseObject.getErrorSchema().getErrorCode());
			Assert.assertEquals(DetectionCode.DC_CLEAN,responseObject.getOutputSchema().getFileClientOutput().getDiagnostic().getDetectionCode());
			Assert.assertNotEquals(null,responseObject.getOutputSchema().getFileClientOutput().getData());
		}
   }
    
    @DisplayName("Valid File Base64 without Base64 header (IMAGE)")
	@Test
	public void validImageFileBase64WithoutBase64Header() throws IOException {
    	final String dummyImageBase64 = "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAFBQUFBVUFpkZFp9h3iHfbmqm5uquf/I18jXyP////////////////////////////////////////////////8BUFBQUFVQWmRkWn2HeId9uaqbm6q5/8jXyNfI///////////////////////////////////////////////////CABEIBQADiAMBIgACEQEDEQH/xAAZAAEBAAMBAAAAAAAAAAAAAAAABQECAwT/2gAIAQEAAAAA9QAAZAAAAAAAAyAAAAwAAAYAAGQAAAAMgAAAAAABgAADAADIAAAAAZAAAAAAADAAAYAAZAAAADIAAAAAAAAMAADAAGQAAAAZAAAAAAAAAYAAYABkAAAAZAAAAAAAAABgADAAZAAAAZAAAAAAAAAADAAYAGQAAAMgAAAAAAAAAAMADABkAAAGQAAAAAAAAAAAwAYAZAAADIAAAAAAAAAAABgDAGQAABkAAAAAAAAAAAAMAYBkAABkAAAAAAAAAAAAAwDAMgAGQAAAAAAAAAAAAADAYDIAGQAAAAAAAAAAAAAAMDAyAMgAAAAAAAAAAAAAAAwABkAAAAAAAAAAAAAAAAYADIAAAABk1ZyYAAAAAAAAABgAyAAAAAGdfPptnvuwAAAAAAAAAGABkAAAAAHh57b529OXDTbvrwbd+PbIAAAAAAAMAMgAAAAA5+Hp7s+bl378Md+fLrp34tO/Pfl6OboAAAAAAAYGQAAAAAOXj9HqcvH39Xm67vJ35dOfTnvp6fJ6+TqAAAAAAAYMgAAAAANfFn158enr78M9OGvbll6PM37eT18nUAAAAAAAwZAAAAAAy8/HGjf27a+Zr06ad/L349/P356Y7dQAAAAAAAAAAAAAMnLmzp6N8AAAAAAAAAAAAAAAAAZAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGm+Q5b5MuXU0bmDXYAAAAAAAAAAAAADPPG/PZvplrkxh00M4NmwAAAAAAAAAAAAADUxuzg1yxnGdtcMsZMgAAAAAAAAAAAAADIAAAAwAAAAAAAAAAAAAGQAAAADAAAAAAAAAAAAAMgAAAAAYAAAAAAAAAAAAGQAAAAAMAAAAAAAAAAAAMjkzy3wx24b5abtDbVvo3z0AGAAAAAAAAAAA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";
		final List<String> expectedFormats = new ArrayList<>();
		expectedFormats.add("jpeg");
		
		final List<String> expectedFormats2 = new ArrayList<>();
		expectedFormats2.add("pdf");
		expectedFormats2.add("jpeg");
		

		List<FileBase64CompleteHandleRequest> requests = new ArrayList<FileBase64CompleteHandleRequest>();
		
		//with name
		FileBase64CompleteHandleRequest req1 = new FileBase64CompleteHandleRequest();
		FileBase64CompleteHandleClientInput fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyImageBase64);
		fci.setFileName("file.jpeg");
		fci.setExpectedFileFormats(expectedFormats);
		req1.setFileClientInput(fci);
		requests.add(req1);
		
		//without filename
		FileBase64CompleteHandleRequest req2 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyImageBase64);
		fci.setExpectedFileFormats(expectedFormats);
		req2.setFileClientInput(fci);
		requests.add(req2);
		
		//with name + expected formats 1
		FileBase64CompleteHandleRequest req3 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyImageBase64);
		fci.setFileName("file.jpeg");
		fci.setExpectedFileFormats(expectedFormats2);
		req3.setFileClientInput(fci);
		requests.add(req3);
		
		//without filename + expected formats 2
		FileBase64CompleteHandleRequest req4 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyImageBase64);
		fci.setExpectedFileFormats(expectedFormats2);
		req4.setFileClientInput(fci);
		requests.add(req4);
		
		for (FileBase64CompleteHandleRequest request : requests) {
			EaiOutputSchema<FileBase64OutputCompleteHandleResponse> responseObject = fileCompleteHandleService.handleFileBase64ContentToBase64(request);
			Assert.assertEquals(null,responseObject.getErrorSchema().getErrorCode());
			Assert.assertEquals(DetectionCode.DC_CLEAN,responseObject.getOutputSchema().getFileClientOutput().getDiagnostic().getDetectionCode());
			Assert.assertNotEquals(null,responseObject.getOutputSchema().getFileClientOutput().getData());
		}
   }
    
    @DisplayName("Valid File Base64 without Base64 header (PDF)")
	@Test
	public void validPdfFileBase64WithoutBase64Header() throws IOException {
		Resource resource = new ClassPathResource("file/pdf/file.pdf");
		
		File file = resource.getFile();

		byte[] fileContent = FileUtils.readFileToByteArray(file);
		String dummyBase64 = Base64.getEncoder().encodeToString(fileContent);
		
		final List<String> expectedFormats = new ArrayList<>();
		expectedFormats.add("pdf");
		
		final List<String> expectedFormats2 = new ArrayList<>();
		expectedFormats2.add("jpeg");
		expectedFormats2.add("pdf");
		
		
		List<FileBase64CompleteHandleRequest> requests = new ArrayList<FileBase64CompleteHandleRequest>();
		
		//with name
		FileBase64CompleteHandleRequest req1 = new FileBase64CompleteHandleRequest();
		FileBase64CompleteHandleClientInput fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyBase64);
		fci.setFileName("file.pdf");
		fci.setExpectedFileFormats(expectedFormats);
		req1.setFileClientInput(fci);
		requests.add(req1);
		
		//without filename
		FileBase64CompleteHandleRequest req2 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyBase64);
		fci.setExpectedFileFormats(expectedFormats);
		req2.setFileClientInput(fci);
		requests.add(req2);
		
		//with name + expected formats 1
		FileBase64CompleteHandleRequest req3 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyBase64);
		fci.setFileName("file.pdf");
		fci.setExpectedFileFormats(expectedFormats2);
		req3.setFileClientInput(fci);
		requests.add(req3);
		
		//without filename + expected formats 2
		FileBase64CompleteHandleRequest req4 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyBase64);
		fci.setExpectedFileFormats(expectedFormats2);
		req4.setFileClientInput(fci);
		requests.add(req4);
			
		for (FileBase64CompleteHandleRequest request : requests) {
			EaiOutputSchema<FileBase64OutputCompleteHandleResponse> responseObject = fileCompleteHandleService.handleFileBase64ContentToBase64(request);
			Assert.assertEquals(null,responseObject.getErrorSchema().getErrorCode());
			Assert.assertEquals(DetectionCode.DC_CLEAN,responseObject.getOutputSchema().getFileClientOutput().getDiagnostic().getDetectionCode());
			Assert.assertNotEquals(null,responseObject.getOutputSchema().getFileClientOutput().getData());
		}
   }
    
    
    @DisplayName("Invalid File Base64 with Base64 header (IMAGE)")
	@Test
	public void invalidFileBase64WithBase64Header() throws IOException {
    	final String dummyImageBase64 = "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAFBQUFBVUFpkZFp9h3iHfbmqm5uquf/I18jXyP////////////////////////////////////////////////8BUFBQUFVQWmRkWn2HeId9uaqbm6q5/8jXyNfI///////////////////////////////////////////////////CABEIBQADiAMBIgACEQEDEQH/xAAZAAEBAAMBAAAAAAAAAAAAAAAABQECAwT/2gAIAQEAAAAA9QAAZAAAAAAAAyAAAAwAAAYAAGQAAAAMgAAAAAABgAADAADIAAAAAZAAAAAAADAAAYAAZAAAADIAAAAAAAAMAADAAGQAAAAZAAAAAAAAAYAAYABkAAAAZAAAAAAAAABgADAAZAAAAZAAAAAAAAAADAAYAGQAAAMgAAAAAAAAAAMADABkAAAGQAAAAAAAAAAAwAYAZAAADIAAAAAAAAAAABgDAGQAABkAAAAAAAAAAAAMAYBkAABkAAAAAAAAAAAAAwDAMgAGQAAAAAAAAAAAAADAYDIAGQAAAAAAAAAAAAAAMDAyAMgAAAAAAAAAAAAAAAwABkAAAAAAAAAAAAAAAAYADIAAAABk1ZyYAAAAAAAAABgAyAAAAAGdfPptnvuwAAAAAAAAAGABkAAAAAHh57b529OXDTbvrwbd+PbIAAAAAAAMAMgAAAAA5+Hp7s+bl378Md+fLrp34tO/Pfl6OboAAAAAAAYGQAAAAAOXj9HqcvH39Xm67vJ35dOfTnvp6fJ6+TqAAAAAAAYMgAAAAANfFn158enr78M9OGvbll6PM37eT18nUAAAAAAAwZAAAAAAy8/HGjf27a+Zr06ad/L349/P356Y7dQAAAAAAAAAAAAAMnLmzp6N8AAAAAAAAAAAAAAAAAZAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGm+Q5b5MuXU0bmDXYAAAAAAAAAAAAADPPG/PZvplrkxh00M4NmwAAAAAAAAAAAAADUxuzg1yxnGdtcMsZMgAAAAAAAAAAAAADIAAAAwAAAAAAAAAAAAAGQAAAADAAAAAAAAAAAAAMgAAAAAYAAAAAAAAAAAAGQAAAAAMAAAAAAAAAAAAMjkzy3wx24b5abtDbVvo3z0AGAAAAAAAAAAA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";
		
		final List<String> unexpectedFormats = new ArrayList<>();
		unexpectedFormats.add("pdf");
		
		final List<String> unexpectedFormats2 = new ArrayList<>();
		unexpectedFormats2.add("pdf");
		unexpectedFormats2.add("png");
		
    	
		List<FileBase64CompleteHandleRequest> requests = new ArrayList<FileBase64CompleteHandleRequest>();
		
		//with name
		FileBase64CompleteHandleRequest req1 = new FileBase64CompleteHandleRequest();
		FileBase64CompleteHandleClientInput fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyImageBase64);
		fci.setFileName("file.pdf");
		fci.setExpectedFileFormats(unexpectedFormats);
		req1.setFileClientInput(fci);
		requests.add(req1);
		
		//without filename
		FileBase64CompleteHandleRequest req2 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyImageBase64);
		fci.setExpectedFileFormats(unexpectedFormats);
		req2.setFileClientInput(fci);
		requests.add(req2);
		
		//with name + expected formats 1
		FileBase64CompleteHandleRequest req3 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyImageBase64);
		fci.setFileName("file.pdf");
		fci.setExpectedFileFormats(unexpectedFormats2);
		req3.setFileClientInput(fci);
		requests.add(req3);
		
		//without filename + expected formats 2
		FileBase64CompleteHandleRequest req4 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyImageBase64);
		fci.setExpectedFileFormats(unexpectedFormats2);
		req4.setFileClientInput(fci);
		requests.add(req4);
		
		for (FileBase64CompleteHandleRequest request : requests) {
			EaiOutputSchema<FileBase64OutputCompleteHandleResponse> responseObject = fileCompleteHandleService.handleFileBase64ContentToBase64(request);
			Assert.assertNotEquals(null,responseObject.getErrorSchema().getErrorCode());	//TODO SPECIFY MORE DETAIL
			Assert.assertEquals(DetectionCode.DC_FILE_FORMAT_NOT_MATCH, responseObject.getOutputSchema().getFileClientOutput().getDiagnostic().getDetectionCode());	//TODO SPECIFY MORE DETAIL
			Assert.assertEquals(null,responseObject.getOutputSchema().getFileClientOutput().getData());
		}
   }
    
    @DisplayName("Invalid File Base64 without Base64 header (IMAGE)")
	@Test
	public void invalidFileBase64WithoutBase64Header() throws IOException {
    	final String dummyImageBase64 = "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAFBQUFBVUFpkZFp9h3iHfbmqm5uquf/I18jXyP////////////////////////////////////////////////8BUFBQUFVQWmRkWn2HeId9uaqbm6q5/8jXyNfI///////////////////////////////////////////////////CABEIBQADiAMBIgACEQEDEQH/xAAZAAEBAAMBAAAAAAAAAAAAAAAABQECAwT/2gAIAQEAAAAA9QAAZAAAAAAAAyAAAAwAAAYAAGQAAAAMgAAAAAABgAADAADIAAAAAZAAAAAAADAAAYAAZAAAADIAAAAAAAAMAADAAGQAAAAZAAAAAAAAAYAAYABkAAAAZAAAAAAAAABgADAAZAAAAZAAAAAAAAAADAAYAGQAAAMgAAAAAAAAAAMADABkAAAGQAAAAAAAAAAAwAYAZAAADIAAAAAAAAAAABgDAGQAABkAAAAAAAAAAAAMAYBkAABkAAAAAAAAAAAAAwDAMgAGQAAAAAAAAAAAAADAYDIAGQAAAAAAAAAAAAAAMDAyAMgAAAAAAAAAAAAAAAwABkAAAAAAAAAAAAAAAAYADIAAAABk1ZyYAAAAAAAAABgAyAAAAAGdfPptnvuwAAAAAAAAAGABkAAAAAHh57b529OXDTbvrwbd+PbIAAAAAAAMAMgAAAAA5+Hp7s+bl378Md+fLrp34tO/Pfl6OboAAAAAAAYGQAAAAAOXj9HqcvH39Xm67vJ35dOfTnvp6fJ6+TqAAAAAAAYMgAAAAANfFn158enr78M9OGvbll6PM37eT18nUAAAAAAAwZAAAAAAy8/HGjf27a+Zr06ad/L349/P356Y7dQAAAAAAAAAAAAAMnLmzp6N8AAAAAAAAAAAAAAAAAZAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGm+Q5b5MuXU0bmDXYAAAAAAAAAAAAADPPG/PZvplrkxh00M4NmwAAAAAAAAAAAAADUxuzg1yxnGdtcMsZMgAAAAAAAAAAAAADIAAAAwAAAAAAAAAAAAAGQAAAADAAAAAAAAAAAAAMgAAAAAYAAAAAAAAAAAAGQAAAAAMAAAAAAAAAAAAMjkzy3wx24b5abtDbVvo3z0AGAAAAAAAAAAA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";
		
		final List<String> unexpectedFormats = new ArrayList<>();
		unexpectedFormats.add("pdf");
		
		final List<String> unexpectedFormats2 = new ArrayList<>();
		unexpectedFormats2.add("pdf");
		unexpectedFormats2.add("png");
		
    	
		List<FileBase64CompleteHandleRequest> requests = new ArrayList<FileBase64CompleteHandleRequest>();
		
		//with name
		FileBase64CompleteHandleRequest req1 = new FileBase64CompleteHandleRequest();
		FileBase64CompleteHandleClientInput fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyImageBase64);
		fci.setFileName("file.jpeg");
		fci.setExpectedFileFormats(unexpectedFormats);
		req1.setFileClientInput(fci);
		requests.add(req1);
		
		//without filename
		FileBase64CompleteHandleRequest req2 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyImageBase64);
		fci.setExpectedFileFormats(unexpectedFormats);
		req2.setFileClientInput(fci);
		requests.add(req2);
		
		//with name + expected formats 1
		FileBase64CompleteHandleRequest req3 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyImageBase64);
		fci.setFileName("file.pdf");
		fci.setExpectedFileFormats(unexpectedFormats2);
		req3.setFileClientInput(fci);
		requests.add(req3);
		
		//without filename + expected formats 2
		FileBase64CompleteHandleRequest req4 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fci.setData(dummyImageBase64);
		fci.setExpectedFileFormats(unexpectedFormats2);
		req4.setFileClientInput(fci);
		requests.add(req4);
		
		for (FileBase64CompleteHandleRequest request : requests) {
			EaiOutputSchema<FileBase64OutputCompleteHandleResponse> responseObject = fileCompleteHandleService.handleFileBase64ContentToBase64(request);
//			Assert.assertNotEquals(null,responseObject.getErrorSchema().getErrorCode());	//TODO SPECIFY MORE DETAIL
			Assert.assertNotEquals(DetectionCode.DC_CLEAN,responseObject.getOutputSchema().getFileClientOutput().getDiagnostic().getDetectionCode());	//TODO SPECIFY MORE DETAIL
			Assert.assertEquals(null,responseObject.getOutputSchema().getFileClientOutput().getData());
		}
   }
    

    @DisplayName("File Constraint Test (Image Max Height and Width)")
	@Test
	public void validImageFileConstraintMaxHeightAndWidthTest() throws IOException {
    	Resource resource = new ClassPathResource("file/file-constraint/600x800-164kb.jpg");
    	
		File file = resource.getFile();

		byte[] fileContent = FileUtils.readFileToByteArray(file);
		String dummyBase64 = Base64.getEncoder().encodeToString(fileContent);
		
		final String filename = "file.jpeg";
		
		final List<String> expectedFormats = new ArrayList<>();
		expectedFormats.add("jpeg");
		
		final List<String> expectedFormats2 = new ArrayList<>();
		expectedFormats2.add("pdf");
		expectedFormats2.add("jpeg");
		
    	
		List<FileBase64CompleteHandleRequest> requests = new ArrayList<FileBase64CompleteHandleRequest>();
		
		//with name
		FileBase64CompleteHandleRequest req1 = new FileBase64CompleteHandleRequest();
		FileBase64CompleteHandleClientInput fci = new FileBase64CompleteHandleClientInput();
		FileConstraint fc = new FileConstraint();
		fc.setMaxWidthInPx(600);
		fc.setMaxWidthInPx(800);
		fci.setFileConstraint(fc);
		fci.setData(dummyBase64);
		fci.setFileName(filename);
		fci.setExpectedFileFormats(expectedFormats);
		req1.setFileClientInput(fci);
		requests.add(req1);
		
		//without filename
		FileBase64CompleteHandleRequest req2 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fc = new FileConstraint();
		fc.setMaxWidthInPx(1000);
		fc.setMaxWidthInPx(1000);
		fci.setFileConstraint(fc);
		fci.setData(dummyBase64);
		fci.setExpectedFileFormats(expectedFormats);
		req2.setFileClientInput(fci);
		requests.add(req2);
		
		//with name + expected formats 1
		FileBase64CompleteHandleRequest req3 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fc = new FileConstraint();
		fc.setMaxWidthInPx(600);
		fc.setMaxWidthInPx(800);
		fci.setFileConstraint(fc);
		fci.setData(dummyBase64);
		fci.setFileName(filename);
		fci.setExpectedFileFormats(expectedFormats2);
		req3.setFileClientInput(fci);
		requests.add(req3);
		
		//without filename + expected formats 2
		FileBase64CompleteHandleRequest req4 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fc = new FileConstraint();
		fc.setMaxWidthInPx(1000);
		fc.setMaxWidthInPx(1000);
		fci.setFileConstraint(fc);
		fci.setData(dummyBase64);
		fci.setExpectedFileFormats(expectedFormats2);
		req4.setFileClientInput(fci);
		requests.add(req4);
		
		for (FileBase64CompleteHandleRequest request : requests) {
			EaiOutputSchema<FileBase64OutputCompleteHandleResponse> responseObject = fileCompleteHandleService.handleFileBase64ContentToBase64(request);
			Assert.assertEquals(null,responseObject.getErrorSchema().getErrorCode());
			Assert.assertEquals(DetectionCode.DC_CLEAN,responseObject.getOutputSchema().getFileClientOutput().getDiagnostic().getDetectionCode());
			Assert.assertNotEquals(null,responseObject.getOutputSchema().getFileClientOutput().getData());
		}
    }
    
    @DisplayName("File Constraint Test (Image Min Width and Height)")
	@Test
	public void validImageFileConstraintMinHeightAndWidthTest() throws IOException {
		Resource resource = new ClassPathResource("file/file-constraint/600x800-164kb.jpg");
		
		File file = resource.getFile();
	
		byte[] fileContent = FileUtils.readFileToByteArray(file);
		String dummyBase64 = Base64.getEncoder().encodeToString(fileContent);
		
		final String filename = "file.jpeg";
		
		final List<String> expectedFormats = new ArrayList<>();
		expectedFormats.add("jpeg");
		
		final List<String> expectedFormats2 = new ArrayList<>();
		expectedFormats2.add("pdf");
		expectedFormats2.add("jpeg");
		
		
		List<FileBase64CompleteHandleRequest> requests = new ArrayList<FileBase64CompleteHandleRequest>();
		
		//with name
		FileBase64CompleteHandleRequest req1 = new FileBase64CompleteHandleRequest();
		FileBase64CompleteHandleClientInput fci = new FileBase64CompleteHandleClientInput();
		FileConstraint fc = new FileConstraint();
		fc.setMaxWidthInPx(600);
		fc.setMaxHeightInPx(800);
		fc.setMinWidthInPx(600);
		fc.setMinHeightInPx(800);
		fc.setMaxSizeInKb(165L);
		fci.setFileConstraint(fc);
		fci.setData(dummyBase64);
		fci.setFileName(filename);
		fci.setExpectedFileFormats(expectedFormats);
		req1.setFileClientInput(fci);
		requests.add(req1);
		
		//without filename
		FileBase64CompleteHandleRequest req2 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fc = new FileConstraint();
		fc.setMaxWidthInPx(600);
		fc.setMaxHeightInPx(800);
		fc.setMinWidthInPx(500);
		fc.setMinHeightInPx(500);
		fc.setMaxSizeInKb(165L);
		fci.setFileConstraint(fc);
		fci.setData(dummyBase64);
		fci.setExpectedFileFormats(expectedFormats);
		req2.setFileClientInput(fci);
		requests.add(req2);
		
		//with name + expected formats 1
		FileBase64CompleteHandleRequest req3 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fc = new FileConstraint();
		fc.setMaxWidthInPx(600);
		fc.setMaxHeightInPx(800);
		fc.setMinWidthInPx(600);
		fc.setMinHeightInPx(800);
		fc.setMaxSizeInKb(165L);
		fci.setFileConstraint(fc);
		fci.setData(dummyBase64);
		fci.setFileName(filename);
		fci.setExpectedFileFormats(expectedFormats2);
		req3.setFileClientInput(fci);
		requests.add(req3);
		
		//without filename + expected formats 2
		FileBase64CompleteHandleRequest req4 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fc = new FileConstraint();
		fc.setMaxWidthInPx(600);
		fc.setMaxHeightInPx(800);
		fc.setMinWidthInPx(500);
		fc.setMinHeightInPx(500);
		fc.setMaxSizeInKb(165L);
		fci.setFileConstraint(fc);
		fci.setData(dummyBase64);
		fci.setExpectedFileFormats(expectedFormats2);
		req4.setFileClientInput(fci);
		requests.add(req4);
		
		for (FileBase64CompleteHandleRequest request : requests) {
			EaiOutputSchema<FileBase64OutputCompleteHandleResponse> responseObject = fileCompleteHandleService.handleFileBase64ContentToBase64(request);
			Assert.assertEquals(null,responseObject.getErrorSchema().getErrorCode());
			Assert.assertEquals(DetectionCode.DC_CLEAN,responseObject.getOutputSchema().getFileClientOutput().getDiagnostic().getDetectionCode());
			Assert.assertNotEquals(null,responseObject.getOutputSchema().getFileClientOutput().getData());
		}
	}

	@DisplayName("File Constraint Test (Image Max Size)")
	@Test
	public void validImageFileConstraintMaxSizeTest() throws IOException {
    	Resource resource = new ClassPathResource("file/file-constraint/600x800-164kb.jpg");
    	
		File file = resource.getFile();

		byte[] fileContent = FileUtils.readFileToByteArray(file);
		String dummyBase64 = Base64.getEncoder().encodeToString(fileContent);
		
		final String filename = "file.jpeg";
		
		final List<String> expectedFormats = new ArrayList<>();
		expectedFormats.add("jpeg");
		
		final List<String> expectedFormats2 = new ArrayList<>();
		expectedFormats2.add("pdf");
		expectedFormats2.add("jpeg");
		
    	
		List<FileBase64CompleteHandleRequest> requests = new ArrayList<FileBase64CompleteHandleRequest>();
		
		//with name
		FileBase64CompleteHandleRequest req1 = new FileBase64CompleteHandleRequest();
		FileBase64CompleteHandleClientInput fci = new FileBase64CompleteHandleClientInput();
		FileConstraint fc = new FileConstraint();
		fc.setMaxWidthInPx(600);
		fc.setMaxWidthInPx(800);
		fc.setMaxSizeInKb(165L);
		fci.setFileConstraint(fc);
		fci.setData(dummyBase64);
		fci.setFileName(filename);
		fci.setExpectedFileFormats(expectedFormats);
		req1.setFileClientInput(fci);
		requests.add(req1);
		
		//without filename
		FileBase64CompleteHandleRequest req2 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fc = new FileConstraint();
		fc.setMaxWidthInPx(1000);
		fc.setMaxWidthInPx(1000);
		fc.setMaxSizeInKb(165L);
		fci.setFileConstraint(fc);
		fci.setData(dummyBase64);
		fci.setExpectedFileFormats(expectedFormats);
		req2.setFileClientInput(fci);
		requests.add(req2);
		
		//with name + expected formats 1
		FileBase64CompleteHandleRequest req3 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fc = new FileConstraint();
		fc.setMaxWidthInPx(600);
		fc.setMaxWidthInPx(800);
		fc.setMaxSizeInKb(165L);
		fci.setFileConstraint(fc);
		fci.setData(dummyBase64);
		fci.setFileName(filename);
		fci.setExpectedFileFormats(expectedFormats2);
		req3.setFileClientInput(fci);
		requests.add(req3);
		
		//without filename + expected formats 2
		FileBase64CompleteHandleRequest req4 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fc = new FileConstraint();
		fc.setMaxWidthInPx(1000);
		fc.setMaxWidthInPx(1000);
		fc.setMaxSizeInKb(165L);
		fci.setFileConstraint(fc);
		fci.setData(dummyBase64);
		fci.setExpectedFileFormats(expectedFormats2);
		req4.setFileClientInput(fci);
		requests.add(req4);
		
		for (FileBase64CompleteHandleRequest request : requests) {
			EaiOutputSchema<FileBase64OutputCompleteHandleResponse> responseObject = fileCompleteHandleService.handleFileBase64ContentToBase64(request);
			Assert.assertEquals(null,responseObject.getErrorSchema().getErrorCode());
			Assert.assertEquals(DetectionCode.DC_CLEAN,responseObject.getOutputSchema().getFileClientOutput().getDiagnostic().getDetectionCode());
			Assert.assertNotEquals(null,responseObject.getOutputSchema().getFileClientOutput().getData());
		}
    }
    
    @DisplayName("File Constraint Test (Image Min Width and Height)")
	@Test
	public void validImageFileConstraintMinSizeTest() throws IOException {
    	Resource resource = new ClassPathResource("file/file-constraint/600x800-164kb.jpg");
    	
		File file = resource.getFile();

		byte[] fileContent = FileUtils.readFileToByteArray(file);
		String dummyBase64 = Base64.getEncoder().encodeToString(fileContent);
		
		final String filename = "file.jpeg";
		
		final List<String> expectedFormats = new ArrayList<>();
		expectedFormats.add("jpeg");
		
		final List<String> expectedFormats2 = new ArrayList<>();
		expectedFormats2.add("pdf");
		expectedFormats2.add("jpeg");
		
    	
		List<FileBase64CompleteHandleRequest> requests = new ArrayList<FileBase64CompleteHandleRequest>();
		
		//with name
		FileBase64CompleteHandleRequest req1 = new FileBase64CompleteHandleRequest();
		FileBase64CompleteHandleClientInput fci = new FileBase64CompleteHandleClientInput();
		FileConstraint fc = new FileConstraint();
		fc.setMaxWidthInPx(600);
		fc.setMaxHeightInPx(800);
		fc.setMinWidthInPx(600);
		fc.setMinHeightInPx(800);
		fc.setMaxSizeInKb(165L);
		fc.setMinSizeInKb(163L);
		fci.setFileConstraint(fc);
		fci.setData(dummyBase64);
		fci.setFileName(filename);
		fci.setExpectedFileFormats(expectedFormats);
		req1.setFileClientInput(fci);
		requests.add(req1);
		
		//without filename
		FileBase64CompleteHandleRequest req2 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fc = new FileConstraint();
		fc.setMaxWidthInPx(600);
		fc.setMaxHeightInPx(800);
		fc.setMinWidthInPx(500);
		fc.setMinHeightInPx(500);
		fc.setMaxSizeInKb(165L);
		fc.setMinSizeInKb(163L);
		fci.setFileConstraint(fc);
		fci.setData(dummyBase64);
		fci.setExpectedFileFormats(expectedFormats);
		req2.setFileClientInput(fci);
		requests.add(req2);
		
		//with name + expected formats 1
		FileBase64CompleteHandleRequest req3 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fc = new FileConstraint();
		fc.setMaxWidthInPx(600);
		fc.setMaxHeightInPx(800);
		fc.setMinWidthInPx(600);
		fc.setMinHeightInPx(800);
		fc.setMaxSizeInKb(165L);
		fc.setMinSizeInKb(163L);
		fci.setFileConstraint(fc);
		fci.setData(dummyBase64);
		fci.setFileName(filename);
		fci.setExpectedFileFormats(expectedFormats2);
		req3.setFileClientInput(fci);
		requests.add(req3);
		
		//without filename + expected formats 2
		FileBase64CompleteHandleRequest req4 = new FileBase64CompleteHandleRequest();
		fci = new FileBase64CompleteHandleClientInput();
		fc = new FileConstraint();
		fc.setMaxWidthInPx(600);
		fc.setMaxHeightInPx(800);
		fc.setMinWidthInPx(500);
		fc.setMinHeightInPx(500);
		fc.setMaxSizeInKb(165L);
		fc.setMinSizeInKb(163L);
		fci.setFileConstraint(fc);
		fci.setData(dummyBase64);
		fci.setExpectedFileFormats(expectedFormats2);
		req4.setFileClientInput(fci);
		requests.add(req4);
		
		for (FileBase64CompleteHandleRequest request : requests) {
			EaiOutputSchema<FileBase64OutputCompleteHandleResponse> responseObject = fileCompleteHandleService.handleFileBase64ContentToBase64(request);
			Assert.assertEquals(null,responseObject.getErrorSchema().getErrorCode());
			Assert.assertEquals(DetectionCode.DC_CLEAN,responseObject.getOutputSchema().getFileClientOutput().getDiagnostic().getDetectionCode());
			Assert.assertNotEquals(null,responseObject.getOutputSchema().getFileClientOutput().getData());
		}
    }
    
//    @DisplayName("Mallicious Image Files")
//	@Test
//	public void malliciousImageFiles() throws IOException {		
//		for (File file : getResourceFolderFiles("file/mallicious-image")) {
//			byte[] fileContent = FileUtils.readFileToByteArray(file);
//			String dummyBase64 = Base64.getEncoder().encodeToString(fileContent);
//			
//			FileBase64CompleteHandleRequest request = new FileBase64CompleteHandleRequest();
//			request.setFileClientInput(new FileBase64CompleteHandleClientInput());
//			request.getFileClientInput().setFileName(getFilename(file.getName())+"."+getFileExtension(file.getName()));
//		
//			List<String> expectedFormats = new ArrayList<String>();
//			expectedFormats.add(getFileExtension(file.getName()));
//			request.getFileClientInput().setExpectedFileFormats(expectedFormats);
//			
//			request.getFileClientInput().setData(dummyBase64);
//			
//			
//			EaiOutputSchema<FileBase64OutputCompleteHandleResponse> responseObject = fileCompleteHandleService.handleFileBase64ContentToBase64(request);
//			Assert.assertEquals(DetectionCode.DC_CLEAN, responseObject.getOutputSchema().getFileClientOutput().getDiagnostic().getDetectionCode());
//			Assert.assertEquals(null, responseObject.getErrorSchema().getErrorCode());
//			Assert.assertNotEquals(dummyBase64, responseObject.getOutputSchema().getFileClientOutput().getData());
//		}
//   }
    
}
