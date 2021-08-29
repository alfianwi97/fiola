package alf.security.fiola.utility.validator.file;

import java.io.File;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import com.aspose.words.Document;
import com.aspose.words.FileFormatInfo;
import com.aspose.words.FileFormatUtil;
import com.aspose.words.NodeCollection;
import com.aspose.words.NodeType;
import com.aspose.words.Shape;

import alf.security.fiola.utility.common.BaseComponent;

public class DocFileValidator extends BaseComponent{
	private static final List<String> ALLOWED_FORMAT = 
            Arrays.asList(new String[] { "doc", "docx", "docm", "wml", "dot", "dotm" });

	@SuppressWarnings("rawtypes")
	public boolean isSafe(File f) {
		boolean safeState = false;
		try {
			if ((f != null) && f.exists() && f.canRead()) {
			   // Perform a first check on Word document format
			   FileFormatInfo formatInfo = FileFormatUtil.detectFileFormat(f.getAbsolutePath());
			   String formatExtension = FileFormatUtil.loadFormatToExtension(formatInfo.getLoadFormat());
			   if ((formatExtension != null) 
			   && ALLOWED_FORMAT.contains(formatExtension.toLowerCase(Locale.US).replaceAll("\\.", ""))) {
			       // Load the file into the Word document parser
			       Document document = new Document(f.getAbsolutePath());
			       // Get safe state from Macro presence
			       safeState = !document.hasMacros();
			       // If document is safe then we pass to OLE objects analysis
			       if (safeState) {
			           // Get all shapes of the document
			           NodeCollection shapes = document.getChildNodes(NodeType.SHAPE, true);
			           Shape shape = null;
			           // Search OLE objects in all shapes
			           int totalOLEObjectCount = 0;
			           for (int i = 0; i < shapes.getCount(); i++) {
			               shape = (Shape) shapes.get(i);
			               // Check if the current shape has OLE object
			               if (shape.getOleFormat() != null) {
			                   totalOLEObjectCount++;
			               }
			           }
			           // Update safe status flag according to number of OLE object found
			           if (totalOLEObjectCount != 0) {
			               safeState = false;
			           }
			
			       }
			   }
			}
		} catch (Exception e) {
			safeState = false;
		}
		return safeState;
	}
	
	@SuppressWarnings("rawtypes")
	public static boolean isSafe(InputStream is) {
		boolean safeState = false;
		try {
			if (is != null) {
			   // Perform a first check on Word document format
//			   FileFormatInfo formatInfo = FileFormatUtil.detectFileFormat(f.getAbsolutePath());
//			   String formatExtension = FileFormatUtil.loadFormatToExtension(formatInfo.getLoadFormat());
			   
			   FileFormatInfo formatInfo = FileFormatUtil.detectFileFormat(is);
			   String formatExtension = FileFormatUtil.loadFormatToExtension(formatInfo.getLoadFormat());
			   
			   if ((formatExtension != null) 
			   && ALLOWED_FORMAT.contains(formatExtension.toLowerCase(Locale.US).replaceAll("\\.", ""))) {
			       // Load the file into the Word document parser
//			       Document document = new Document(f.getAbsolutePath());
				   Document document = new Document(is);
			       // Get safe state from Macro presence
			       safeState = !document.hasMacros();
			       // If document is safe then we pass to OLE objects analysis
			       if (safeState) {
			           // Get all shapes of the document
			           NodeCollection shapes = document.getChildNodes(NodeType.SHAPE, true);
			           Shape shape = null;
			           // Search OLE objects in all shapes
			           int totalOLEObjectCount = 0;
			           for (int i = 0; i < shapes.getCount(); i++) {
			               shape = (Shape) shapes.get(i);
			               // Check if the current shape has OLE object
			               if (shape.getOleFormat() != null) {
			                   totalOLEObjectCount++;
			               }
			           }
			           // Update safe status flag according to number of OLE object found
			           if (totalOLEObjectCount != 0) {
			               safeState = false;
			           }
			
			       }
			   }
			}
		} catch (Exception e) {
			safeState = false;
		}
		return safeState;
	}
}
