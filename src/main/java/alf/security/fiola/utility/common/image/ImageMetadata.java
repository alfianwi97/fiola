package alf.security.fiola.utility.common.image;

import java.util.List;

public class ImageMetadata {
	private String formatName;
	private List<String> comments;
	private int heightInPx;
	private int widthInPx;
	private String mimeType;
	private boolean fallbackOnApacheCommonsImaging;
	public String getFormatName() {
		return formatName;
	}
	public void setFormatName(String formatName) {
		this.formatName = formatName;
	}
	public List<String> getComments() {
		return comments;
	}
	public void setComments(List<String> comments) {
		this.comments = comments;
	}
	public int getHeightInPx() {
		return heightInPx;
	}
	public void setHeightInPx(int heightInPx) {
		this.heightInPx = heightInPx;
	}
	public int getWidthInPx() {
		return widthInPx;
	}
	public void setWidthInPx(int widthInPx) {
		this.widthInPx = widthInPx;
	}
	public String getMimeType() {
		return mimeType;
	}
	public void setMimeType(String mimeType) {
		this.mimeType = mimeType;
	}
	public boolean isFallbackOnApacheCommonsImaging() {
		return fallbackOnApacheCommonsImaging;
	}
	public void setFallbackOnApacheCommonsImaging(boolean fallbackOnApacheCommonsImaging) {
		this.fallbackOnApacheCommonsImaging = fallbackOnApacheCommonsImaging;
	}
	@Override
	public String toString() {
		return "ImageMetadata [formatName=" + formatName + ", comments=" + comments + ", heightInPx=" + heightInPx
				+ ", widthInPx=" + widthInPx + ", mimeType=" + mimeType + ", fallbackOnApacheCommonsImaging="
				+ fallbackOnApacheCommonsImaging + "]";
	}
	
	
	
}
