package alf.security.fiola.internals.model.filevalidator;

import com.fasterxml.jackson.annotation.JsonProperty;

import alf.security.fiola.utility.common.BaseFileClientInput;

public abstract class BaseFileValidatingClientInput extends BaseFileClientInput implements IFileConstraintValidationRequest{
	@JsonProperty("min_size")
	private Integer minSizeInKb;
	@JsonProperty("max_size")
	private Integer maxSizeInKb;
	@JsonProperty("min_height")
	private Integer minHeightInPx;
	@JsonProperty("max_height")
	private Integer maxHeightInPx;
	@JsonProperty("min_width")
	private Integer minWidthInPx;
	@JsonProperty("max_width")
	private Integer maxWidthInPx;
	public Integer getMinSizeInKb() {
		return minSizeInKb;
	}
	public void setMinSizeInKb(Integer minSizeInKb) {
		this.minSizeInKb = minSizeInKb;
	}
	public Integer getMaxSizeInKb() {
		return maxSizeInKb;
	}
	public void setMaxSizeInKb(Integer maxSizeInKb) {
		this.maxSizeInKb = maxSizeInKb;
	}
	public Integer getMinHeightInPx() {
		return minHeightInPx;
	}
	public void setMinHeightInPx(Integer minHeightInPx) {
		this.minHeightInPx = minHeightInPx;
	}
	public Integer getMaxHeightInPx() {
		return maxHeightInPx;
	}
	public void setMaxHeightInPx(Integer maxHeightInPx) {
		this.maxHeightInPx = maxHeightInPx;
	}
	public Integer getMinWidthInPx() {
		return minWidthInPx;
	}
	public void setMinWidthInPx(Integer minWidthInPx) {
		this.minWidthInPx = minWidthInPx;
	}
	public Integer getMaxWidthInPx() {
		return maxWidthInPx;
	}
	public void setMaxWidthInPx(Integer maxWidthInPx) {
		this.maxWidthInPx = maxWidthInPx;
	}
	
	
}
