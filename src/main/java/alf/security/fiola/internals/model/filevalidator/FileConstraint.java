package alf.security.fiola.internals.model.filevalidator;

import com.fasterxml.jackson.annotation.JsonProperty;

import alf.security.fiola.internals.model.filecompletehandle.DocumentFileConstraint;
import alf.security.fiola.internals.model.filecompletehandle.ImageFileConstraint;
import lombok.Data;

@Data
public class FileConstraint implements ImageFileConstraint, DocumentFileConstraint{
	@JsonProperty("min_size")
	private Long minSizeInKb;
	@JsonProperty("max_size")
	private Long maxSizeInKb;
	@JsonProperty("min_height")
	private Integer minHeightInPx;
	@JsonProperty("max_height")
	private Integer maxHeightInPx;
	@JsonProperty("min_width")
	private Integer minWidthInPx;
	@JsonProperty("max_width")
	private Integer maxWidthInPx;
	
	@JsonProperty("is_image_portrait")
	private Boolean isImagePortrait;
}
