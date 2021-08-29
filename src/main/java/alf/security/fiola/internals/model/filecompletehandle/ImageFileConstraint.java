package alf.security.fiola.internals.model.filecompletehandle;

public interface ImageFileConstraint {
	
	public Long getMinSizeInKb();
	public Long getMaxSizeInKb();
	public Integer getMinHeightInPx();
	public Integer getMaxHeightInPx();
	public Integer getMinWidthInPx();
	public Integer getMaxWidthInPx();
	public Boolean getIsImagePortrait();
}
