package alf.security.fiola.internals.model.apigw.v2;

public interface IEaiOutputSchema<OutputSchema> {
	public OutputSchema getOutputSchema();
	public void setOutputSchema(OutputSchema outputSchema);
	public ErrorSchema getErrorSchema();
	public void setErrorSchema(ErrorSchema errorSchema);
}
