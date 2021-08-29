package alf.security.fiola.utility.common;

public class Coordinate {
	private Double latitude;
	private Double longitude;
	private Double altitude;
	
	public Coordinate (Double latitude, Double longitude, Double altitude) {
		setLatitude(latitude);
		setLongitude(longitude);
		setAltitude(altitude);
	}
	public Coordinate (Double latitude, Double longitude) {
		setLatitude(latitude);
		setLongitude(longitude);
		setAltitude(0);
	}
	public Coordinate (String latitude, String longitude, String altitude) {
		setLatitude(latitude);
		setLongitude(longitude);
		setAltitude(altitude);
	}
	public Coordinate (String latitude, String longitude) {
		setLatitude(latitude);
		setLongitude(longitude);
		setAltitude(0);
	}
	
	public double getLatitude() {
		return latitude;
	}
	public void setLatitude(double latitude) {
		this.latitude = latitude;
	}
	public double getLongitude() {
		return longitude;
	}
	public void setLongitude(double longitude) {
		this.longitude = longitude;
	}
	public double getAltitude() {
		return altitude;
	}
	public void setAltitude(double altitude) {
		this.altitude = altitude;
	}
	
	
	public void setLatitude(String latitude) {
		this.latitude = new Double(latitude);
	}
	public void setLongitude(String longitude) {
		this.longitude = new Double(longitude);
	}
	public void setAltitude(String altitude) {
		this.altitude = new Double(altitude);
	}
	
}
