package alf.security.fiola.utility.misc;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Set;

import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.stereotype.Component;

import com.google.gson.Gson;
@Component
public class RESTFunctionHelper {
	@SuppressWarnings("rawtypes")
	public static String execRESTFunction(String restURL, String requestMethod, String additionalParamInURL,
			LinkedHashMap mapInputHeader, LinkedHashMap mapInputBody, boolean doLog) {
		if (doLog) {
			System.out.println("================================================");
		}
		String retval = null;

		String finalURL = restURL + additionalParamInURL;
		if (doLog) {
			System.out.println("***** Start\n*** finalURL : \n" + finalURL);
		}
		if (mapInputBody==null) {
			mapInputBody = new LinkedHashMap();
		}
		
		try {
			Gson gson = new Gson();
			String json = gson.toJson(mapInputBody);
			if (doLog) {
				System.out.println("\n*** Input : \n" + formatReadableJson(json));
			}
			JSONObject jsonObject = null;
			jsonObject = new JSONObject(json);

			try {
				URL url = new URL(finalURL);
				HttpURLConnection connection = (HttpURLConnection) url.openConnection();
				if (mapInputHeader.size() > 0) {
					Set keys = mapInputHeader.keySet();
					Iterator iterator1 = keys.iterator();
					while (iterator1.hasNext()) {
						String key = String.valueOf(iterator1.next());
						String value = null;
						if (mapInputHeader.get(key)!=null) {
							value = String.valueOf(mapInputHeader.get(key));
						}
						connection.setRequestProperty(key, value);
					}
				}
				connection.setRequestMethod(requestMethod);
				connection.setConnectTimeout(15000);
				connection.setReadTimeout(15000);
				connection.setRequestProperty("Content-Type", "application/json");
				connection.setDoOutput(true);

				if (mapInputBody.size() > 0) {
					OutputStreamWriter out = new OutputStreamWriter(connection.getOutputStream());
					out.write(jsonObject.toString());
					out.close();
				}

				InputStream content = null;
				if (connection.getResponseCode() != 200) {
					content = (InputStream) connection.getErrorStream();
				} else {
					content = (InputStream) connection.getInputStream();
				}

				BufferedReader in = new BufferedReader(new InputStreamReader(content));
				String line = "";
				while ((line = in.readLine()) != null) {
					retval = line;
				}
				in.close();

			} catch (SocketTimeoutException ex) {
				System.out.println("Timeout! " + ex);
			} 
			catch (Exception ex) {
				ex.printStackTrace();
			}

		} catch (JSONException ex) {
			ex.printStackTrace();
		}
		if (doLog) {
			System.out.println("\n*** Output : \n" + formatReadableJson(retval) + "\n***** End");
			System.out.println("================================================\n");
		}
		return retval;
	}

	public static String formatReadableJson(String jsonString) {
		String retval = jsonString.replaceAll("null,", "null,\n").replaceAll("\",", "\",\n").replaceAll("\\[", "\\[\n")
				.replaceAll("\\]", "\n\\]").replaceAll("\\{", "\\{\n").replaceAll("\\}", "\n\\}");
		return retval;
	}
}
