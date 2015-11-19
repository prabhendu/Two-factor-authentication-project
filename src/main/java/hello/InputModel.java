package hello;

import com.fasterxml.jackson.annotation.JsonProperty;

/** 
 * Input model class for HTML form input
 * @author prabhendu
 */

public class InputModel {

    private final String username;
    private final String password;
    private final long fingerprint;
    private final int[] latency;

    public InputModel(@JsonProperty("username") String username,
    				  @JsonProperty("password") String password,
    				  @JsonProperty("fingerprint") long fingerprint, 
    				  @JsonProperty("latency") int[] latency) {
        this.username = username;
        this.password = password;
        this.fingerprint = fingerprint;
        this.latency = latency;
    }

    public String getUsername() {
        return new String(username);
    }
    
    public String getPassword() {
        return new String(password);
    }
    
    public long getFingerprint() {
        return fingerprint;
    }
    
    public int[] getLatency() {
        return latency;
    }
}
