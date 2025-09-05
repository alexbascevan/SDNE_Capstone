package ca.sheridancollege.koonerga.domain;

import java.time.LocalDateTime;

import lombok.Data;
@Data
public class Alert {
	 private Long id;
	    private String essid;
	    private String bssid;
	    private Integer channel;
	    private Integer avgPower;
	    private String auth;
	    private String enc;
	    private String alertType;
	    private LocalDateTime detectedAt;
	    private Long whitelistId;

}
