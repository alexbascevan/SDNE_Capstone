package ca.sheridancollege.koonerga.domain;

import java.time.LocalDateTime;


import lombok.Data;
@Data
public class ScanResult {
	private Long id;
    private String essid;
    private String bssid;
    private Integer channel;
    private Integer avgPower;
    private String auth;
    private String enc;
    private LocalDateTime scannedAt;
    private Long whitelistId;

}
