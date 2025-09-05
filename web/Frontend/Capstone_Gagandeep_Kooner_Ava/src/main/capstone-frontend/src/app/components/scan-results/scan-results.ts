export class ScanResults {
	id?: number;
	  essid!: string;
	  bssid!: string;
	  channel!: number;
	  avg_power!: number;
	  auth!: string;
	  enc!: string;
	  scanned_at!: string;
	  whitelist_id?: number;
}
