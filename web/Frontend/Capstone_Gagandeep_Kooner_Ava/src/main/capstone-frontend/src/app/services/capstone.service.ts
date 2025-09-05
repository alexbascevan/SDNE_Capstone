import { Injectable , inject} from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { ScanResults } from '../components/scan-results/scan-results';
import {Alerts } from '../components/alerts/alerts';

const API_BASE = '/api';
const SCANS_URL = `${API_BASE}/access/scans`;
const ALERTS_URL = `${API_BASE}/access/alerts`;
@Injectable({
  providedIn: 'root'
})
export class CapstoneService {
	

	constructor(private http: HttpClient) { }

	 getRecentScans(): Observable<any[]> {
	   return this.http.get<ScanResults[]>('/api/access/scans');
	 }

	 getRecentAlerts(): Observable<any[]> {
	   return this.http.get<Alerts[]>('/api/access/alerts');
	 }
	

	
	 
}

