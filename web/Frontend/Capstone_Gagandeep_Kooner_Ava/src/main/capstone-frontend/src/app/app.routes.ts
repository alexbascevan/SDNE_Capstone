import { Routes } from '@angular/router';
import { NavbarComponent } from './components/navbar/navbar.component'
import { DashboardComponent } from './components/dashboard/dashboard.component';
import { ScanResultsComponent } from './components/scan-results/scan-results.component';
import { AlertsComponent} from './components/alerts/alerts.component';


export const routes: Routes = [
	{ 
	    path: '', 
	    component: DashboardComponent,
	    title: 'Dashboard'  // Optional: Add title for route
	  },
	  { 
	    path: 'scans', 
	    component: ScanResultsComponent,
	    title: 'Scan Results'
	  },
	  { 
	    path: 'alerts', 
	    component: AlertsComponent,
	    title: 'Security Alerts'
	  },
	  { 
	    path: '**', 
	    redirectTo: '',
	    pathMatch: 'full' 
	  }
];
