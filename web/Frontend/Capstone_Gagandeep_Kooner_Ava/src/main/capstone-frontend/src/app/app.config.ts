import { ApplicationConfig } from '@angular/core';
import { provideRouter } from '@angular/router';

import { routes } from './app.routes';
import { provideHttpClient } from '@angular/common/http';

export const appConfig: ApplicationConfig = {
	providers: [
	    provideRouter(routes),
	    provideHttpClient(),
	    { provide: 'BASE_API_URL', useValue: '/api' } // Proxy will handle this in dev
	  ]
};
